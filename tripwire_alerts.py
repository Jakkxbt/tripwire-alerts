#!/usr/bin/env python3
"""
Tripwire Alerts — Central Alerting Hub for the Blue Arsenal
===========================================================
Channels:
  - Slack webhook
  - Discord webhook
  - Telegram bot (sendMessage)
  - Generic webhook (POST JSON)
  - Email (SMTP)
  - Syslog
  - Local log file

Design:
  - Reads alert events as JSON lines from stdin (pipeline-friendly)
  - Or send single messages via CLI
  - Config file: /etc/tripwire/config.json or ~/.config/tripwire/config.json
  - Per-severity channel routing (critical → all channels, info → log only)
  - Message batching, retry with backoff, throttling
  - All findings from arsenal tools can be piped here

Config format (/etc/tripwire/config.json):
{
  "slack":   {"webhook_url": "https://hooks.slack.com/services/..."},
  "discord": {"webhook_url": "https://discord.com/api/webhooks/..."},
  "telegram": {"bot_token": "...", "chat_id": "..."},
  "webhook": {"url": "http://siem:8080/ingest", "headers": {"X-Key": "..."}},
  "smtp":    {"host": "smtp.example.com", "port": 587, "user": "...",
              "password": "...", "from": "sentry@example.com",
              "to": ["soc@example.com"]},
  "syslog":  {"enabled": true, "facility": "local0"},
  "file":    {"path": "/var/log/tripwire_alerts.log"},
  "min_severity": "medium",
  "batch_seconds": 2
}

Usage:
  echo '{"severity":"critical","rule":"SSH Brute Force","ip":"1.2.3.4"}' | python3 tripwire_alerts.py
  python3 tripwire_alerts.py send --channel slack --severity critical --message "Honeypot hit from 1.2.3.4"
  python3 tripwire_alerts.py --test          # send test message to all channels
  python3 tripwire_alerts.py --check-config  # validate config
  roothunter.py | python3 tripwire_alerts.py --parse-lines
"""

import os
import re
import sys
import json
import time
import ssl
import argparse
import smtplib
import logging
import socket
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from collections import deque


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
DEFAULT_CONFIG_PATHS = [
    '/etc/tripwire/config.json',
    os.path.expanduser('~/.config/tripwire/config.json'),
    os.path.expanduser('~/tripwire_config.json'),
]

CONFIG_TEMPLATE = {
    "min_severity": "medium",
    "batch_seconds": 2,
    "retries": 3,
    "slack": {},
    "discord": {},
    "telegram": {},
    "webhook": {},
    "smtp": {},
    "syslog": {"enabled": False},
    "file": {"path": "/var/log/tripwire_alerts.log"},
}


class TripwireAlerter:
    def __init__(self, config_path=None):
        self.config = self._load_config(config_path)
        self.throttle = {}
        self.logger = logging.getLogger('tripwire')
        self.logger.setLevel(logging.INFO)
        self._setup_logger()

    # ─── Config ───────────────────────────────────────────────────────

    def _load_config(self, config_path):
        config = dict(CONFIG_TEMPLATE)
        paths = [config_path] if config_path else DEFAULT_CONFIG_PATHS
        for p in paths:
            if p and os.path.exists(p):
                try:
                    loaded = json.loads(Path(p).read_text())
                    config.update(loaded)
                    print(f"[✓] Config loaded from {p}", file=sys.stderr)
                    return config
                except (json.JSONDecodeError, OSError) as e:
                    print(f"[!] Config error in {p}: {e}", file=sys.stderr)
        if not config_path:
            print("[i] No config found — running with defaults (file logging only).", file=sys.stderr)
        return config

    def _setup_logger(self):
        file_cfg = self.config.get('file', {})
        if file_cfg.get('path'):
            try:
                os.makedirs(os.path.dirname(file_cfg['path']), exist_ok=True)
                handler = logging.FileHandler(file_cfg['path'])
                handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
                self.logger.addHandler(handler)
            except OSError as e:
                print(f"[!] Cannot open log file: {e}", file=sys.stderr)

    # ─── Severity Filtering ───────────────────────────────────────────

    def _severity_allowed(self, severity):
        min_sev = self.config.get('min_severity', 'medium')
        return SEVERITY_ORDER.get(severity, 9) <= SEVERITY_ORDER.get(min_sev, 2)

    def _throttled(self, channel, key, seconds=30):
        """Rate-limit identical alerts per channel."""
        tkey = (channel, key)
        now = time.time()
        if now - self.throttle.get(tkey, 0) < seconds:
            return True
        self.throttle[tkey] = now
        return False

    # ─── Event Normalization ──────────────────────────────────────────

    def format_message(self, event, for_markdown=True):
        """Build a human-readable alert message from a JSON event."""
        sev = event.get('severity', 'info').upper()
        rule = event.get('rule') or event.get('title') or event.get('type') or 'Alert'
        lines = [f"🚨 {rule} [{sev}]"]
        if event.get('time'):
            lines.append(f"🕐 {event['time']}")
        if event.get('ip'):
            lines.append(f"🌐 Source: {event['ip']}")
        if event.get('user'):
            lines.append(f"👤 User: {event['user']}")
        if event.get('detail'):
            lines.append(f"📋 {event['detail']}")
        if event.get('evidence'):
            ev = event['evidence']
            lines.append(f"📄 Evidence: {ev[:200]}")
        if event.get('mitre'):
            lines.append(f"🎯 MITRE: {event['mitre']}")
        if event.get('host'):
            lines.append(f"🖥 Host: {event['host']}")
        elif 'hostname' in self.config:
            lines.append(f"🖥 Host: {self.config['hostname']}")

        if for_markdown and self.config.get('markdown', True):
            return '\n'.join(f'`{l}`' if l.startswith('🕐') else l for l in lines)
        return '\n'.join(lines)

    # ─── Channel Senders ──────────────────────────────────────────────

    def _http_post(self, url, payload, headers=None, timeout=10, retries=None):
        retries = retries or self.config.get('retries', 3)
        data = json.dumps(payload).encode()
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=data,
                                             headers={'Content-Type': 'application/json',
                                                      ** (headers or {})})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                if attempt == retries - 1:
                    self.logger.error(f'HTTP send failed: {e}')
                    return None
                time.sleep(2 ** attempt)

    def send_slack(self, message, severity='info'):
        cfg = self.config.get('slack', {})
        url = cfg.get('webhook_url')
        if not url:
            return False
        color = {'critical': 'danger', 'high': 'danger', 'medium': 'warning',
                 'low': 'warning', 'info': 'good'}.get(severity, 'good')
        payload = {"attachments": [{"color": color, "text": message}]}
        return self._http_post(url, payload)

    def send_discord(self, message, severity='info'):
        cfg = self.config.get('discord', {})
        url = cfg.get('webhook_url')
        if not url:
            return False
        color = {'critical': 0xff0000, 'high': 0xff4444, 'medium': 0xffaa00,
                 'low': 0xffdd44, 'info': 0x44ff44}.get(severity, 0x44ff44)
        payload = {"embeds": [{"description": message, "color": color}]}
        return self._http_post(url, payload)

    def send_telegram(self, message, severity='info'):
        cfg = self.config.get('telegram', {})
        token = cfg.get('bot_token')
        chat_id = cfg.get('chat_id')
        if not token or not chat_id:
            return False
        url = f'https://api.telegram.org/bot{token}/sendMessage'
        payload = {'chat_id': chat_id, 'text': message[:4000],
                   'disable_web_page_preview': True}
        return self._http_post(url, payload)

    def send_webhook(self, event, message):
        cfg = self.config.get('webhook', {})
        url = cfg.get('url')
        if not url:
            return False
        payload = {
            'timestamp': datetime.now().isoformat(),
            'severity': event.get('severity', 'info'),
            'message': message,
            'event': event,
            'source': 'tripwire-alerts',
        }
        return self._http_post(url, payload, headers=cfg.get('headers'))

    def send_email(self, message, severity='info'):
        cfg = self.config.get('smtp', {})
        if not all(cfg.get(k) for k in ('host', 'from', 'to')):
            return False
        try:
            subject = f'[Tripwire {severity.upper()}] Security Alert'
            body = f'{message}\n\nSent by Tripwire Alerts at {datetime.now().isoformat()}'
            msg = (f'From: {cfg["from"]}\r\n'
                   f'To: {", ".join(cfg["to"])}\r\n'
                   f'Subject: {subject}\r\n\r\n{body}')
            port = cfg.get('port', 587)
            with smtplib.SMTP(cfg['host'], port, timeout=15) as smtp:
                if cfg.get('starttls', True):
                    smtp.starttls(context=ssl.create_default_context())
                if cfg.get('user'):
                    smtp.login(cfg['user'], cfg.get('password', ''))
                smtp.sendmail(cfg['from'], cfg['to'], msg)
            return True
        except (smtplib.SMTPException, OSError) as e:
            self.logger.error(f'Email send failed: {e}')
            return False

    def send_syslog(self, message, severity='info'):
        if not self.config.get('syslog', {}).get('enabled'):
            return False
        facility = getattr(logging.handlers if hasattr(logging, 'handlers') else logging, 'handlers', None)
        try:
            import logging.handlers
            sev_map = {'critical': logging.CRITICAL, 'high': logging.ERROR,
                       'medium': logging.WARNING, 'low': logging.INFO, 'info': logging.INFO}
            handler = logging.handlers.SysLogHandler(address='/dev/log',
                                                     facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
            logger = logging.getLogger('tripwire_syslog')
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.log(sev_map.get(severity, logging.INFO), message.replace('\n', ' | '))
            return True
        except (OSError, ImportError):
            return False

    def send_file(self, event, message):
        file_cfg = self.config.get('file', {})
        if not file_cfg.get('path'):
            return False
        try:
            with open(file_cfg['path'], 'a') as f:
                f.write(json.dumps(event) + '\n')
            return True
        except OSError:
            return False

    # ─── Orchestration ────────────────────────────────────────────────

    def deliver(self, event):
        severity = event.get('severity', 'info')
        if not self._severity_allowed(severity):
            return {'status': 'filtered'}

        message = self.format_message(event)
        key = event.get('rule') or event.get('type') or event.get('title') or ''

        results = {'status': 'delivered', 'channels': {}}

        # High severity → every channel; medium/low → file + configured; info → file
        channels = ['file']
        if severity in ('critical', 'high'):
            channels += ['slack', 'discord', 'telegram', 'webhook', 'email', 'syslog']
        elif severity == 'medium':
            channels += ['slack', 'telegram', 'webhook', 'syslog']

        for channel in channels:
            if self._throttled(channel, key):
                continue
            sender = getattr(self, f'send_{channel}', None)
            if not sender:
                continue
            if channel == 'webhook':
                ok = sender(event, message)
            elif channel in ('file',):
                ok = sender(event, message)
            else:
                ok = sender(message, severity)
            results['channels'][channel] = bool(ok)
            if ok and channel != 'file':
                print(f"    [✓] {channel}: sent", file=sys.stderr)

        return results

    def process_stdin(self, parse_lines=False):
        """Read JSON events (or raw lines) from stdin."""
        count = 0
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                if parse_lines:
                    event = self._parse_finding_line(line)
                else:
                    event = json.loads(line)
                if event:
                    self.deliver(event)
                    count += 1
            except json.JSONDecodeError:
                continue
        print(f"[i] Processed {count} events", file=sys.stderr)

    def _parse_finding_line(self, line):
        """Heuristic parse of colored scanner output lines into events."""
        sev_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium',
                   'low': 'low', 'info': 'info'}
        sev = 'info'
        for s in sev_map:
            if re.search(rf'\[{s.upper()}\]|\[{s}\]', line, re.IGNORECASE):
                sev = s
                break
        # Strip ANSI codes
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
        ip = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', clean)
        return {
            'severity': sev,
            'rule': 'Scanner Finding',
            'detail': clean[:300],
            'ip': ip.group(0) if ip else None,
            'time': datetime.now().isoformat(),
        }

    # ─── CLI helpers ──────────────────────────────────────────────────

    def send_test(self):
        print("[i] Sending test alert to all configured channels...")
        for channel in ('slack', 'discord', 'telegram', 'webhook', 'email', 'syslog', 'file'):
            sender = getattr(self, f'send_{channel}', None)
            if not sender:
                continue
            msg = f'Tripwire Alerts test message from {socket.gethostname()} at {datetime.now().isoformat()}'
            ok = sender(msg, 'info') if channel not in ('webhook', 'file') else \
                 sender({'severity': 'info', 'rule': 'Test', 'detail': msg, 'time': datetime.now().isoformat()}, msg)
            print(f"    {'✓' if ok else '✗'} {channel}: {'sent' if ok else 'not configured/failed'}")

    def check_config(self):
        print("[i] Configuration check:")
        configured = []
        for channel in ('slack', 'discord', 'telegram', 'webhook', 'email', 'syslog', 'file'):
            cfg = self.config.get(channel, {})
            if channel == 'syslog':
                status = cfg.get('enabled', False)
            elif channel == 'file':
                status = bool(cfg.get('path'))
            elif channel == 'email':
                status = bool(cfg.get('host'))
            else:
                status = bool(cfg.get('webhook_url') or cfg.get('bot_token') or cfg.get('url'))
            marker = '✓' if status else '✗'
            print(f"    {marker} {channel}")
            if status:
                configured.append(channel)
        print(f"[i] {len(configured)} channel(s) configured")
        print(f"[i] Minimum severity: {self.config.get('min_severity', 'medium')}")


def main():
    parser = argparse.ArgumentParser(description='Tripwire Alerts — Central Alerting Hub')
    parser.add_argument('--config', '-c', help='Config file path')
    parser.add_argument('send', nargs='?', help='send subcommand')
    parser.add_argument('--channel', default='all', help='Channel for send (slack/discord/telegram/webhook/email/syslog/file)')
    parser.add_argument('--severity', default='info', choices=['critical', 'high', 'medium', 'low', 'info'])
    parser.add_argument('--message', '-m', help='Message to send')
    parser.add_argument('--rule', help='Rule/title for the event')
    parser.add_argument('--ip', help='Source IP')
    parser.add_argument('--user', help='Username')
    parser.add_argument('--detail', help='Detail line')
    parser.add_argument('--parse-lines', action='store_true',
                        help='Parse raw scanner output lines from stdin instead of JSON')
    parser.add_argument('--test', action='store_true', help='Send test message to all channels')
    parser.add_argument('--check-config', action='store_true', help='Validate configuration')
    parser.add_argument('--init-config', action='store_true', help='Write config template')

    args = parser.parse_args()

    if args.init_config:
        path = args.config or '/etc/tripwire/config.json'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            print(f'[!] {path} already exists')
            return
        Path(path).write_text(json.dumps(CONFIG_TEMPLATE, indent=2))
        print(f'[✓] Template written to {path}')
        return

    alerter = TripwireAlerter(config_path=args.config)

    if args.check_config:
        alerter.check_config()
        return

    if args.test:
        alerter.send_test()
        return

    if args.send == 'send':
        if not args.message:
            print('[!] --message required for send')
            return
        event = {
            'severity': args.severity,
            'rule': args.rule or 'Manual Alert',
            'message': args.message,
            'detail': args.detail or args.message,
            'ip': args.ip,
            'user': args.user,
            'time': datetime.now().isoformat(),
        }
        results = alerter.deliver(event)
        print(f"[i] Channels: {results.get('channels', {})}")
        return

    # Default: read events from stdin
    alerter.process_stdin(parse_lines=args.parse_lines)


if __name__ == '__main__':
    main()
