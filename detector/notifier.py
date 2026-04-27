import time
import json
import threading
import logging
import datetime
import requests

logger = logging.getLogger('notifier')


class SlackNotifier:

    def __init__(self, config, audit_logger):
        self.webhook_url = config['slack']['webhook_url']
        self.enabled = (
            bool(self.webhook_url) and
            'YOUR_SLACK_WEBHOOK_URL' not in self.webhook_url
        )
        self.audit_logger = audit_logger
        if not self.enabled:
            logger.warning("Slack webhook not configured. Alerts will be logged only.")

    def send_ban_alert(self, ip, condition, rate, mean, z_score, ratio, duration, tier):
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        payload = {
            "username": "HNG Anomaly Detector",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": "#FF0000",
                "title": f":rotating_light: IP BANNED: {ip}",
                "fields": [
                    {"title": "Condition",     "value": condition,           "short": True},
                    {"title": "Current Rate",  "value": f"{rate:.2f} req/s", "short": True},
                    {"title": "Baseline Mean", "value": f"{mean:.2f} req/s", "short": True},
                    {"title": "Z-Score",       "value": f"{z_score:.2f}",    "short": True},
                    {"title": "Rate Ratio",    "value": f"{ratio:.2f}x",     "short": True},
                    {"title": "Ban Duration",  "value": duration,            "short": True},
                    {"title": "Offense Tier",  "value": str(tier),           "short": True},
                    {"title": "Timestamp",     "value": ts,                  "short": True},
                ],
                "footer": "HNG Anomaly Detection Engine",
                "ts": int(time.time()),
            }]
        }
        self._send(payload, 'BAN', ip)

    def send_unban_alert(self, ip, duration, tier, reason):
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        payload = {
            "username": "HNG Anomaly Detector",
            "icon_emoji": ":white_check_mark:",
            "attachments": [{
                "color": "#36a64f",
                "title": f":white_check_mark: IP UNBANNED: {ip}",
                "fields": [
                    {"title": "Reason",       "value": reason,    "short": True},
                    {"title": "Served Ban",   "value": duration,  "short": True},
                    {"title": "Offense Tier", "value": str(tier), "short": True},
                    {"title": "Timestamp",    "value": ts,        "short": True},
                ],
                "footer": "HNG Anomaly Detection Engine",
                "ts": int(time.time()),
            }]
        }
        self._send(payload, 'UNBAN', ip)

    def send_global_alert(self, condition, rate, mean, stddev, z_score, ratio):
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        payload = {
            "username": "HNG Anomaly Detector",
            "icon_emoji": ":warning:",
            "attachments": [{
                "color": "#FFA500",
                "title": ":warning: GLOBAL TRAFFIC ANOMALY DETECTED",
                "fields": [
                    {"title": "Condition",     "value": condition,            "short": True},
                    {"title": "Global Rate",   "value": f"{rate:.2f} req/s",  "short": True},
                    {"title": "Baseline Mean", "value": f"{mean:.2f} req/s",  "short": True},
                    {"title": "Stddev",        "value": f"{stddev:.2f}",      "short": True},
                    {"title": "Z-Score",       "value": f"{z_score:.2f}",     "short": True},
                    {"title": "Rate Ratio",    "value": f"{ratio:.2f}x",      "short": True},
                    {"title": "Action",        "value": "Alert only",         "short": True},
                    {"title": "Timestamp",     "value": ts,                   "short": True},
                ],
                "footer": "HNG Anomaly Detection Engine",
                "ts": int(time.time()),
            }]
        }
        self._send(payload, 'GLOBAL_ALERT', '*')

    def _send(self, payload, alert_type, ip):
        if not self.enabled:
            logger.info(f"[SLACK MOCK] {alert_type} for {ip}")
            return

        def _do_send():
            try:
                resp = requests.post(self.webhook_url, json=payload, timeout=8)
                if resp.status_code == 200:
                    logger.info(f"Slack {alert_type} alert sent for {ip}")
                else:
                    logger.warning(f"Slack returned {resp.status_code} for {alert_type}")
            except Exception as e:
                logger.error(f"Slack send failed: {e}")

        threading.Thread(target=_do_send, daemon=True).start()
