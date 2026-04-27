import subprocess
import time
import threading
import logging
import datetime

logger = logging.getLogger('blocker')

BAN_DURATIONS = [600, 1800, 7200, 365 * 86400]
BAN_LABELS = ['10min', '30min', '2hr', 'permanent']


class IPBlocker:

    def __init__(self, config, notifier, audit_logger, shared_state, state_lock):
        self.config = config
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.shared_state = shared_state
        self.state_lock = state_lock
        self._ip_tiers = {}
        self._lock = threading.Lock()

    def ban(self, ip, condition, rate, mean, z_score=0.0, ratio=0.0):
        now = time.time()

        with self._lock:
            with self.state_lock:
                if ip in self.shared_state['banned_ips']:
                    return

            tier = self._ip_tiers.get(ip, 0)
            duration = BAN_DURATIONS[min(tier, len(BAN_DURATIONS) - 1)]
            label = BAN_LABELS[min(tier, len(BAN_LABELS) - 1)]

            success = self._iptables_drop(ip)
            if not success:
                logger.error(f"iptables DROP failed for {ip}")
                return

            with self.state_lock:
                self.shared_state['banned_ips'][ip] = {
                    'banned_at': now,
                    'duration': duration,
                    'tier': tier,
                    'reason': condition,
                    'label': label,
                    'rate': rate,
                    'mean': mean,
                }

            self._ip_tiers[ip] = min(tier + 1, len(BAN_DURATIONS) - 1)

        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        self.audit_logger.info(
            f"[{ts}] BAN ip={ip} | condition={condition} | "
            f"rate={rate:.4f} | baseline={mean:.4f} | duration={label}"
        )
        logger.warning(
            f"BANNED ip={ip} duration={label} tier={tier} "
            f"condition={condition} rate={rate:.2f} mean={mean:.2f}"
        )
        self.notifier.send_ban_alert(
            ip=ip, condition=condition, rate=rate, mean=mean,
            z_score=z_score, ratio=ratio, duration=label, tier=tier,
        )

    def unban(self, ip, reason='auto_unban'):
        now = time.time()

        with self.state_lock:
            ban_info = self.shared_state['banned_ips'].pop(ip, None)

        if ban_info is None:
            return

        self._iptables_accept(ip)

        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        self.audit_logger.info(
            f"[{ts}] UNBAN ip={ip} | condition={reason} | "
            f"rate={ban_info.get('rate', 0):.4f} | baseline={ban_info.get('mean', 0):.4f} | "
            f"duration={ban_info.get('label', 'unknown')}"
        )
        logger.info(f"UNBANNED ip={ip} reason={reason}")
        self.notifier.send_unban_alert(
            ip=ip, duration=ban_info.get('label', 'unknown'),
            tier=ban_info.get('tier', 0), reason=reason,
        )

    def _iptables_drop(self, ip):
        try:
            cmd = ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                logger.error(f"iptables error: {result.stderr.decode()}")
                return False
            return True
        except Exception as e:
            logger.error(f"iptables DROP error: {e}")
            return False

    def _iptables_accept(self, ip):
        try:
            cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e:
            logger.warning(f"iptables ACCEPT error for {ip}: {e}")
