import time
import logging

logger = logging.getLogger('unbanner')

PERMANENT_THRESHOLD = 30 * 24 * 3600


class AutoUnbanner:

    def __init__(self, config, blocker, notifier, audit_logger, shared_state, state_lock):
        self.config = config
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.shared_state = shared_state
        self.state_lock = state_lock
        self.check_interval = config.get('unbanner', {}).get('check_interval', 10)
        self.running = False

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        logger.info("AutoUnbanner started.")
        while self.running:
            time.sleep(self.check_interval)
            self._check_bans()
        logger.info("AutoUnbanner stopped.")

    def _check_bans(self):
        now = time.time()
        to_unban = []

        with self.state_lock:
            for ip, info in list(self.shared_state['banned_ips'].items()):
                banned_at = info.get('banned_at', now)
                duration = info.get('duration', 600)
                if duration >= PERMANENT_THRESHOLD:
                    continue
                if now - banned_at >= duration:
                    to_unban.append(ip)

        for ip in to_unban:
            logger.info(f"Ban expired for {ip}, unbanning.")
            self.blocker.unban(ip, reason='ban_expired')
