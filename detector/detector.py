import time
import threading
import logging
import datetime
from collections import defaultdict

logger = logging.getLogger('detector')


class AnomalyDetector:

    def __init__(self, config, baseline_engine, blocker, notifier, audit_logger, shared_state, state_lock):
        self.config = config
        self.baseline = baseline_engine
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.shared_state = shared_state
        self.state_lock = state_lock

        self.z_threshold = config['detection']['z_score_threshold']
        self.ratio_threshold = config['detection']['ratio_threshold']
        self.error_surge_multiplier = config['detection']['error_surge_multiplier']
        self.tightened_z = config['detection']['tightened_z_threshold']
        self.tightened_ratio = config['detection']['tightened_ratio_threshold']
        self.cooldown_seconds = config['detection']['cooldown_seconds']
        self.global_cooldown = config['detection'].get('global_cooldown_seconds', 60)

        self._ip_cooldown = {}
        self._lock = threading.Lock()
        self._global_last_flagged = 0.0
        self._last_tick = time.time()

    def evaluate(self, ip, ip_rate, global_rate, ip_error_rate, record):
        now = time.time()

        if now - self._last_tick >= 1.0:
            self.baseline.record_sample(global_rate)
            self._last_tick = now
            mean, stddev = self.baseline.get_baseline()
            with self.state_lock:
                self.shared_state['effective_mean'] = mean
                self.shared_state['effective_stddev'] = stddev
                self.shared_state['baseline_ready'] = self.baseline.is_ready()

        if not self.baseline.is_ready():
            return

        mean, stddev = self.baseline.get_baseline()
        error_baseline = self.baseline.get_error_baseline()

        error_surge = ip_error_rate >= (self.error_surge_multiplier * error_baseline)
        if error_surge:
            z_thresh = self.tightened_z
            ratio_thresh = self.tightened_ratio
        else:
            z_thresh = self.z_threshold
            ratio_thresh = self.ratio_threshold

        self._check_ip(ip, ip_rate, mean, stddev, z_thresh, ratio_thresh,
                       error_surge, ip_error_rate, error_baseline, now)
        self._check_global(global_rate, mean, stddev, now)

    def _check_ip(self, ip, rate, mean, stddev, z_thresh, ratio_thresh,
                  error_surge, ip_error_rate, error_baseline, now):
        with self.state_lock:
            if ip in self.shared_state['banned_ips']:
                return

        with self._lock:
            last = self._ip_cooldown.get(ip, 0.0)
            if now - last < self.cooldown_seconds:
                return

        z_score = self._z_score(rate, mean, stddev)
        ratio = rate / max(mean, 0.001)

        fired_z = z_score > z_thresh
        fired_ratio = ratio > ratio_thresh

        if not (fired_z or fired_ratio):
            return

        condition = ('error_surge+' if error_surge else '') + ('z_score' if fired_z else 'ratio')

        with self._lock:
            self._ip_cooldown[ip] = now

        logger.warning(
            f"ANOMALY ip={ip} rate={rate:.2f} mean={mean:.2f} "
            f"z={z_score:.2f} ratio={ratio:.2f} condition={condition}"
        )

        self.blocker.ban(ip, condition=condition, rate=rate, mean=mean,
                         z_score=z_score, ratio=ratio)

    def _check_global(self, rate, mean, stddev, now):
        if now - self._global_last_flagged < self.global_cooldown:
            return

        z_score = self._z_score(rate, mean, stddev)
        ratio = rate / max(mean, 0.001)

        if not (z_score > self.z_threshold or ratio > self.ratio_threshold):
            return

        self._global_last_flagged = now
        condition = 'global_z_score' if z_score > self.z_threshold else 'global_ratio'

        ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        self.audit_logger.info(
            f"[{ts}] GLOBAL_ALERT ip=* | condition={condition} | "
            f"rate={rate:.4f} | baseline={mean:.4f} | duration=N/A"
        )

        logger.warning(
            f"GLOBAL ANOMALY rate={rate:.2f} mean={mean:.2f} "
            f"z={z_score:.2f} condition={condition}"
        )

        self.notifier.send_global_alert(
            condition=condition, rate=rate, mean=mean,
            stddev=stddev, z_score=z_score, ratio=ratio,
        )

    @staticmethod
    def _z_score(rate, mean, stddev):
        if stddev < 0.001:
            return 0.0
        return (rate - mean) / stddev
