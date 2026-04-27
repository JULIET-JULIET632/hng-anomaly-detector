import time
import math
import threading
import logging
import datetime
from collections import deque

logger = logging.getLogger('baseline')


class BaselineEngine:
    WINDOW_SIZE = 1800
    RECALC_INTERVAL = 60
    MIN_SAMPLES = 120
    FLOOR_MEAN = 0.1
    FLOOR_STDDEV = 0.05

    def __init__(self, config, audit_logger):
        self.config = config
        self.audit_logger = audit_logger
        self._window = deque(maxlen=self.WINDOW_SIZE)
        self._hour_slots = {}
        self._effective_mean = self.FLOOR_MEAN
        self._effective_stddev = self.FLOOR_STDDEV
        self._lock = threading.Lock()
        self._last_recalc = 0.0
        self._ready = False
        self._history = deque(maxlen=500)

    def record_sample(self, req_per_second):
        now = time.time()
        with self._lock:
            self._window.append(req_per_second)
            hour_key = time.localtime().tm_hour
            if hour_key not in self._hour_slots:
                self._hour_slots[hour_key] = {'mean': 0.0, 'stddev': 0.0, 'count': 0}
            self._hour_slots[hour_key]['count'] += 1
        if now - self._last_recalc >= self.RECALC_INTERVAL:
            self._recalculate(now)

    def get_baseline(self):
        with self._lock:
            return self._effective_mean, self._effective_stddev

    def is_ready(self):
        with self._lock:
            return self._ready

    def get_history(self):
        with self._lock:
            return list(self._history)

    def get_error_baseline(self):
        with self._lock:
            return max(self._effective_mean * 0.10, 0.01)

    def _compute_stats(self, data):
        n = len(data)
        if n == 0:
            return self.FLOOR_MEAN, self.FLOOR_STDDEV
        mean = sum(data) / n
        if n > 1:
            variance = sum((x - mean) ** 2 for x in data) / (n - 1)
            stddev = math.sqrt(variance)
        else:
            stddev = 0.0
        return mean, stddev

    def _recalculate(self, now):
        with self._lock:
            data = list(self._window)
            if len(data) < 10:
                return
            rolling_mean, rolling_stddev = self._compute_stats(data)
            hour_key = time.localtime().tm_hour
            slot = self._hour_slots.setdefault(hour_key, {'mean': 0.0, 'stddev': 0.0, 'count': 0})
            slot['mean'] = rolling_mean
            slot['stddev'] = rolling_stddev

            if slot['count'] >= self.MIN_SAMPLES:
                chosen_mean = slot['mean']
                chosen_stddev = slot['stddev']
                source = f"hour_slot:{hour_key}"
            else:
                chosen_mean = rolling_mean
                chosen_stddev = rolling_stddev
                source = "rolling_window"

            self._effective_mean = max(chosen_mean, self.FLOOR_MEAN)
            self._effective_stddev = max(chosen_stddev, self.FLOOR_STDDEV)

            if len(data) >= self.MIN_SAMPLES:
                self._ready = True

            self._history.append({
                'timestamp': now,
                'mean': self._effective_mean,
                'stddev': self._effective_stddev,
                'source': source,
                'samples': len(data),
            })

        self._last_recalc = now
        ts = datetime.datetime.utcfromtimestamp(now).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.audit_logger.info(
            f"[{ts}] BASELINE_RECALC ip=* | condition=recalc | "
            f"rate={self._effective_mean:.4f} | baseline={self._effective_mean:.4f} | "
            f"stddev={self._effective_stddev:.4f} | source={source} | samples={len(data)}"
        )
        logger.info(
            f"Baseline: mean={self._effective_mean:.4f} stddev={self._effective_stddev:.4f} "
            f"source={source} samples={len(data)}"
        )
