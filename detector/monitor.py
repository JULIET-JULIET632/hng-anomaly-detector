import json
import time
import logging
import threading
import os
from collections import deque, defaultdict

logger = logging.getLogger('monitor')


class LogMonitor:
    def __init__(self, config, detector, shared_state, state_lock):
        self.config = config
        self.detector = detector
        self.shared_state = shared_state
        self.state_lock = state_lock
        self.log_path = config['nginx']['log_path']
        self.window_seconds = config['detection']['window_seconds']
        self.running = False
        self.ip_windows = defaultdict(deque)
        self.global_window = deque()
        self.ip_error_windows = defaultdict(deque)
        self._last_metrics_update = 0

    def stop(self):
        self.running = False

    def _parse_line(self, line):
        line = line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
            source_ip = record.get('source_ip', '')
            if ',' in source_ip:
                source_ip = source_ip.split(',')[0].strip()
            return {
                'source_ip': source_ip,
                'timestamp': float(record.get('timestamp', time.time())),
                'method': record.get('method', ''),
                'path': record.get('path', ''),
                'status': int(record.get('status', 0)),
                'response_size': int(record.get('response_size', 0)),
            }
        except Exception as e:
            logger.debug(f"Parse error: {e} | {line[:80]}")
            return None

    def _evict(self, dq, now):
        while dq and (now - dq[0]) > self.window_seconds:
            dq.popleft()

    def _evict_pairs(self, dq, now):
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()

    def _update_windows(self, record):
        now = record['timestamp']
        ip = record['source_ip']
        is_error = record['status'] >= 400

        ip_dq = self.ip_windows[ip]
        ip_dq.append(now)
        self._evict(ip_dq, now)
        ip_rate = len(ip_dq) / self.window_seconds

        err_dq = self.ip_error_windows[ip]
        err_dq.append((now, is_error))
        self._evict_pairs(err_dq, now)

        self.global_window.append(now)
        self._evict(self.global_window, now)
        global_rate = len(self.global_window) / self.window_seconds

        return ip_rate, global_rate

    def _get_ip_error_rate(self, ip):
        err_dq = self.ip_error_windows.get(ip)
        if not err_dq:
            return 0.0
        error_count = sum(1 for _, is_err in err_dq if is_err)
        return error_count / self.window_seconds

    def _update_shared_state(self, now):
        if now - self._last_metrics_update < 1.0:
            return
        self._last_metrics_update = now
        top_ips = {ip: len(dq) for ip, dq in self.ip_windows.items() if len(dq) > 0}
        with self.state_lock:
            self.shared_state['global_req_rate'] = len(self.global_window) / self.window_seconds
            self.shared_state['top_ips'] = dict(
                sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            )
            self.shared_state['total_requests'] = self.shared_state.get('total_requests', 0) + 1

    def run(self):
        self.running = True
        logger.info(f"LogMonitor watching: {self.log_path}")

        while self.running and not os.path.exists(self.log_path):
            logger.warning(f"Waiting for log file: {self.log_path}")
            time.sleep(5)

        with open(self.log_path, 'r') as f:
            f.seek(0, 2)
            logger.info("Tailing log from current end.")
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                record = self._parse_line(line)
                if not record or not record['source_ip']:
                    continue
                ip = record['source_ip']
                ip_rate, global_rate = self._update_windows(record)
                ip_error_rate = self._get_ip_error_rate(ip)
                self._update_shared_state(record['timestamp'])
                self.detector.evaluate(
                    ip=ip,
                    ip_rate=ip_rate,
                    global_rate=global_rate,
                    ip_error_rate=ip_error_rate,
                    record=record,
                )
        logger.info("LogMonitor stopped.")
