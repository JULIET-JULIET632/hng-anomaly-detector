import threading
import logging
import signal
import sys
import time
import yaml
import os

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import DashboardServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/hng-detector/daemon.log'),
    ]
)
logger = logging.getLogger('main')


def load_config(path='/app/config.yaml'):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def setup_audit_log(config):
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    handler = logging.FileHandler(config['audit']['log_path'])
    handler.setFormatter(logging.Formatter('%(message)s'))
    audit_logger.addHandler(handler)
    audit_logger.propagate = False
    return audit_logger


def main():
    logger.info("=== HNG Anomaly Detection Engine Starting ===")
    config = load_config()
    os.makedirs('/var/log/hng-detector', exist_ok=True)
    audit_logger = setup_audit_log(config)

    shared_state = {
        'banned_ips': {},
        'global_req_rate': 0.0,
        'top_ips': {},
        'effective_mean': 0.0,
        'effective_stddev': 0.0,
        'uptime_start': time.time(),
        'total_requests': 0,
        'baseline_ready': False,
    }
    state_lock = threading.Lock()

    notifier = SlackNotifier(config, audit_logger)
    blocker = IPBlocker(config, notifier, audit_logger, shared_state, state_lock)
    unbanner = AutoUnbanner(config, blocker, notifier, audit_logger, shared_state, state_lock)
    baseline_engine = BaselineEngine(config, audit_logger)
    detector = AnomalyDetector(config, baseline_engine, blocker, notifier, audit_logger, shared_state, state_lock)
    monitor = LogMonitor(config, detector, shared_state, state_lock)
    dashboard = DashboardServer(config, shared_state, state_lock, baseline_engine, blocker)

    def shutdown(signum, frame):
        logger.info("Shutting down...")
        monitor.stop()
        unbanner.stop()
        dashboard.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    threading.Thread(target=monitor.run, name='LogMonitor', daemon=True).start()
    threading.Thread(target=unbanner.run, name='AutoUnbanner', daemon=True).start()
    threading.Thread(target=dashboard.run, name='Dashboard', daemon=True).start()

    logger.info(f"All components started. Dashboard on port {config['dashboard']['port']}")

    while True:
        time.sleep(5)


if __name__ == '__main__':
    main()
