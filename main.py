"""
SOC Sentinel — Host-based Intrusion Detection System
=====================================================
Entry point and orchestration layer.

Usage:
    python main.py                          # Run with default config.yaml
    python main.py --config /path/to.yaml   # Custom config
    python main.py --install                # Register as system startup service
    python main.py --uninstall              # Remove startup service
    python main.py --verbose                # Debug-level logging
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
from core.monitor import SystemMonitor
from core.detector import AnomalyDetector
from core.rules import Rules
from alerts.logger import AlertLogger
from alerts.sound_alert import SoundAlert
from alerts.popup_alert import PopupAlert
from ai.analyzer import AIAnalyzer
from utils.config import load_config, DEFAULT_CONFIG_PATH
from utils.installer import install_service, uninstall_service
from utils.models import Alert, AnalysisResult

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
    )


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------
class SentinelOrchestrator:
    """
    Wires together monitoring → detection → alerting → AI analysis.

    Each monitoring cycle:
      1. Collect a SystemSnapshot via monitor.
      2. Evaluate snapshot against rules via detector.
      3. For each resulting Alert, dispatch the full pipeline in a daemon
         thread so slow AI calls never stall the monitoring loop.
    """

    def __init__(self, config: dict) -> None:
        self.config = config
        self.running = False
        self._log = logging.getLogger(self.__class__.__name__)

        rules = Rules.from_config(config)
        self._monitor = SystemMonitor(config["monitoring"])
        self._detector = AnomalyDetector(rules)
        self._logger = AlertLogger(config["alerts"])
        self._sound = SoundAlert(
            enabled=config["alerts"]["sound"],
            threshold=config["alerts"]["notify_threshold"],
        )
        self._popup = PopupAlert(
            enabled=config["alerts"]["popup"],
            threshold=config["alerts"]["notify_threshold"],
        )
        self._ai = AIAnalyzer(config["ai"])

    # ------------------------------------------------------------------
    # Alert pipeline
    # ------------------------------------------------------------------
    def _dispatch(self, alert: Alert) -> None:
        """
        Full pipeline for a single Alert.
        Runs in its own daemon thread — AI latency is isolated here.
        """
        # 1. Persist the raw alert immediately (before AI, so nothing is lost
        #    even if the AI call times out or fails).
        self._logger.write_alert(alert)

        # 2. Notify the operator.
        self._sound.trigger(alert)
        self._popup.show(alert)

        # 3. AI classification and report (optional, non-blocking for caller).
        if self.config["ai"]["enabled"]:
            try:
                analysis: AnalysisResult = self._ai.analyze(alert)
                self._logger.write_analysis(alert, analysis)
                self._log.info(
                    "[%s] %s — AI severity: %s",
                    alert.alert_id,
                    alert.title,
                    analysis.severity,
                )
            except Exception as exc:
                # AI failure must never suppress the original alert.
                self._log.warning(
                    "AI analysis failed for alert %s: %s", alert.alert_id, exc
                )

    def _handle_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            threading.Thread(
                target=self._dispatch,
                args=(alert,),
                name=f"sentinel-alert-{alert.alert_id}",
                daemon=True,
            ).start()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def run(self) -> None:
        interval: int = self.config["monitoring"]["interval"]
        self.running = True

        self._log.info("=" * 60)
        self._log.info("  SOC Sentinel started  |  interval: %ds", interval)
        self._log.info("=" * 60)

        while self.running:
            try:
                snapshot = self._monitor.collect()
                alerts = self._detector.evaluate(snapshot)

                if alerts:
                    self._log.warning(
                        "%d anomaly(s) detected in this cycle", len(alerts)
                    )
                    self._handle_alerts(alerts)
                else:
                    self._log.debug("Cycle clean — no anomalies detected")

            except Exception as exc:
                # Log unexpected collection/detection errors but keep running.
                self._log.error("Error during monitoring cycle: %s", exc, exc_info=True)

            time.sleep(interval)

    def stop(self) -> None:
        self._log.info("Shutdown signal received — stopping SOC Sentinel.")
        self.running = False


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
def _register_signals(orchestrator: SentinelOrchestrator) -> None:
    def _handler(signum: int, frame) -> None:  # noqa: ANN001
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):      # SIGTERM not available on Windows
        signal.signal(signal.SIGTERM, _handler)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-sentinel",
        description=(
            "SOC Sentinel — Host-based Intrusion Detection System\n"
            "Monitors CPU, RAM, processes, and network connections in real time."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                          # Start with default config\n"
            "  python main.py -c /etc/sentinel.yaml   # Custom config path\n"
            "  python main.py --install                # Enable on system startup\n"
            "  python main.py --uninstall              # Disable startup service\n"
        ),
    )

    parser.add_argument(
        "--config", "-c",
        default=str(DEFAULT_CONFIG_PATH),
        metavar="PATH",
        help=f"Path to config.yaml  (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install SOC Sentinel as a system startup service and exit",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the startup service installed by --install and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging (very noisy — use for development)",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)
    log = logging.getLogger("sentinel.main")

    # ------------------------------------------------------------------
    # Service management commands — act and exit immediately
    # ------------------------------------------------------------------
    if args.install and args.uninstall:
        parser.error("--install and --uninstall are mutually exclusive.")

    if args.install:
        install_service()
        return

    if args.uninstall:
        uninstall_service()
        return

    # ------------------------------------------------------------------
    # Load configuration
    # ------------------------------------------------------------------
    config_path = Path(args.config)
    if not config_path.exists():
        log.error(
            "Config file not found: %s\n"
            "Copy config.yaml to that path, or pass --config <path>.",
            config_path,
        )
        sys.exit(1)

    config = load_config(config_path)
    log.debug("Configuration loaded from %s", config_path)

    # Ensure log directory exists
    log_file = Path(config["alerts"]["log_path"])
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build orchestrator, wire signals, start
    # ------------------------------------------------------------------
    orchestrator = SentinelOrchestrator(config)
    _register_signals(orchestrator)

    try:
        orchestrator.run()
    except KeyboardInterrupt:
        orchestrator.stop()
    except Exception as exc:
        log.critical("Fatal error in orchestrator: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
