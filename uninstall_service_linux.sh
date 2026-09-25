#!/bin/bash
# Stop the Latency Checker logger service and remove the automatic start.
cd "$(dirname "$(readlink -f "$0")")" || exit 1
python3 latency_logger.py uninstall            # per-user service, if any
if [ -f /etc/systemd/system/latency-logger.service ]; then
  sudo python3 latency_logger.py uninstall     # boot service
fi
