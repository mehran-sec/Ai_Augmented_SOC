#!/usr/bin/env python3
"""
Wazuh -> n8n integration script.

Wazuh calls this automatically when an alert matching the <integration>
block in ossec.conf fires. It receives:
    sys.argv[1] = path to a temp file containing the alert JSON
    sys.argv[2] = API key (<api_key> in ossec.conf) -> sent as X-Webhook-Token
    sys.argv[3] = hook_url (the n8n webhook URL from ossec.conf)

It reads the alert, adds a couple of useful fields, and POSTs it to n8n.
Failures are logged locally so you can debug without losing alerts silently.
"""

import sys
import json
import logging
import os
import time
from datetime import datetime, timezone

# urllib is stdlib-only on purpose — Wazuh's bundled python may not have `requests`
import urllib.request
import urllib.error

# ---- Configuration ----
LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECONDS = 10
MAX_RETRIES = 3
BACKOFF_SECONDS = (1, 2)   # kept short: integratord waits for this script
AUTH_HEADER = "X-Webhook-Token"


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s custom-n8n: %(levelname)s: %(message)s",
    )


def read_alert(alert_file_path):
    """Read and parse the Wazuh alert JSON file Wazuh wrote to disk."""
    with open(alert_file_path, "r") as f:
        return json.load(f)


def build_payload(alert):
    """
    Wazuh's alert JSON is deeply nested and inconsistent across rule types.
    We don't fully normalize here (that's n8n's job in step 2) — we just
    make sure the fields n8n needs to normalize/fingerprint are always
    present, even if null, so n8n never crashes on a missing key.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    payload = {
        "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "rule_level": rule.get("level"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "user": data.get("srcuser") or data.get("dstuser"),
        "src_ip": data.get("srcip"),
        "command": data.get("command"),
        "full_log": alert.get("full_log"),
        "raw_alert": alert,  # keep the full original in case n8n needs more later
    }
    return payload


def send_to_n8n(hook_url, payload, api_key=None):
    """POST the payload to the n8n webhook, with basic retry on failure."""
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key and api_key.lower() != "none":
        headers[AUTH_HEADER] = api_key     # n8n webhook Header Auth checks this
    req = urllib.request.Request(hook_url, data=data, headers=headers, method="POST")

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                logging.info(
                    "Sent alert rule_id=%s to n8n, status=%s",
                    payload.get("rule_id"),
                    resp.status,
                )
                return True
        except Exception as e:             # URLError, HTTPError, socket timeouts, resets
            last_error = e
            logging.warning(
                "Attempt %s/%s failed sending to n8n: %s", attempt, MAX_RETRIES, e
            )
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)])

    logging.error("All attempts to send alert to n8n failed: %s", last_error)
    return False


def main():
    setup_logging()

    if len(sys.argv) < 4:
        logging.error("Missing arguments. Expected: alert_file api_key hook_url")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    try:
        alert = read_alert(alert_file_path)
    except Exception as e:
        logging.error("Failed to read/parse alert file %s: %s", alert_file_path, e)
        sys.exit(1)

    payload = build_payload(alert)
    ok = send_to_n8n(hook_url, payload, api_key)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
