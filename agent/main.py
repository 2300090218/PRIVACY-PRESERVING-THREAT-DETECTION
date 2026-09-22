"""
Local Organization Agent CLI & Service Runner
Usage:
    python -m agent.main --test [EVENT_TYPE]    # Send a single test event (FAILED_LOGIN, BRUTE_FORCE, PORT_SCAN)
    python -m agent.main --status               # Display agent status & local queue
    python -m agent.main --loop [INTERVAL_SEC]  # Run continuous background telemetry collection
"""

import sys
import time
import argparse
import json
from agent.client import LocalAgentClient

def print_banner():
    print("""
=============================================================================
  LOCAL ORGANIZATION AGENT (Organization A - DMZ Gateway)
  Local Privacy Gateway  *  Zero PII Egress  *  Resilient Queue
=============================================================================
""")

def main():
    parser = argparse.ArgumentParser(description="Local Organization Privacy-Preserving Agent")
    parser.add_argument("--test", nargs="?", const="FAILED_LOGIN", help="Generate and send a single test event (FAILED_LOGIN, BRUTE_FORCE, PORT_SCAN, SUSPICIOUS_ACTIVITY, BENIGN)")
    parser.add_argument("--status", action="store_true", help="Show current agent health and queue status")
    parser.add_argument("--loop", type=float, nargs="?", const=3.0, help="Run continuous telemetry collection with interval in seconds")
    args = parser.parse_args()

    client = LocalAgentClient()

    if args.status:
        health = client.get_health_status()
        print(json.dumps(health, indent=2))
        return

    print_banner()

    if args.test:
        event_type = args.test.upper()
        print(f"[*] Generating local RAW telemetry event: {event_type}")
        raw_event = client.collector.create_raw_test_event(event_type=event_type)
        print(f"    Raw event fields locally: {list(raw_event.keys())}")
        print(f"    Sensitive PII present locally:")
        print(f"      - username: {raw_event.get('username')}")
        print(f"      - source_ip: {raw_event.get('source_ip')}")
        print(f"      - device_id: {raw_event.get('device_id')}")
        print(f"      - location: {raw_event.get('location')}")

        print("\n[*] Passing through Local Privacy Gateway...")
        success, resp = client.process_and_transmit(raw_event)
        if success:
            print(f"[+] SUCCESS: Transmitted protected event to Central API.")
            print(f"    Response: {json.dumps(resp, indent=2)}")
        else:
            print(f"[-] FAILED: Could not transmit to Central API (event safely queued).")
            print(f"    Details: {json.dumps(resp, indent=2)}")
        return

    if args.loop:
        interval = args.loop
        print(f"[*] Starting continuous telemetry collection (Interval: {interval}s)...")
        print("    Press Ctrl+C to terminate.")
        scenarios = ["BENIGN", "FAILED_LOGIN", "BENIGN", "BRUTE_FORCE", "BENIGN", "PORT_SCAN", "SUSPICIOUS_ACTIVITY"]
        idx = 0
        try:
            while True:
                scen = scenarios[idx % len(scenarios)]
                raw = client.collector.create_raw_test_event(scen)
                success, _ = client.process_and_transmit(raw)
                status_str = "OK" if success else "QUEUED"
                print(f"[{time.strftime('%H:%M:%S')}] Telemetry [{scen}] -> Privacy Gateway -> [{status_str}]")
                idx += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Stopping agent...")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
