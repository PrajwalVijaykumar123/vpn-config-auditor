#!/usr/bin/env python3
"""
vpn-config-auditor: audits a real OpenVPN (.ovpn/.conf) or WireGuard
(.conf) config file for weak crypto and missing protections - VORACLE-
enabling compression, missing control-channel HMAC, unverified server
certs, weak ciphers/hashes, and missing WireGuard pre-shared keys.

Usage:
    python3 scanner.py --openvpn client.ovpn
    python3 scanner.py --wireguard wg0.conf
    python3 scanner.py --openvpn server.conf --json report.json --fail-on high
"""
import argparse
import json
import sys

from checks import run_openvpn_checks, run_wireguard_checks

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def severity_at_or_above(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(threshold)


def main():
    parser = argparse.ArgumentParser(description="Audit an OpenVPN or WireGuard config for weak crypto/settings.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--openvpn", metavar="FILE", help="Path to an OpenVPN .ovpn/.conf file")
    mode.add_argument("--wireguard", metavar="FILE", help="Path to a WireGuard .conf file")
    parser.add_argument("--json", dest="json_out", help="Write results to this JSON file")
    parser.add_argument("--fail-on", choices=["any", "low", "medium", "high", "critical"], default="high")
    args = parser.parse_args()

    if args.openvpn:
        with open(args.openvpn) as f:
            text = f.read()
        results = run_openvpn_checks(text)
        label = f"OpenVPN config audit ({args.openvpn})"
    else:
        with open(args.wireguard) as f:
            text = f.read()
        results = run_wireguard_checks(text)
        label = f"WireGuard config audit ({args.wireguard})"

    passed = [r for r in results if r.status == "pass"]
    failed = [r for r in results if r.status == "fail"]
    skipped = [r for r in results if r.status == "skip"]

    print(f"{label}: {len(results)} checks ({len(passed)} pass, {len(failed)} fail, {len(skipped)} skipped)\n")
    if not failed:
        print("No failed checks.")
    else:
        for r in sorted(failed, key=lambda r: SEVERITY_ORDER.index(r.severity), reverse=True):
            print(f"  [FAIL - {r.severity.upper()}] {r.check_id}: {r.title}")
            print(f"      {r.detail}")
            print(f"      Fix: {r.remediation}\n")
    if skipped:
        print("Skipped (directive not found in this config):")
        for r in skipped:
            print(f"  [SKIP] {r.check_id}: {r.title} - {r.detail}")

    if args.json_out:
        with open(args.json_out, "w") as out:
            json.dump([r.__dict__ for r in results], out, indent=2)
        print(f"\nWrote {len(results)} results to {args.json_out}")

    threshold = "low" if args.fail_on == "any" else args.fail_on
    failing = [r for r in failed if severity_at_or_above(r.severity, threshold)]
    sys.exit(1 if failing else 0)


if __name__ == "__main__":
    main()
