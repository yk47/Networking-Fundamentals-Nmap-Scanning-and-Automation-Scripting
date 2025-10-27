#!/usr/bin/env python3
"""
nmap_automation.py

Simple automation script that runs an Nmap SYN scan (-sS) against a target host and
writes a human-readable report (scan_report.txt).

Requirements:
 - nmap (the binary) installed and in PATH
 - python3
 - python-nmap library (install with: pip install python-nmap)

Usage:
    python3 nmap_automation.py --target 192.168.0.103

The script:
 - accepts a target IP or hostname
 - runs an Nmap SYN scan with service/version detection
 - extracts open ports, service names, and versions (when available)
 - writes a timestamped report to scan_report.txt

Notes:
 - Running SYN scans may require root privileges on some systems (Linux/macOS).
 - Modify scan_args if you want different Nmap flags (e.g., add -O for OS detection).
"""

import argparse
import datetime
import sys
import os

try:
    import nmap
except ImportError:
    print("Error: python-nmap module not installed. Install with: pip install python-nmap")
    sys.exit(1)


def run_scan(target, scan_args='-sS -sV -Pn'):
    """Run nmap scan and return the PortScanner object."""
    scanner = nmap.PortScanner()
    print(f"Running: nmap {scan_args} {target}")
    try:
        scanner.scan(hosts=target, arguments=scan_args)
    except nmap.PortScannerError as e:
        print(f"Nmap scan failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error while scanning: {e}")
        sys.exit(1)
    return scanner


def extract_results(scanner):
    """Extract scan results into a structured Python dict."""
    results = {}
    for host in scanner.all_hosts():
        host_info = {
            'addresses': scanner[host].get('addresses', {}),
            'state': scanner[host].get('status', {}).get('state', 'unknown'),
            'tcp': {}
        }
        # TCP ports
        tcp_ports = scanner[host].get('tcp', {})
        for port, port_data in tcp_ports.items():
            host_info['tcp'][port] = {
                'state': port_data.get('state'),
                'name': port_data.get('name'),
                'product': port_data.get('product'),
                'version': port_data.get('version'),
                'extrainfo': port_data.get('extrainfo'),
            }
        results[host] = host_info
    return results


def write_report(results, target, out_path='scan_report.txt'):
    """Write a readable report containing timestamp, target, and open ports."""
    now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    lines = []
    lines.append(f"Scan report generated: {now}\n")
    lines.append(f"Target: {target}\n")

    for host, info in results.items():
        lines.append(f"Host: {host}")
        addr = info.get('addresses', {})
        if 'ipv4' in addr:
            lines.append(f"  IPv4: {addr['ipv4']}")
        if 'ipv6' in addr:
            lines.append(f"  IPv6: {addr['ipv6']}")
        lines.append(f"  State: {info.get('state')}\n")

        tcp = info.get('tcp', {})
        if tcp:
            lines.append("  Open TCP ports:")
            lines.append("  Port | State | Service | Product | Version | ExtraInfo")
            lines.append("  ------------------------------------------------------------")
            for port in sorted(tcp.keys()):
                p = tcp[port]
                lines.append(f"  {port} | {p.get('state')} | {p.get('name') or '-'} | {p.get('product') or '-'} | {p.get('version') or '-'} | {p.get('extrainfo') or '-'}")
        else:
            lines.append("  No open TCP ports found (or not detected).")

        lines.append('\n')

    lines.append("Scan completed. Review the services above and research any suspicious/unknown entries.")

    try:
        with open(out_path, 'w') as f:
            f.write('\n'.join(lines))
        print(f"Report written to {out_path}")
    except Exception as e:
        print(f"Failed to write report: {e}")


def main():
    parser = argparse.ArgumentParser(description='Automate an Nmap SYN scan and produce a report.')
    parser.add_argument('--target', '-t', required=True, help='Target IP address or hostname to scan (e.g., 192.168.0.103)')
    parser.add_argument('--out', '-o', default='scan_report.txt', help='Output report filename')
    parser.add_argument('--args', default='-sS -sV -Pn', help='Additional nmap arguments (default: "-sS -sV -Pn")')
    args = parser.parse_args()

    # Check nmap binary exists
    if not shutil_which('nmap'):
        print('Error: nmap binary not found in PATH. Install nmap and ensure it is available.')
        sys.exit(1)

    scanner = run_scan(args.target, scan_args=args.args)
    results = extract_results(scanner)
    write_report(results, args.target, out_path=args.out)


def shutil_which(name):
    """Small helper to check for binary in PATH without importing shutil directly where older Python may not have it."""
    from shutil import which
    return which(name)


if __name__ == '__main__':
    main()
