import argparse
from scanner import scanTarget, scanTargets, generateTargets
from VulnScanner.utils.reportWriter import saveReport


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-o", "--output", help="Output file for report (JSON)", default="report.json")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose scan output")
    parser.add_argument("-f", "--full-scan", action="store_true", help="Scan all well-known ports (1-1024)")
    args = parser.parse_args()

    port_list = list(range(1, 1025)) if args.full_scan else None
    targets = generateTargets(args.target)
    report = scanTargets(targets, verbose=args.verbose, port_list=port_list)
    saveReport(report, args.output)

if __name__ == "__main__":
    main()