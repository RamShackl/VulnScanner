import argparse
from scanner import scanTarget, scanTargets, generateTargets
from reportWriter import saveReport


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-o", "--output", help="Output file for report (JSON)", default="report.json")
    args = parser.parse_args()

    targets = generateTargets(args.target)
    result = scanTarget(args.target)
    saveReport(result, args.output)

if __name__ == "__main__":
    main()