import json

# Simple report writer, could be implemented into another program, but could be made more robust for different outputs.
def saveReport(data, filename="report.json", verbosity="full"):
    """
    Writes the scan report to a JSON file with optional verbosity control.
    Adds a summary header for each target.
    
    :param data: List of scan results
    :param filename: Output file name
    :param verbosity: "Full" includes all port data, "summary" only targets summaries
    """

    report = []
    for host_data in data:
        target = host_data.get("target", "Unknown")
        open_ports = host_data.get("openPorts", {})

        summary = {
            "target": target,
            "total_open_ports": len(open_ports),
            "vulnerable_ports": sum(
                1 for info in open_ports.values() if info.get("Vulnerable", False)
            ),
        }

        if verbosity == "summary":
            report.append(summary)
        else:
            detailed = {
                "target": target,
                "summary": summary,
                "openPorts": open_ports
            }
            report.append(detailed)

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
