import json
from pyvis.network import Network


def load_report(report_path="report.json"):
    with open(report_path, "r") as f:
        return json.load(f)
    
def sanitize(text):
    return text.replace("<", "").replace(">", "").replace("\"", "'").strip()

def visualize_network_interactive(report):
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white")
    net.barnes_hut()

    MAX_SUMMARY_LEN = 16

    for entry in report:
        target = entry.get("target")
        hostname = entry.get("hostname", "")
        ports = entry.get("openPorts", {})

        if not ports:
            continue

        host_label = f"{hostname} ({target})" if hostname and hostname != target else target
        host_title = f"Host: {target}" + (f"\nHostname: {hostname}" if hostname and hostname != target else "")

        net.add_node(
            target,
            label=host_label,
            title=host_title,
            color="skyblue",
            shape="dot",
            size=25
        )

        
        for port, info in ports.items():
            port_node_id = f"{target}:{port}"
            vulns = info.get("vulnerabilities_found", [])
            vuln_flag = isinstance(vulns, list) and vulns and vulns[0] != "No known vulnerabilities found."

            color = "red" if vuln_flag else "green"
            banner = info.get("banner", "No banner info")

            
            short_banner = banner[:100] + "..." if len(banner) > 100 else banner
            safe_banner = sanitize(short_banner)

            
            if vuln_flag:
                vulns_text = "Vulnerabilities:<br>" + "<br>".join(
                    [
                        f"{cve.get('id')}: {sanitize(cve.get('summary')[:MAX_SUMMARY_LEN])}..."
                        for cve in vulns
                    ]
                )
            else:
                vulns_text = "No known vulnerabilities found."

            tooltip = f"Port {port} | {safe_banner} | {vulns_text}"

            net.add_node(
                port_node_id,
                label=str(port),
                title=tooltip,
                color=color,
                shape="square",
                size=15
            )
            net.add_edge(target, port_node_id)

    net.show_buttons(filter_=['physics'])
    net.show("network_map.html")

if __name__ == "__main__":
    report_data = load_report()
    visualize_network_interactive(report_data)
