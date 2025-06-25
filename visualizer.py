import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

def loadReport(reportPath="report.json"):
    with open(reportPath, "r") as f:
        return json.load(f)
    
def visualizeNetwork(report):
    G = nx.Graph()

    for entry in report:
        target = entry.get("target")
        G.add_node(target, type="host", color="skyblue")

        ports = entry.get("openPorts", {})
        for port, info in ports.items():
            portNode = f"{target}:{port}"
            service = info.get("banner", "").split("\n")[0]
            vulns = info.get("vulnerabilities_found", [])
            vulnFlag = bool(vulns and isinstance(vulns, list) and vulns[0] != "No known vulnerabilities found.")

            # Port node
            G.add_node(portNode, type="port", color="red" if vulnFlag else "green")
            G.add_edge(target, portNode)

    hosts = [n for n, attr in G.nodes(data=True) if attr['type'] == 'host']
    ports = [n for n, attr in G.nodes(data=True) if attr['type'] == 'port']

    
    pos = nx.spring_layout(G, seed=42) # positioning layout

    plt.figure(figsize=(14, 10))

    # Draw ports
    nx.draw_networkx_nodes(G, pos,
                           nodelist=ports,
                           node_shape='s',
                           node_color=[G.nodes[n]['color'] for n in ports],
                           node_size=600,
                           label='Port')

    # Draw edges
    nx.draw_networkx_edges(G, pos, alpha=0.4)

    # Label only hosts for clarity
    labels = {n: n for n in hosts}
    nx.draw_networkx_labels(G, pos, labels, font_size=10, font_weight='bold')

    # Legend
    red_patch = mpatches.Patch(color='red', label='Vulnerable Port')
    green_patch = mpatches.Patch(color='green', label='Non-vulnerable Port')
    blue_patch = mpatches.Patch(color='skyblue', label='Host (IP)')
    plt.legend(handles=[blue_patch, green_patch, red_patch])

    plt.title("Network Map - Hosts and Open Ports")
    plt.axis('off')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    report_data = loadReport()
    visualizeNetwork(report_data)
