import networkx as nx


# --- SIMULATED CVE DATABASE (Real-world CVE patterns) ---
# In production, this would query OSV.dev / NVD in real-time.
CVE_DATABASE = {
    # CRITICAL (>70)
    "pkg:npm/express@4.18.2": 88.0,
    "pkg:npm/body-parser@1.20.1": 82.0,
    "pkg:npm/path-to-regexp@0.1.7": 90.0,        # CVE-2024-45296 ReDoS
    "pkg:npm/jsonwebtoken@9.0.2": 75.0,
    "pkg:npm/qs@6.11.0": 72.0,

    # HIGH (40-70)
    "pkg:npm/axios@1.6.0": 55.0,
    "pkg:npm/mongoose@7.5.0": 55.0,
    "pkg:npm/bcrypt@5.1.1": 55.0,
    "pkg:npm/validator@13.11.0": 55.0,
    "pkg:npm/semver@7.5.4": 55.0,
    "pkg:npm/debug@2.6.9": 50.0,
    "pkg:npm/follow-redirects@1.15.2": 45.0,
    "pkg:npm/lodash@4.17.21": 45.0,
    "pkg:npm/send@0.18.0": 45.0,
    "pkg:npm/serve-static@1.15.0": 45.0,
    "pkg:npm/mquery@5.0.0": 45.0,
    "pkg:npm/debug@4.3.4": 42.0,
    "pkg:npm/raw-body@2.5.1": 40.0,
    "pkg:npm/cookie@0.5.0": 35.0,

    # LOW (<40)
    "pkg:npm/winston@3.10.0": 30.0,
    "pkg:npm/form-data@4.0.0": 30.0,
    "pkg:npm/scheduler@0.23.0": 25.0,
    "pkg:npm/uuid@9.0.0": 20.0,
    "pkg:npm/react@18.2.0": 20.0,
    "pkg:npm/react-dom@18.2.0": 20.0,
    "pkg:npm/dotenv@16.3.1": 15.0,
    "pkg:npm/cors@2.8.5": 15.0,
    "pkg:npm/helmet@7.0.0": 10.0,
    "pkg:npm/ms@2.0.0": 15.0,
        # LOW (<40)
    "pkg:npm/winston@3.10.0": 30.0,
    "pkg:npm/form-data@4.0.0": 30.0,
    "pkg:npm/scheduler@0.23.0": 25.0,
    "pkg:npm/uuid@9.0.0": 20.0,
    "pkg:npm/react@18.2.0": 20.0,
    "pkg:npm/react-dom@18.2.0": 20.0,
    "pkg:npm/dotenv@16.3.1": 15.0,
    "pkg:npm/cors@2.8.5": 15.0,
    "pkg:npm/helmet@7.0.0": 10.0,
    "pkg:npm/ms@2.0.0": 15.0,

    # ---- PYTHON (for logistics demo) ----
    "pkg:pypi/django@4.2.7": 72.0,
    "pkg:pypi/requests@2.31.0": 78.0,
    "pkg:pypi/cryptography@41.0.7": 82.0,
    "pkg:pypi/jwt@2.8.0": 68.0,
    "pkg:pypi/flask@3.0.0": 55.0,
    "pkg:pypi/sqlalchemy@2.0.23": 45.0,
    "pkg:pypi/urllib3@2.1.0": 50.0,
}



def calculate_risk_scores(graph: nx.DiGraph) -> dict:
    """Comprehensive risk score combining structure + vulnerabilities."""
    if graph.number_of_nodes() == 0:
        return {}

    try:
        betweenness = nx.betweenness_centrality(graph)
    except Exception:
        betweenness = {n: 0.0 for n in graph.nodes()}

    try:
        pagerank = nx.pagerank(graph, alpha=0.85)
    except Exception:
        pagerank = {n: 0.0 for n in graph.nodes()}

    scores = {}
    for node in graph.nodes():
        bc_score = betweenness.get(node, 0.0) * 100
        pr_score = pagerank.get(node, 0.0) * 300
        in_deg = graph.in_degree(node)
        out_deg = graph.out_degree(node)
        in_deg_score = min(in_deg * 8, 100)

        structural_risk = (bc_score * 0.4) + (pr_score * 0.3) + (in_deg_score * 0.3)
        cve_score = CVE_DATABASE.get(node, 0.0)

        final_score = max(structural_risk, cve_score)
        if final_score < 10:
            final_score = 10.0
        final_score = min(final_score, 100.0)

        is_root = graph.nodes[node].get('is_root', False)
        node_type = "Application" if is_root else "Dependency"

        scores[node] = {
            'centrality': round(betweenness.get(node, 0.0), 4),
            'pagerank': round(pagerank.get(node, 0.0), 4),
            'risk_score': round(final_score, 1),
            'in_degree': in_deg,
            'out_degree': out_deg,
            'cve_score': cve_score,
            'has_cve': cve_score > 0,
            'type': node_type,
            'is_root': is_root,
        }
    return scores


def get_mitigation_priorities(graph: nx.DiGraph, scores: dict) -> list:
    """Ranks dependency packages by risk, counting affected applications."""
    priorities = []
    root_apps = [n for n in graph.nodes() if graph.nodes[n].get('is_root', False)]

    for node, data in scores.items():
        if data['type'] != "Dependency":
            continue
        if data['risk_score'] < 30:
            continue

        affected_apps = []
        for app in root_apps:
            try:
                if nx.has_path(graph, app, node):
                    affected_apps.append(app)
            except nx.NetworkXError:
                continue

        if len(affected_apps) == 0:
            continue

        priorities.append({
            "id": node,
            "name": graph.nodes[node].get('name', node),
            "version": graph.nodes[node].get('version', ''),
            "risk_score": data['risk_score'],
            "has_cve": data['has_cve'],
            "cve_score": data['cve_score'],
            "affected_apps_count": len(affected_apps),
            "affected_apps": [graph.nodes[a].get('name', a) for a in affected_apps],
        })

    return sorted(priorities, key=lambda x: x['risk_score'], reverse=True)


def simulate_compromise(graph: nx.DiGraph, compromised_node: str) -> dict:
    """Simulates compromise and calculates full blast radius."""
    if compromised_node not in graph:
        return {"error": "Package not found in dependency graph."}

    try:
        blast_radius = list(nx.descendants(graph, compromised_node))
    except nx.NetworkXError:
        blast_radius = []

    root_apps = [n for n in graph.nodes() if graph.nodes[n].get('is_root', False)]
    affected_apps = []
    for app in root_apps:
        try:
            if nx.has_path(graph, app, compromised_node):
                affected_apps.append({
                    "id": app,
                    "name": graph.nodes[app].get('name', app)
                })
        except nx.NetworkXError:
            continue

    propagation_paths = []
    for target in blast_radius[:10]:
        try:
            path = nx.shortest_path(graph, source=compromised_node, target=target)
            propagation_paths.append([graph.nodes[n].get('name', n) for n in path])
        except nx.NetworkXNoPath:
            continue

    max_depth = 0
    for target in blast_radius:
        try:
            depth = nx.shortest_path_length(graph, source=compromised_node, target=target)
            max_depth = max(max_depth, depth)
        except nx.NetworkXNoPath:
            continue

    if len(affected_apps) >= 3 or max_depth >= 4:
        severity = "CRITICAL"
    elif len(affected_apps) >= 1 or max_depth >= 2:
        severity = "HIGH"
    else:
        severity = "LOW"

    return {
        "compromised_node": compromised_node,
        "compromised_name": graph.nodes[compromised_node].get('name', compromised_node),
        "blast_radius": blast_radius,
        "affected_count": len(blast_radius),
        "affected_apps": affected_apps,
        "affected_apps_count": len(affected_apps),
        "propagation_paths": propagation_paths,
        "max_depth": max_depth,
        "severity": severity,
    }


def get_graph_summary(graph: nx.DiGraph, scores: dict) -> dict:
    """High-level dashboard metrics."""
    total = graph.number_of_nodes()
    critical = sum(1 for d in scores.values() if d['risk_score'] >= 70)
    high = sum(1 for d in scores.values() if 40 <= d['risk_score'] < 70)
    low = sum(1 for d in scores.values() if d['risk_score'] < 40)
    roots = sum(1 for n in graph.nodes() if graph.nodes[n].get('is_root', False))

    return {
        "total_packages": total,
        "total_edges": graph.number_of_edges(),
        "critical_count": critical,
        "high_count": high,
        "low_count": low,
        "applications_count": roots,
        "dependency_count": total - roots,
    }