import json
import networkx as nx


def parse_sbom(file_path: str) -> nx.DiGraph:
    """
    Reads a CycloneDX SBOM JSON file and returns a directed dependency graph.
    Handles missing fields, empty components, and circular references safely.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)

    graph = nx.DiGraph()
    components = sbom_data.get('components', [])

    if not components:
        raise ValueError("SBOM file has no components. Please upload a valid CycloneDX SBOM.")

    # Track valid node IDs so we never create dangling edges
    valid_ids = set()

    # STEP 1: Add all nodes (packages)
    for component in components:
        ref = component.get('bom-ref') or f"pkg:{component.get('name', 'unknown')}@{component.get('version', '0.0.0')}"
        valid_ids.add(ref)

        graph.add_node(
            ref,
            name=component.get('name', 'unknown'),
            version=component.get('version', '0.0.0'),
            purl=component.get('purl', ''),
            type=component.get('type', 'library'),
            group=component.get('group', '')
        )

    # STEP 2: Add all edges (dependencies)
    dependencies = sbom_data.get('dependencies', [])
    for dep in dependencies:
        source = dep.get('ref')
        if not source or source not in valid_ids:
            continue

        for target in dep.get('dependsOn', []):
            if target in valid_ids and target != source:
                graph.add_edge(source, target)

    # STEP 3: Detect root applications (nodes that nothing depends on)
    for node in graph.nodes():
        if graph.in_degree(node) == 0:
            graph.nodes[node]['is_root'] = True
        else:
            graph.nodes[node]['is_root'] = False

    return graph