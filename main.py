from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanners.sbom_parser import parse_sbom
from analysis.risk_engine import (
    calculate_risk_scores,
    get_mitigation_priorities,
    simulate_compromise,
    get_graph_summary,
)
import os

app = FastAPI(title="SupplyChain Sentinel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory state for the demo
current_graph = None
current_scores = None
uploaded_filename = None

UPLOAD_DIR = "data"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class HistoryItem(BaseModel):
    filename: str


@app.post("/api/upload-sbom/")
async def upload_sbom(file: UploadFile = File(...)):
    """Uploads and parses an SBOM file into a dependency graph."""
    global current_graph, current_scores, uploaded_filename

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    if not (file.filename.endswith('.json') or file.filename.endswith('.xml')):
        raise HTTPException(status_code=400, detail="Only .json or .xml SBOM files are supported.")

    try:
        file_location = os.path.join(UPLOAD_DIR, file.filename)
        contents = await file.read()
        with open(file_location, "wb") as f:
            f.write(contents)

        current_graph = parse_sbom(file_location)
        current_scores = calculate_risk_scores(current_graph)
        uploaded_filename = file.filename

        return {
            "message": "SBOM parsed successfully.",
            "filename": file.filename,
            "nodes": current_graph.number_of_nodes(),
            "edges": current_graph.number_of_edges(),
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse SBOM: {str(e)}")


@app.get("/api/analyze/")
async def analyze_graph():
    """Returns the full graph with nodes enriched by risk scores."""
    if current_graph is None or current_scores is None:
        raise HTTPException(status_code=400, detail="No SBOM uploaded yet. Please upload a file first.")

    nodes_data = []
    for node in current_graph.nodes():
        score = current_scores.get(node, {})
        nodes_data.append({
            "id": node,
            "name": current_graph.nodes[node].get('name', node),
            "version": current_graph.nodes[node].get('version', ''),
            "risk_score": score.get('risk_score', 0),
            "centrality": score.get('centrality', 0),
            "in_degree": score.get('in_degree', 0),
            "out_degree": score.get('out_degree', 0),
            "type": score.get('type', 'Dependency'),
            "has_cve": score.get('has_cve', False),
        })

    edges_data = [{"source": u, "target": v} for u, v in current_graph.edges()]

    return {"nodes": nodes_data, "edges": edges_data}


@app.get("/api/priorities/")
async def get_priorities():
    """Returns ranked mitigation priorities."""
    if current_graph is None or current_scores is None:
        raise HTTPException(status_code=400, detail="No SBOM uploaded yet.")

    priorities = get_mitigation_priorities(current_graph, current_scores)
    return {"priorities": priorities}


@app.get("/api/summary/")
async def get_summary():
    """Returns high-level dashboard metrics."""
    if current_graph is None or current_scores is None:
        raise HTTPException(status_code=400, detail="No SBOM uploaded yet.")

    return get_graph_summary(current_graph, current_scores)


@app.post("/api/simulate/")
async def simulate(node_id: str):
    """Simulates a compromise on the given node."""
    if current_graph is None:
        raise HTTPException(status_code=400, detail="No SBOM uploaded yet.")

    result = simulate_compromise(current_graph, node_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# Serve the frontend (must be mounted LAST)
app.mount("/", StaticFiles(directory="static", html=True), name="static")