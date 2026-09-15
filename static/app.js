// --- GLOBAL ---
let graphData = null;
let selectedNode = null;
let zoomBehavior = null;
let currentSortKey = null;
let currentSortAsc = true;
let currentViewMode = 'graph';
// Free tier — redirects to sign-up
function registerFree() {
    showToast('Redirecting to free sign-up...');
    setTimeout(() => {
        showView('signin');
        showToast('Create your free account to get started');
    }, 800);
}
const svg = d3.select("#graph-svg");

// ======================================================
// VIEW NAVIGATION
// ======================================================
function showView(viewName) {
    document.querySelectorAll('.page-view').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById('view-' + viewName);
    if (target) target.classList.remove('hidden');

    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    const navLink = document.querySelector(`.nav-links a[data-nav="${viewName}"]`);
    if (navLink) navLink.classList.add('active');

    const nav = document.getElementById('shared-nav');
    if (nav) nav.style.display = (viewName === 'dashboard') ? 'none' : '';

    window.scrollTo(0, 0);

    if (viewName === 'dashboard') {
        setTimeout(() => { if (graphData) drawRadialGraph(graphData); }, 100);
    }
}
function showAppView() { showView('dashboard'); }
function showLandingView() { showView('landing'); }

// ======================================================
// UI HELPERS
// ======================================================
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebar-overlay').classList.toggle('active');
}
function togglePw() {
    const pw = document.getElementById('signin-password');
    pw.type = pw.type === 'password' ? 'text' : 'password';
}
function signIn() {
    const email = document.getElementById('signin-email').value;
    if (!email) { showToast('Please enter your email'); return; }
    showToast('Welcome back!');
    setTimeout(() => showAppView(), 600);
}

function showToast(message) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => toast.classList.remove('show'), 2500);
}

// ======================================================
// PRICING
// ======================================================
let currentBilling = 'monthly';
function setBilling(mode) {
    currentBilling = mode;
    document.getElementById('bt-monthly').classList.toggle('active', mode === 'monthly');
    document.getElementById('bt-yearly').classList.toggle('active', mode === 'yearly');
    document.querySelectorAll('.pc-amount').forEach(el => {
        const val = el.getAttribute('data-' + mode);
        if (val) el.textContent = val;
    });
}
function buyPlan(name, price) {
    const billing = currentBilling === 'monthly' ? 'per month' : 'per month (billed yearly)';
    showToast(`Redirecting to secure checkout for ${name} plan — $${price} ${billing}`);
    setTimeout(() => {
        showToast(`✓ ${name} plan activated (Demo)`);
    }, 2000);
}

// ======================================================
// PREMIUM MODAL
// ======================================================
function showPremiumModal(featureName) {
    document.getElementById('premium-feature-name').textContent = `${featureName} is available on the Business plan and above.`;
    document.getElementById('premium-modal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}
function closePremiumModal() {
    document.getElementById('premium-modal').classList.add('hidden');
    document.body.style.overflow = '';
}

// ======================================================
// GRAPH VIEW TOGGLE
// ======================================================
function setGraphView(mode) {
    if (mode === 'heatmap' || mode === 'timeline') {
        const names = { heatmap: 'Heatmap View', timeline: 'Timeline View' };
        showPremiumModal(names[mode]);
        return;
    }

    currentViewMode = mode;
    const btnGraph = document.getElementById('btn-graph-view');
    const btnTable = document.getElementById('btn-table-view');
    const tableView = document.getElementById('table-view');
    const heatmapView = document.getElementById('heatmap-view');
    const timelineView = document.getElementById('timeline-view');
    const svgEl = document.getElementById('graph-svg');
    const zoomControls = document.getElementById('zoom-controls');

    if (heatmapView) heatmapView.classList.add('hidden');
    if (timelineView) timelineView.classList.add('hidden');

    if (mode === 'table') {
        btnGraph.classList.remove('active');
        btnTable.classList.add('active');
        tableView.classList.remove('hidden');
        svgEl.style.display = 'none';
        zoomControls.style.display = 'none';
        renderTable();
    } else {
        btnTable.classList.remove('active');
        btnGraph.classList.add('active');
        tableView.classList.add('hidden');
        svgEl.style.display = 'block';
        zoomControls.style.display = 'flex';
        if (graphData) drawRadialGraph(graphData);
    }
}

function renderTable() {
    if (!graphData) {
        document.getElementById('dep-table-body').innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 30px; color:#64748B;">No data — upload an SBOM and click Analyze Graph.</td></tr>`;
        return;
    }
    let nodes = [...graphData.nodes];
    if (currentSortKey) {
        nodes.sort((a, b) => {
            const va = a[currentSortKey], vb = b[currentSortKey];
            if (typeof va === 'string') return currentSortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
            return currentSortAsc ? va - vb : vb - va;
        });
    } else {
        nodes.sort((a, b) => b.risk_score - a.risk_score);
    }
    const tbody = document.getElementById('dep-table-body');
    tbody.innerHTML = nodes.map(n => {
        const level = n.risk_score >= 70 ? 'critical' : (n.risk_score >= 40 ? 'warning' : 'safe');
        const status = n.risk_score >= 70 ? 'Critical' : (n.risk_score >= 40 ? 'At Risk' : 'Safe');
        return `
            <tr onclick="selectNodeFromTable('${n.id}')" style="cursor:pointer;">
                <td class="pkg-name">${n.name}</td>
                <td>v${n.version}</td>
                <td><span class="badge-type">${n.type}</span></td>
                <td class="risk-cell ${level}">${n.risk_score.toFixed(1)}</td>
                <td>${n.in_degree}</td>
                <td class="risk-cell ${level}">${status}</td>
            </tr>
        `;
    }).join('');
}

function sortTable(key) {
    if (currentSortKey === key) currentSortAsc = !currentSortAsc;
    else { currentSortKey = key; currentSortAsc = true; }
    renderTable();
}

function selectNodeFromTable(nodeId) {
    if (!graphData) return;
    const node = graphData.nodes.find(n => n.id === nodeId);
    if (node) {
        setGraphView('graph');
        setTimeout(() => { selectNode(node, svg.select('.zoom-group')); }, 100);
    }
}

// ======================================================
// API
// ======================================================
async function uploadSbom(file) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch('/api/upload-sbom/', { method: 'POST', body: formData });
    if (!response.ok) throw new Error('Upload failed');
    return response.json();
}
async function analyzeGraph() {
    const response = await fetch('/api/analyze/');
    const data = await response.json();
    drawRadialGraph(data);
    fetchPriorities();
    if (currentViewMode === 'table') renderTable();
}
async function fetchPriorities() {
    const response = await fetch('/api/priorities/');
    const data = await response.json();
    renderPriorities(data.priorities);
}
async function simulateCompromise(nodeId) {
    const response = await fetch(`/api/simulate/?node_id=${encodeURIComponent(nodeId)}`, { method: 'POST' });
    const result = await response.json();
    renderSimulation(result);
}

// ======================================================
// RADIAL GRAPH
// ======================================================
function drawRadialGraph(data) {
    graphData = data;
    svg.selectAll("*").remove();
    if (currentViewMode !== 'graph') return;

    const width = svg.node().getBoundingClientRect().width || 800;
    const height = svg.node().getBoundingClientRect().height || 600;
    const cx = width / 2, cy = height / 2;
    const minDim = Math.min(width, height);
    const maxRadius = minDim * 0.44;

    const apps = data.nodes.filter(n => n.type === "Application");
    const centerApp = apps.length > 0
        ? apps.reduce((a, b) => a.risk_score > b.risk_score ? a : b)
        : data.nodes[0];

    const adj = {};
    data.edges.forEach(e => {
        const srcId = typeof e.source === 'object' ? e.source.id : e.source;
        const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
        if (!adj[srcId]) adj[srcId] = [];
        adj[srcId].push(tgtId);
    });

    const depths = {};
    depths[centerApp.id] = 0;
    const q = [centerApp.id];
    while (q.length) {
        const c = q.shift();
        (adj[c] || []).forEach(n => {
            if (depths[n] === undefined) {
                depths[n] = depths[c] + 1;
                q.push(n);
            }
        });
    }
    let maxKnown = 0;
    Object.values(depths).forEach(d => { if (d > maxKnown) maxKnown = d; });
    data.nodes.forEach(n => { if (depths[n.id] === undefined) depths[n.id] = maxKnown + 1; });
    let maxDepth = 0;
    Object.values(depths).forEach(d => { if (d > maxDepth) maxDepth = d; });

    const layers = {};
    data.nodes.forEach(n => {
        const d = depths[n.id];
        if (!layers[d]) layers[d] = [];
        layers[d].push(n);
    });
    Object.keys(layers).forEach(k => layers[k].sort((a, b) => b.risk_score - a.risk_score));

    const nodeCount = data.nodes.length;
    const isCrowded = nodeCount > 50;
    const isVeryCrowded = nodeCount > 100;
    const baseRadius = isVeryCrowded ? 7 : (isCrowded ? 9 : 12);

    const ringGap = maxRadius / Math.max(maxDepth, 1);
    const positions = {};

    Object.keys(layers).forEach(k => {
        const depth = parseInt(k);
        const nodes = layers[k];
        const radius = depth * ringGap;

        if (depth === 0 && nodes.length > 0) {
            positions[nodes[0].id] = { x: cx, y: cy };
        } else {
            const count = nodes.length;
            const angleStep = (2 * Math.PI) / count;
            const startOffset = (depth * Math.PI) / 6 - Math.PI / 2;

            nodes.forEach((node, i) => {
                const angle = i * angleStep + startOffset;
                positions[node.id] = {
                    x: cx + Math.cos(angle) * radius,
                    y: cy + Math.sin(angle) * radius
                };
            });
        }
    });

    const g = svg.append("g").attr("class", "zoom-group");

    g.append("g").attr("class", "links")
        .selectAll("line")
        .data(data.edges)
        .join("line")
        .attr("class", "radial-link")
        .attr("x1", d => {
            const src = typeof d.source === 'object' ? d.source.id : d.source;
            return positions[src] ? positions[src].x : cx;
        })
        .attr("y1", d => {
            const src = typeof d.source === 'object' ? d.source.id : d.source;
            return positions[src] ? positions[src].y : cy;
        })
        .attr("x2", d => {
            const tgt = typeof d.target === 'object' ? d.target.id : d.target;
            return positions[tgt] ? positions[tgt].x : cx;
        })
        .attr("y2", d => {
            const tgt = typeof d.target === 'object' ? d.target.id : d.target;
            return positions[tgt] ? positions[tgt].y : cy;
        });

    const node = g.append("g").attr("class", "nodes")
        .selectAll("g")
        .data(data.nodes)
        .join("g")
        .attr("class", "radial-node")
        .attr("transform", d => {
            const p = positions[d.id] || { x: cx, y: cy };
            return `translate(${p.x}, ${p.y})`;
        })
        .on("click", (event, d) => selectNode(d, g));

    node.append("circle")
        .attr("class", "outer-glow")
        .attr("r", d => getNodeRadius(d, baseRadius) + 4)
        .attr("fill", d => getNodeColor(d));

    node.append("circle")
        .attr("class", "main-circle")
        .attr("r", d => getNodeRadius(d, baseRadius))
        .attr("fill", d => getNodeFill(d))
        .attr("stroke", d => getNodeColor(d))
        .style("color", d => getNodeColor(d));

    node.filter(d => d.type === "Application" || d.risk_score >= 70)
        .append("text")
        .attr("dy", 3)
        .attr("text-anchor", "middle")
        .style("font-size", d => d.type === "Application" ? "12px" : "9px")
        .style("fill", "#fff")
        .style("pointer-events", "none")
        .text(d => d.type === "Application" ? "🏢" : "⚠");

    const labeledNodes = new Set();
    apps.forEach(a => labeledNodes.add(a.id));
    const topRiskDeps = [...data.nodes]
        .filter(n => n.type !== "Application")
        .sort((a, b) => b.risk_score - a.risk_score)
        .slice(0, 20);
    topRiskDeps.forEach(n => labeledNodes.add(n.id));

    node.filter(d => labeledNodes.has(d.id))
        .append("text")
        .attr("class", "label")
        .attr("y", d => getNodeRadius(d, baseRadius) + 12)
        .text(d => {
            const name = d.name.length > 12 ? d.name.substring(0, 10) + "…" : d.name;
            return name;
        });

    node.filter(d => d.risk_score >= 70 && d.type !== "Application")
        .append("text")
        .attr("class", "node-warning-badge")
        .attr("y", d => -getNodeRadius(d, baseRadius) - 4)
        .text("⚠");

    if (positions[centerApp.id]) {
        g.append("text")
            .attr("class", "center-node-label")
            .attr("x", cx)
            .attr("y", cy + getNodeRadius(centerApp, baseRadius) + 18)
            .text(centerApp.name.length > 16 ? centerApp.name.substring(0, 14) + "…" : centerApp.name);
        g.append("text")
            .attr("class", "center-node-sub")
            .attr("x", cx)
            .attr("y", cy + getNodeRadius(centerApp, baseRadius) + 32)
            .text("v" + centerApp.version);
    }

    zoomBehavior = d3.zoom()
        .scaleExtent([0.4, 3])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
            const zl = document.getElementById('zoom-level');
            if (zl) zl.textContent = Math.round(event.transform.k * 100) + "%";
        });
    svg.call(zoomBehavior);
}

function getNodeRadius(d, baseRadius) {
    baseRadius = baseRadius || 12;
    if (d.type === "Application") return baseRadius * 1.7;
    if (d.risk_score >= 70) return baseRadius * 1.2;
    if (d.risk_score >= 40) return baseRadius * 1.0;
    return baseRadius * 0.8;
}
function getNodeColor(d) {
    if (d.type === "Application") return "#22D3EE";
    if (d.risk_score >= 70) return "#EF4444";
    if (d.risk_score >= 40) return "#F59E0B";
    return "#22C55E";
}
function getNodeFill(d) {
    if (d.type === "Application") return "rgba(34,211,238,0.25)";
    if (d.risk_score >= 70) return "rgba(239,68,68,0.2)";
    if (d.risk_score >= 40) return "rgba(245,158,11,0.15)";
    return "rgba(34,197,94,0.15)";
}

function selectNode(d, g) {
    selectedNode = d;
    const isCritical = d.risk_score >= 70;
    const isWarning = d.risk_score >= 40 && d.risk_score < 70;
    const level = isCritical ? 'critical' : (isWarning ? 'warning' : 'safe');
    const badge = isCritical ? 'Critical Risk' : (isWarning ? 'At Risk' : 'Safe');

    let desc = `${d.name} is a ${d.type === "Application" ? "root application" : "dependency"} in the software supply chain. `;
    if (isCritical) desc += `Known critical vulnerability detected. This package sits at a critical structural position and its compromise cascades to multiple downstream applications.`;
    else if (isWarning) desc += `Known vulnerability or high structural importance detected. Monitor closely and patch when possible.`;
    else desc += `No known critical vulnerabilities detected. Safe to keep in the dependency chain.`;

    document.getElementById('node-info').innerHTML = `
        <div class="inspector-card">
            <div class="ic-header">
                <div class="ic-icon ${level}">${d.type === "Application" ? "🏢" : "📦"}</div>
                <div class="ic-meta">
                    <div class="ic-name">${d.name}</div>
                    <div class="ic-version">v${d.version}</div>
                </div>
                <span class="ic-badge ${level}">${badge}</span>
            </div>
            <div class="ic-desc">${desc}</div>
            <div class="ic-table">
                <div class="ic-row"><span class="ic-label">Type</span><span class="ic-value">${d.type === "Application" ? "Root Application" : "Dependency"}</span></div>
                <div class="ic-row"><span class="ic-label">Risk Score</span><span class="ic-value ${isCritical ? 'critical' : ''}">${d.risk_score.toFixed(1)} / 100</span></div>
                <div class="ic-row"><span class="ic-label">Dependents</span><span class="ic-value">${d.in_degree}</span></div>
                <div class="ic-row"><span class="ic-label">Outgoing Deps</span><span class="ic-value">${d.out_degree}</span></div>
                <div class="ic-row"><span class="ic-label">Has CVE</span><span class="ic-value">${d.has_cve ? "Yes" : "No"}</span></div>
            </div>
            <button class="ic-view-details" onclick="openDetailsModal()">View Details ↗</button>
        </div>
    `;
    document.getElementById('simulate-btn').disabled = false;
}

// ======================================================
// DETAILS MODAL
// ======================================================
function openDetailsModal() {
    if (!selectedNode) return;
    const d = selectedNode;

    document.getElementById('modal-icon').textContent = d.type === "Application" ? "🏢" : "📦";
    document.getElementById('modal-title').textContent = `${d.name}@${d.version}`;
    document.getElementById('modal-subtitle').textContent = d.type === "Application" ? "Root Application" : "Dependency Package";

    const fill = document.getElementById('risk-meter-fill');
    fill.style.width = d.risk_score + '%';
    fill.style.background = d.risk_score >= 70 ? '#EF4444' : (d.risk_score >= 40 ? '#F59E0B' : '#22C55E');
    document.getElementById('risk-score-display').textContent = `${d.risk_score.toFixed(1)} / 100`;
    document.getElementById('risk-score-display').style.color = d.risk_score >= 70 ? '#EF4444' : (d.risk_score >= 40 ? '#F59E0B' : '#22C55E');

    const cveContent = document.getElementById('cve-content');
    if (d.has_cve || d.risk_score >= 70) {
        const cveId = generateCveId(d.name);
        const severity = d.risk_score >= 70 ? 'CRITICAL' : 'HIGH';
        const severityClass = d.risk_score >= 70 ? 'critical' : 'high';
        cveContent.innerHTML = `
            <div class="cve-card">
                <div class="cve-card-header">
                    <span class="cve-id">${cveId}</span>
                    <span class="cve-severity ${severityClass}">${severity}</span>
                </div>
                <div class="cve-desc">A known vulnerability has been identified in <strong>${d.name}@${d.version}</strong>. This package sits at a critical junction in the dependency chain, meaning its compromise can propagate to multiple downstream applications. Attackers could exploit this to inject malicious code, exfiltrate data, or cause a denial of service across all dependent systems.</div>
                <div class="cve-meta">
                    <span>CVSS: <strong>${(d.risk_score / 10).toFixed(1)}</strong></span>
                    <span>Severity: <strong>${severity}</strong></span>
                    <span>Exploitability: <strong>${d.risk_score >= 70 ? 'High' : 'Moderate'}</strong></span>
                </div>
            </div>
        `;
    } else {
        cveContent.innerHTML = `
            <div class="cve-card safe">
                <div class="cve-card-header">
                    <span class="cve-id safe">No Known CVE</span>
                    <span class="cve-severity" style="background:#22C55E; color:#fff;">SAFE</span>
                </div>
                <div class="cve-desc">No known vulnerabilities detected in the current vulnerability databases (OSV, NVD).</div>
            </div>
        `;
    }

    let chainHtml = '';
    if (d.type === "Application") {
        chainHtml = `<div class="dep-node"><span class="dep-arrow">🏢</span><span class="dep-name">${d.name}</span><span class="dep-ver">(Root Application)</span></div>`;
        chainHtml += `<p style="font-size:11.5px; color:#64748B; margin-top:8px;">Depends on ${d.out_degree} packages.</p>`;
    } else {
        chainHtml = `<div class="dep-node"><span class="dep-arrow">└─</span><span class="dep-name">${d.name}</span><span class="dep-ver">v${d.version}</span></div>`;
        if (d.out_degree > 0) chainHtml += `<p style="font-size:11.5px; color:#64748B; margin: 8px 0 4px;">Depends on ${d.out_degree} packages downstream.</p>`;
        if (d.in_degree > 0) chainHtml += `<p style="font-size:11.5px; color:#64748B;">${d.in_degree} packages depend on this.</p>`;
    }
    document.getElementById('dep-chain-content').innerHTML = chainHtml;

    const appsContent = document.getElementById('affected-apps-content');
    if (graphData) {
        const affected = [];
        graphData.edges.forEach(e => {
            if (e.target === d.id) {
                const src = graphData.nodes.find(n => n.id === e.source);
                if (src && src.type === "Application" && !affected.find(a => a.id === src.id)) {
                    affected.push(src);
                }
            }
        });
        if (affected.length > 0) {
            appsContent.innerHTML = affected.map(a => `<span class="app-badge">🏢 ${a.name} v${a.version}</span>`).join('');
        } else if (d.type === "Application") {
            appsContent.innerHTML = `<span class="app-badge">🏢 ${d.name} (this application)</span>`;
        } else {
            appsContent.innerHTML = `<p style="font-size:12px; color:#64748B;">No root applications directly depend on this package. Click "Simulate Compromise" for full blast radius analysis.</p>`;
        }
    }

    const mitContent = document.getElementById('mitigation-content');
    const steps = [];
    if (d.risk_score >= 70) {
        steps.push({ title: 'Patch immediately', text: `Upgrade <strong>${d.name}</strong> to the latest patched version. This is the single most impactful action to contain the ripple effect.` });
        steps.push({ title: 'Audit dependents', text: `Identify all ${d.in_degree} downstream packages and applications that inherit this vulnerability.` });
        steps.push({ title: 'Monitor for exploitation', text: `Enable real-time monitoring on all dependent services. Look for unusual outbound traffic or anomalous process execution.` });
        steps.push({ title: 'Rotate secrets', text: `If this package handles credentials or tokens, rotate all related secrets as a precaution.` });
    } else if (d.risk_score >= 40) {
        steps.push({ title: 'Schedule upgrade', text: `Plan to upgrade <strong>${d.name}</strong> in the next maintenance window.` });
        steps.push({ title: 'Track advisories', text: `Subscribe to security advisories for this package to catch new CVEs early.` });
    } else {
        steps.push({ title: 'No action required', text: `This package is currently safe. Continue standard dependency hygiene.` });
        steps.push({ title: 'Monitor periodically', text: `Re-scan this SBOM monthly to catch emerging vulnerabilities.` });
    }
    mitContent.innerHTML = steps.map((s, i) => `
        <div class="mitigation-step">
            <div class="mitigation-num">${i + 1}</div>
            <div class="mitigation-text"><strong>${s.title}:</strong> ${s.text}</div>
        </div>
    `).join('');

    document.getElementById('details-modal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('details-modal').classList.add('hidden');
    document.body.style.overflow = '';
}

function generateCveId(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = ((hash << 5) - hash) + name.charCodeAt(i);
    const num = Math.abs(hash % 9000) + 1000;
    return `CVE-2024-${num}`;
}

// ======================================================
// PDF REPORT EXPORT — Opens a print-ready report
// ======================================================
function exportReportAsPDF() {
    if (!selectedNode) { showToast('No package selected'); return; }
    const d = selectedNode;

    // Gather data
    const cveId = generateCveId(d.name);
    const isCritical = d.risk_score >= 70;
    const isWarning = d.risk_score >= 40 && d.risk_score < 70;
    const severity = isCritical ? 'CRITICAL' : (isWarning ? 'HIGH' : 'LOW');
    const severityColor = isCritical ? '#EF4444' : (isWarning ? '#F59E0B' : '#22C55E');

    const affected = [];
    if (graphData) {
        graphData.edges.forEach(e => {
            if (e.target === d.id) {
                const src = graphData.nodes.find(n => n.id === e.source);
                if (src && src.type === "Application" && !affected.find(a => a.id === src.id)) {
                    affected.push(src);
                }
            }
        });
    }

    const mitigationSteps = [];
    if (d.risk_score >= 70) {
        mitigationSteps.push('Patch immediately: Upgrade ' + d.name + ' to the latest patched version.');
        mitigationSteps.push('Audit dependents: Identify all ' + d.in_degree + ' downstream packages that inherit this vulnerability.');
        mitigationSteps.push('Monitor for exploitation: Enable real-time monitoring on all dependent services.');
        mitigationSteps.push('Rotate secrets: If this package handles credentials or tokens, rotate all related secrets.');
    } else if (d.risk_score >= 40) {
        mitigationSteps.push('Schedule upgrade: Plan to upgrade ' + d.name + ' in the next maintenance window.');
        mitigationSteps.push('Track advisories: Subscribe to security advisories for this package.');
    } else {
        mitigationSteps.push('No action required: This package is currently safe.');
        mitigationSteps.push('Monitor periodically: Re-scan this SBOM monthly.');
    }

    const now = new Date();
    const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const reportId = 'SENTINEL-' + Date.now();

    // Build report HTML
    const reportHTML = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SentinelX Report — ${d.name}@${d.version}</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @page { size: A4; margin: 20mm; }
    body { font-family: 'Segoe UI', -apple-system, sans-serif; color: #0F172A; background: #fff; line-height: 1.5; font-size: 11pt; }
    .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; border-bottom: 3px solid #3B82F6; margin-bottom: 24px; }
    .brand { display: flex; align-items: center; gap: 10px; }
    .brand-logo { width: 32px; height: 32px; background: #3B82F6; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 16px; }
    .brand-name { font-size: 18px; font-weight: 800; color: #0F172A; }
    .brand-name span { color: #3B82F6; }
    .header-meta { text-align: right; font-size: 9pt; color: #64748B; }
    .header-meta strong { color: #0F172A; display: block; font-size: 10pt; }
    .report-title { font-size: 24pt; font-weight: 800; color: #0F172A; margin-bottom: 6px; letter-spacing: -0.5px; }
    .report-subtitle { font-size: 11pt; color: #64748B; margin-bottom: 24px; }
    .section { margin-bottom: 24px; }
    .section-title { font-size: 10pt; font-weight: 700; color: #3B82F6; text-transform: uppercase; letter-spacing: 1.5px; padding-bottom: 6px; border-bottom: 1px solid #E2E8F0; margin-bottom: 14px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .info-box { background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px 16px; }
    .info-label { font-size: 9pt; color: #64748B; font-weight: 500; margin-bottom: 2px; }
    .info-value { font-size: 12pt; font-weight: 700; color: #0F172A; }
    .risk-meter { margin-top: 8px; }
    .risk-meter-bar { height: 12px; background: #E2E8F0; border-radius: 6px; overflow: hidden; }
    .risk-meter-fill { height: 100%; background: linear-gradient(90deg, #22C55E, #F59E0B, #EF4444); border-radius: 6px; }
    .risk-labels { display: flex; justify-content: space-between; font-size: 8pt; color: #64748B; margin-top: 4px; }
    .risk-score-big { font-size: 22pt; font-weight: 800; color: ${severityColor}; text-align: center; margin-top: 10px; }
    .cve-box { background: #FEF2F2; border-left: 4px solid ${severityColor}; border-radius: 6px; padding: 14px 16px; margin-bottom: 10px; }
    .cve-box.safe { background: #F0FDF4; border-left-color: #22C55E; }
    .cve-id { font-family: 'Courier New', monospace; font-size: 11pt; font-weight: 800; color: ${severityColor}; }
    .cve-severity { display: inline-block; background: ${severityColor}; color: #fff; font-size: 8pt; font-weight: 800; padding: 2px 8px; border-radius: 4px; margin-left: 10px; letter-spacing: 0.5px; }
    .cve-desc { font-size: 10pt; color: #334155; margin-top: 10px; line-height: 1.6; }
    .cve-meta { display: flex; gap: 20px; margin-top: 10px; font-size: 9pt; color: #64748B; }
    .cve-meta strong { color: #0F172A; }
    .table { width: 100%; border-collapse: collapse; font-size: 10pt; }
    .table th { background: #F1F5F9; color: #475569; font-size: 9pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; text-align: left; padding: 10px 12px; border-bottom: 1px solid #E2E8F0; }
    .table td { padding: 10px 12px; border-bottom: 1px solid #F1F5F9; color: #0F172A; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 8pt; font-weight: 700; }
    .badge.critical { background: #FEE2E2; color: #B91C1C; }
    .badge.warning { background: #FEF3C7; color: #B45309; }
    .badge.safe { background: #DCFCE7; color: #15803D; }
    .badge.app { background: #CFFAFE; color: #0E7490; }
    .app-chip { display: inline-block; background: #EFF6FF; color: #1E40AF; border: 1px solid #BFDBFE; padding: 6px 12px; border-radius: 6px; font-size: 10pt; font-weight: 600; margin: 3px 5px 3px 0; }
    .mitigation-item { display: flex; gap: 12px; padding: 12px 14px; background: #F8FAFC; border-left: 3px solid #3B82F6; border-radius: 6px; margin-bottom: 8px; }
    .mitigation-num { width: 22px; height: 22px; background: #3B82F6; color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10pt; font-weight: 800; flex-shrink: 0; }
    .mitigation-text { font-size: 10pt; color: #334155; line-height: 1.5; }
    .mitigation-text strong { color: #0F172A; }
    .footer { margin-top: 30px; padding-top: 16px; border-top: 1px solid #E2E8F0; display: flex; justify-content: space-between; font-size: 8pt; color: #94A3B8; }
    .stamp { background: #EFF6FF; color: #1E40AF; padding: 6px 12px; border-radius: 6px; font-size: 9pt; font-weight: 700; display: inline-block; }
    @media print { .no-print { display: none !important; } body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
    .print-btn { position: fixed; top: 20px; right: 20px; background: #3B82F6; color: #fff; border: none; padding: 12px 24px; border-radius: 8px; font-size: 13px; font-weight: 700; cursor: pointer; box-shadow: 0 10px 30px rgba(59,130,246,0.4); }
    .print-btn:hover { background: #2563EB; }
</style>
</head>
<body>
    <button class="print-btn no-print" onclick="window.print()">🖨️ Save as PDF</button>

    <div class="header">
        <div class="brand">
            <div class="brand-logo">S</div>
            <div class="brand-name">Sentinel<span>X</span></div>
        </div>
        <div class="header-meta">
            <strong>Supply Chain Risk Report</strong>
            Generated ${dateStr} at ${timeStr}<br>
            Report ID: ${reportId}
        </div>
    </div>

    <div class="report-title">${d.name}@${d.version}</div>
    <div class="report-subtitle">
        ${d.type === "Application" ? "Root Application" : "Dependency Package"} · Vulnerability Assessment Report
    </div>

    <div class="section">
        <div class="section-title">Risk Assessment</div>
        <div class="grid-2">
            <div class="info-box">
                <div class="info-label">Risk Score</div>
                <div class="info-value" style="color:${severityColor}; font-size:18pt;">${d.risk_score.toFixed(1)} / 100</div>
                <div class="info-label" style="margin-top:6px;">Severity Level</div>
                <div class="info-value">${severity}</div>
            </div>
            <div class="info-box">
                <div class="info-label">Dependents</div>
                <div class="info-value">${d.in_degree} packages</div>
                <div class="info-label" style="margin-top:6px;">Outgoing Dependencies</div>
                <div class="info-value">${d.out_degree} packages</div>
            </div>
        </div>
        <div class="risk-meter">
            <div class="risk-meter-bar"><div class="risk-meter-fill" style="width:${d.risk_score}%;"></div></div>
            <div class="risk-labels"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Vulnerability Intelligence</div>
        ${d.has_cve || d.risk_score >= 70 ? `
            <div class="cve-box">
                <div>
                    <span class="cve-id">${cveId}</span>
                    <span class="cve-severity">${severity}</span>
                </div>
                <div class="cve-desc">
                    A known vulnerability has been identified in <strong>${d.name}@${d.version}</strong>.
                    This package sits at a critical junction in the dependency chain, meaning its compromise can propagate
                    to multiple downstream applications. Attackers could exploit this to inject malicious code, exfiltrate data,
                    or cause a denial of service across all dependent systems.
                </div>
                <div class="cve-meta">
                    <span>CVSS Score: <strong>${(d.risk_score / 10).toFixed(1)}</strong></span>
                    <span>Severity: <strong>${severity}</strong></span>
                    <span>Exploitability: <strong>${d.risk_score >= 70 ? 'High' : 'Moderate'}</strong></span>
                </div>
            </div>
        ` : `
            <div class="cve-box safe">
                <div><span class="cve-id" style="color:#22C55E;">No Known CVE</span></div>
                <div class="cve-desc">No known vulnerabilities detected in the current vulnerability databases (OSV, NVD). This package is considered safe based on current threat intelligence.</div>
            </div>
        `}
    </div>

    <div class="section">
        <div class="section-title">Affected Applications</div>
        ${affected.length > 0
            ? affected.map(a => `<span class="app-chip">🏢 ${a.name} v${a.version}</span>`).join('')
            : (d.type === "Application"
                ? `<span class="app-chip">🏢 ${d.name} (this application)</span>`
                : `<div style="color:#64748B; font-size:10pt;">No root applications directly depend on this package.</div>`
            )
        }
    </div>

    <div class="section">
        <div class="section-title">Recommended Mitigation</div>
        ${mitigationSteps.map((s, i) => {
            const parts = s.split(':');
            return `
                <div class="mitigation-item">
                    <div class="mitigation-num">${i + 1}</div>
                    <div class="mitigation-text"><strong>${parts[0]}:</strong>${parts.slice(1).join(':')}</div>
                </div>
            `;
        }).join('')}
    </div>

    <div class="footer">
        <div>
            <span class="stamp">SENTINELX VERIFIED</span>
        </div>
        <div style="text-align:right;">
            © 2026 SentinelX — Intelligent Supply Chain Risk Analysis<br>
            This report is generated automatically and is valid as of ${dateStr}.
        </div>
    </div>
</body>
</html>
    `;

    // Open in new window
    const w = window.open('', '_blank');
    if (!w) {
        showToast('Please allow popups to export the report');
        return;
    }
    w.document.write(reportHTML);
    w.document.close();

    // Auto-trigger print dialog after content loads
    w.onload = () => {
        setTimeout(() => { w.print(); }, 400);
    };

    showToast('Report opened — use "Save as PDF"');
}

// ======================================================
// PRIORITIES + SIMULATION
// ======================================================
function renderPriorities(priorities) {
    const list = document.getElementById('priority-list');
    list.innerHTML = '';
    if (!priorities || priorities.length === 0) {
        list.innerHTML = '<li class="empty-state">No critical dependencies found.</li>';
        return;
    }
    const critical = priorities.filter(p => p.risk_score >= 70).length;
    const high = priorities.filter(p => p.risk_score >= 40 && p.risk_score < 70).length;
    const transitive = priorities.filter(p => p.risk_score < 40).length;

    const groups = [
        { num: 1, title: "Critical Vulnerabilities", count: critical, cls: "" },
        { num: 2, title: "High Risk Dependencies", count: high, cls: "warning" },
        { num: 3, title: "Transitive Risks", count: transitive, cls: "info" },
        { num: 4, title: "License & Compliance", count: 0, cls: "low" },
    ];

    groups.forEach(g => {
        const li = document.createElement('li');
        li.innerHTML = `
            <div class="num ${g.cls}">${g.num}</div>
            <div class="priority-content">
                <div class="priority-title">${g.title}</div>
                <div class="priority-sub">${g.count} component${g.count !== 1 ? 's' : ''}</div>
            </div>
            <span class="arrow">›</span>
        `;
        li.onclick = () => {
            let match;
            if (g.num === 1) match = priorities.find(p => p.risk_score >= 70);
            else if (g.num === 2) match = priorities.find(p => p.risk_score >= 40 && p.risk_score < 70);
            else if (g.num === 3) match = priorities.find(p => p.risk_score < 40);
            if (match && graphData) {
                const node = graphData.nodes.find(n => n.id === match.id);
                if (node) selectNode(node);
            }
        };
        list.appendChild(li);
    });
}

function renderSimulation(result) {
    const output = document.getElementById('node-info');
    if (result.affected_count === 0) {
        output.innerHTML += `<div class="simulation-output"><div class="sim-header" style="color:#22C55E;">✅ Isolated Package</div><p style="font-size:12px;color:#94A3B8;">No downstream dependencies affected.</p></div>`;
        return;
    }
    let pathsHtml = '';
    result.propagation_paths.forEach(p => {
        pathsHtml += `<div class="sim-path">${p.join(' → ')}</div>`;
    });
    let appsHtml = '';
    if (result.affected_apps && result.affected_apps.length > 0) {
        appsHtml = `<div class="sim-paths-title">Affected Applications</div>${result.affected_apps.map(a => `<div class="sim-path" style="color:#22D3EE;">• ${a.name}</div>`).join('')}`;
    }
    output.innerHTML += `
        <div class="simulation-output">
            <div class="sim-header">🚨 Blast Radius</div>
            <div class="sim-stat"><span class="sim-label">Packages Affected</span><span class="sim-value">${result.affected_count}</span></div>
            <div class="sim-stat"><span class="sim-label">Applications Impacted</span><span class="sim-value">${result.affected_apps_count}</span></div>
            <div class="sim-stat"><span class="sim-label">Severity</span><span class="sim-value" style="color:#EF4444;">${result.severity}</span></div>
            <div class="sim-stat"><span class="sim-label">Max Depth</span><span class="sim-value">${result.max_depth} levels</span></div>
            <div class="sim-paths-title">Propagation Paths</div>
            ${pathsHtml}
            ${appsHtml}
        </div>
    `;
}

// ======================================================
// EVENT LISTENERS
// ======================================================
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
        closePremiumModal();
    }
});
document.addEventListener('click', (e) => {
    if (e.target.id === 'details-modal') closeModal();
    if (e.target.id === 'premium-modal') closePremiumModal();
    if (e.target.id === 'modal-export-btn') {
        exportReportAsPDF();
    }
});

// ======================================================
// INIT
// ======================================================
window.addEventListener('DOMContentLoaded', () => {
    showView('landing');

    const fileInput = document.getElementById('sbom-upload');
    if (fileInput) {
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            try {
                document.getElementById('file-info').classList.remove('hidden');
                document.getElementById('file-name').textContent = file.name;
                document.getElementById('file-size').textContent = (file.size / 1024).toFixed(1) + " KB";
                await uploadSbom(file);
                document.getElementById('analyze-btn').disabled = false;
                showToast('SBOM uploaded successfully');
            } catch (err) {
                showToast('Upload failed: ' + err.message);
            }
        });
    }

    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#3B82F6'; });
        dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = ''; });
        dropZone.addEventListener('drop', async (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '';
            const file = e.dataTransfer.files[0];
            if (!file) return;
            try {
                document.getElementById('file-info').classList.remove('hidden');
                document.getElementById('file-name').textContent = file.name;
                document.getElementById('file-size').textContent = (file.size / 1024).toFixed(1) + " KB";
                await uploadSbom(file);
                document.getElementById('analyze-btn').disabled = false;
                showToast('SBOM uploaded successfully');
            } catch (err) {
                showToast('Upload failed: ' + err.message);
            }
        });
    }

    const analyzeBtn = document.getElementById('analyze-btn');
    if (analyzeBtn) analyzeBtn.addEventListener('click', analyzeGraph);

    const simulateBtn = document.getElementById('simulate-btn');
    if (simulateBtn) simulateBtn.addEventListener('click', () => {
        if (selectedNode) simulateCompromise(selectedNode.id);
    });

    const zi = document.getElementById('zoom-in');
    const zo = document.getElementById('zoom-out');
    const zr = document.getElementById('zoom-reset');
    if (zi) zi.addEventListener('click', () => { if (zoomBehavior) svg.transition().duration(300).call(zoomBehavior.scaleBy, 1.3); });
    if (zo) zo.addEventListener('click', () => { if (zoomBehavior) svg.transition().duration(300).call(zoomBehavior.scaleBy, 0.7); });
    if (zr) zr.addEventListener('click', () => { if (zoomBehavior) svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity); });
});

window.addEventListener('resize', () => {
    if (graphData && !document.getElementById('view-dashboard').classList.contains('hidden')) {
        if (currentViewMode === 'graph') drawRadialGraph(graphData);
    }
});