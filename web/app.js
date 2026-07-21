// ==============================================================================
// GLOBAL STATE & CONSTANTS
// ==============================================================================
let currentGraph = null;
let selectedNode = null;
let simulation = null;
let svg = null;
let gLink = null;
let gNode = null;
let zoomBehavior = null;
let width = 0;
let height = 0;

// ==============================================================================
// DOM EVENT LISTENERS & SETUP
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
    setupSettingsModal();
    setupDragAndDrop();
    setupSearchForm();
    setupCanvasControls();
    
    // Close Details Panel listener
    document.getElementById('btn-close-details').addEventListener('click', () => {
        document.getElementById('details-panel').classList.add('hidden');
        if (selectedNode) {
            d3.selectAll('.node').classed('selected', false);
            selectedNode = null;
        }
    });
});

// ==============================================================================
// SECTION 1: DRAG & DROP MANIFEST LOADER
// ==============================================================================
function setupDragAndDrop() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('manifest-file');

    // Dragover event styling
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleUploadedFile(e.dataTransfer.files[0]);
        }
    });

    // Handle standard file clicks
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleUploadedFile(e.target.files[0]);
        }
    });
}

function handleUploadedFile(file) {
    showLoading(true);
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const rawContent = e.target.result;
        
        // POST raw content to upload API endpoint, sending original filename in headers
        fetch('/api/upload', {
            method: 'POST',
            headers: {
                'X-File-Name': file.name,
                'Content-Type': 'text/plain',
                ...getAuthHeaders()
            },
            body: rawContent
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error || 'Server error'); });
            }
            return response.json();
        })
        .then(graphData => {
            showLoading(false);
            processAndRenderGraph(graphData);
        })
        .catch(err => {
            showLoading(false);
            alert(`Error: ${err.message}`);
        });
    };
    reader.onerror = function() {
        showLoading(false);
        alert("Failed to read file.");
    };
    reader.readAsText(file);
}

// ==============================================================================
// SECTION 2: SINGLE LIBRARY AUDIT FORM
// ==============================================================================
function setupSearchForm() {
    const form = document.getElementById('search-form');
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const name = document.getElementById('package-name').value.trim();
        const ecosystem = document.getElementById('package-ecosystem').value;
        const version = document.getElementById('package-version').value.trim();
        
        if (!name) return;
        
        showLoading(true);
        
        let url = `/api/search?name=${encodeURIComponent(name)}&ecosystem=${encodeURIComponent(ecosystem)}`;
        if (version) {
            url += `&version=${encodeURIComponent(version)}`;
        }
        
        fetch(url, {
            headers: getAuthHeaders()
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Server error'); });
                }
                return response.json();
            })
            .then(graphData => {
                showLoading(false);
                processAndRenderGraph(graphData);
            })
            .catch(err => {
                showLoading(false);
                alert(`Error: ${err.message}`);
            });
    });
}

// ==============================================================================
// SECTION 3: METRICS DASHBOARD
// ==============================================================================
function updateMetrics(nodes) {
    let total = nodes.length;
    let vulns = 0;
    let recent = 0;
    let failures = 0;
    let highestRisk = 'LOW';
    
    nodes.forEach(n => {
        if (n.vulnerabilities) vulns += n.vulnerabilities.length;
        if (n.is_recent) recent++;
        if (n.file_verification && !n.file_verification.verified) failures++;
        
        // Classify highest overall risk found in graph
        if (n.risk === 'critical') highestRisk = 'CRITICAL';
        else if (n.risk === 'high' && highestRisk !== 'CRITICAL') highestRisk = 'HIGH';
        else if (n.risk === 'medium' && highestRisk !== 'CRITICAL' && highestRisk !== 'HIGH') highestRisk = 'MEDIUM';
    });
    
    document.getElementById('metric-total').textContent = total;
    document.getElementById('metric-vulns').textContent = vulns;
    document.getElementById('metric-recent').textContent = recent;
    document.getElementById('metric-failures').textContent = failures;
    
    // Set risk badge
    const badge = document.getElementById('risk-score-badge');
    badge.className = `risk-badge ${highestRisk}`;
    badge.textContent = highestRisk;
    
    // Show dashboard section
    document.getElementById('metrics-panel').classList.remove('hidden');
}

// ==============================================================================
// SECTION 4: D3 FORCE-DIRECTED GRAPH VISUALIZER
// ==============================================================================
function processAndRenderGraph(graphData) {
    currentGraph = graphData;
    
    // Reset selected state
    selectedNode = null;
    document.getElementById('details-panel').classList.add('hidden');
    
    // Show summary metrics
    updateMetrics(graphData.nodes);
    
    // Draw visualizer
    renderGraph(graphData);
}

function renderGraph(graphData) {
    const container = document.getElementById('graph-container');
    container.innerHTML = ''; // Clear placeholder or old canvas
    
    width = container.clientWidth;
    height = container.clientHeight;
    
    const svgEl = d3.create("svg")
        .attr("class", "graph-svg")
        .attr("viewBox", [0, 0, width, height]);
        
    svg = svgEl;
    
    const mainGroup = svgEl.append("g");
    
    // Enable D3 zoom behavior
    zoomBehavior = d3.zoom()
        .scaleExtent([0.15, 6])
        .on("zoom", (event) => {
            mainGroup.attr("transform", event.transform);
        });
        
    svgEl.call(zoomBehavior);
    
    // Transform arrays into object structures for simulation references
    const links = graphData.links.map(d => Object.create(d));
    const nodes = graphData.nodes.map(d => Object.create(d));
    
    // Instantiate force simulation physics
    simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-200))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(30));
        
    // Draw links (edges)
    gLink = mainGroup.append("g")
        .attr("class", "links-group")
        .selectAll("line")
        .data(links)
        .join("line")
        .attr("class", "link");
        
    // Draw nodes
    gNode = mainGroup.append("g")
        .attr("class", "nodes-group")
        .selectAll("g")
        .data(nodes)
        .join("g")
        .attr("class", d => `node risk-${d.risk}`)
        .call(drag(simulation));
        
    // Glowing circles representation
    gNode.append("circle")
        .attr("r", 12);
        
    // Labels containing package names
    gNode.append("text")
        .attr("class", "node-label")
        .attr("x", 16)
        .attr("y", 4)
        .text(d => d.name);
        
    // Tick calculation on active frames
    simulation.on("tick", () => {
        gLink
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
            
        gNode
            .attr("transform", d => `translate(${d.x},${d.y})`);
    });
    
    // ==========================================================================
    // SELECTION & INTERACTION HANDLERS
    // ==========================================================================
    gNode.on("click", (event, d) => {
        event.stopPropagation();
        
        // Selection highlight
        d3.selectAll('.node').classed('selected', false);
        d3.select(event.currentTarget).classed('selected', true);
        selectedNode = d;
        
        showDetails(d);
    });
    
    gNode.on("mouseover", (event, d) => {
        highlightNodeChain(d);
    });
    
    gNode.on("mouseout", () => {
        resetHighlights();
    });
    
    // Clear selection when clicking canvas base
    svgEl.on("click", () => {
        d3.selectAll('.node').classed('selected', false);
        document.getElementById('details-panel').classList.add('hidden');
        selectedNode = null;
    });
    
    container.appendChild(svgEl.node());
}

// Hover Highlighting for ancestors and descendants
function highlightNodeChain(targetNode) {
    const connectedNodeIds = new Set([targetNode.id]);
    
    gLink.classed("highlighted", d => {
        const isConnected = d.source.id === targetNode.id || d.target.id === targetNode.id;
        if (isConnected) {
            connectedNodeIds.add(d.source.id);
            connectedNodeIds.add(d.target.id);
        }
        return isConnected;
    });
    
    gNode.classed("dimmed", d => !connectedNodeIds.has(d.id));
    gLink.classed("dimmed", d => !(d.source.id === targetNode.id || d.target.id === targetNode.id));
}

function resetHighlights() {
    gNode.classed("dimmed", false);
    gLink.classed("dimmed", false);
    gLink.classed("highlighted", false);
}

// Node dragging logic (D3 standard implementation)
function drag(sim) {
    function dragstarted(event) {
        if (!event.active) sim.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
    }
    
    function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
    }
    
    function dragended(event) {
        if (!event.active) sim.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
    }
    
    return d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended);
}

// ==============================================================================
// SECTION 5: CANVAS ZOOM NAVIGATION CONTROLS
// ==============================================================================
function setupCanvasControls() {
    document.getElementById('btn-zoom-in').addEventListener('click', () => {
        if (svg && zoomBehavior) svg.transition().duration(200).call(zoomBehavior.scaleBy, 1.3);
    });

    document.getElementById('btn-zoom-out').addEventListener('click', () => {
        if (svg && zoomBehavior) svg.transition().duration(200).call(zoomBehavior.scaleBy, 0.7);
    });

    document.getElementById('btn-zoom-reset').addEventListener('click', () => {
        if (svg && zoomBehavior && width && height) {
            svg.transition().duration(250).call(
                zoomBehavior.transform,
                d3.zoomIdentity.translate(0, 0).scale(1)
            );
        }
    });
}

// ==============================================================================
// SECTION 6: DETAIL SIDEBAR PRESENTATION
// ==============================================================================
function showDetails(node) {
    const content = document.getElementById('details-content');
    const panel = document.getElementById('details-panel');
    
    content.innerHTML = ''; // Clear previous fields
    
    // Map risk levels to badge classes
    let badgeClass = 'badge-gray';
    if (node.risk === 'low') badgeClass = 'badge-success';
    else if (node.risk === 'medium') badgeClass = 'badge-warning';
    else if (node.risk === 'high') badgeClass = 'badge-danger';
    else if (node.risk === 'critical') badgeClass = 'badge-danger text-bold blink';
    
    let riskText = node.risk.toUpperCase();
    if (node.risk === 'critical') riskText = 'CRITICAL (Integrity Failure)';
    
    let detailsHtml = `
        <div class="detail-section">
            <div class="detail-row">
                <strong>Library Name</strong>
                <span class="text-bold">${node.name}</span>
            </div>
            <div class="detail-row">
                <strong>Ecosystem</strong>
                <span class="badge badge-info">${node.ecosystem}</span>
            </div>
            <div class="detail-row">
                <strong>Requested Version</strong>
                <code>${node.requested_version}</code>
            </div>
            <div class="detail-row">
                <strong>Resolved Version</strong>
                <code>${node.resolved_version}</code>
            </div>
            <div class="detail-row">
                <strong>Latest Version</strong>
                <code>${node.latest_version}</code>
            </div>
            <div class="detail-row">
                <strong>Release Age</strong>
                <span>${node.age_days !== null ? `${node.age_days} days ago` : 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <strong>Installed Status</strong>
                <span>${node.installed_version ? `Version: ${node.installed_version}` : '*Not Installed*'}</span>
            </div>
            <div class="detail-row">
                <strong>Risk Category</strong>
                <span class="badge ${badgeClass}">${riskText}</span>
            </div>
        </div>
    `;
    
    // Checksum verification detail box
    if (node.file_verification) {
        const verified = node.file_verification.verified;
        const reason = node.file_verification.reason;
        
        if (!verified) {
            detailsHtml += `
                <div class="checksum-fail-card blink">
                    <h4>⚠️ Checksum Verification Mismatch</h4>
                    <p>${reason}</p>
                </div>
            `;
        } else {
            detailsHtml += `
                <div class="detail-section">
                    <div class="detail-row">
                        <strong>Integrity Hash</strong>
                        <span class="badge badge-success">✓ Verified Matching</span>
                    </div>
                </div>
            `;
        }
    }
    // Vulnerability Details Listing
    if (node.vulnerabilities && node.vulnerabilities.length > 0) {
        detailsHtml += `
            <div class="detail-section">
                <h3>Vulnerability Advisories (${node.vulnerabilities.length})</h3>
                <div class="vulns-container">
        `;
        
        node.vulnerabilities.forEach(v => {
            const aliasStr = v.aliases && v.aliases.length > 0 ? ` / ${v.aliases.join(', ')}` : '';
            const descText = v.details ? v.details.replace(/\n/g, '<br>') : 'No extra advisory text provided.';
            
            detailsHtml += `
                <div class="vuln-item">
                    <div class="vuln-item-header">
                        <span class="vuln-item-id">${v.id}${aliasStr}</span>
                    </div>
                    <div class="vuln-item-title">${v.summary}</div>
                    <div class="vuln-item-desc">${descText}</div>
                    
                    <button class="btn btn-primary btn-ai-explain" 
                            style="padding: 0.25rem 0.5rem; font-size: 0.7rem; margin-top: 0.5rem; display: flex; align-items: center; gap: 0.25rem;" 
                            data-vuln-id="${v.id}" 
                            data-summary="${encodeURIComponent(v.summary)}" 
                            data-details="${encodeURIComponent(v.details || '')}">
                        ✨ Explain with Gemini AI
                    </button>
                    <div id="ai-explain-${v.id}" class="hidden" style="margin-top: 0.75rem; border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 0.5rem; font-size: 0.75rem; color: #cbd5e1; line-height: 1.4;">
                        <div class="spinner" style="width: 14px; height: 14px; border-width: 2px; margin-bottom: 0.25rem;"></div>
                        Loading AI summary...
                    </div>
                </div>
            `;
        });
        
        detailsHtml += `
                </div>
            </div>
        `;
    } else {
        detailsHtml += `
            <div class="detail-section">
                <div class="detail-row">
                    <strong>Vulnerabilities</strong>
                    <span class="badge badge-success">No Vulnerabilities Found</span>
                </div>
            </div>
        `;
    }
    
    if (node.error) {
        detailsHtml += `
            <div class="checksum-fail-card">
                <h4>🛑 Error Resolution</h4>
                <p>${node.error}</p>
            </div>
        `;
    }
    
    content.innerHTML = detailsHtml;
    panel.classList.remove('hidden');

    // Bind AI Explain buttons click handler
    const aiButtons = content.querySelectorAll('.btn-ai-explain');
    aiButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = btn.getAttribute('data-vuln-id');
            const summary = decodeURIComponent(btn.getAttribute('data-summary'));
            const details = decodeURIComponent(btn.getAttribute('data-details'));
            
            const explanationArea = document.getElementById(`ai-explain-${id}`);
            explanationArea.classList.remove('hidden');
            explanationArea.innerHTML = `
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div class="spinner" style="width: 12px; height: 12px; border-width: 2px;"></div>
                    <span>Gemini is generating analysis...</span>
                </div>
            `;
            
            btn.disabled = true;
            
            fetch('/api/explain-vulnerability', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ vuln_id: id, summary: summary, details: details })
            })
            .then(res => {
                if (!res.ok) {
                    return res.json().then(err => { throw new Error(err.error || 'Server error'); });
                }
                return res.json();
            })
            .then(data => {
                // Convert markdown symbols to HTML elements
                let formattedExp = data.explanation
                    .replace(/\n/g, '<br>')
                    .replace(/\*\*(.*?)\*\//g, '<strong>$1</strong>')
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/\*(.*?)\*/g, '<em>$1</em>')
                    .replace(/`(.*?)`/g, '<code>$1</code>');
                explanationArea.innerHTML = `
                    <strong style="color: var(--accent-cyan); display: block; margin-bottom: 0.25rem;">✨ Gemini Security Analysis:</strong>
                    <div>${formattedExp}</div>
                `;
            })
            .catch(err => {
                explanationArea.innerHTML = `<span class="text-danger">Error: ${err.message}</span>`;
                btn.disabled = false;
            });
        });
    });
}

// ==============================================================================
// CONFIGURATION & API KEY SETUP
// ==============================================================================
function getAuthHeaders() {
    const headers = {};
    const nvdKey = localStorage.getItem('depshield_nvd_key');
    const geminiKey = localStorage.getItem('depshield_gemini_key');
    if (nvdKey) headers['X-NVD-API-Key'] = nvdKey;
    if (geminiKey) headers['X-Gemini-API-Key'] = geminiKey;
    return headers;
}

function setupSettingsModal() {
    const modal = document.getElementById('settings-modal');
    const btnOpen = document.getElementById('btn-settings');
    const btnClose = document.getElementById('btn-close-settings');
    const btnSave = document.getElementById('btn-save-settings');
    
    const inputNvd = document.getElementById('settings-nvd-key');
    const inputGemini = document.getElementById('settings-gemini-key');
    
    // Load saved values
    inputNvd.value = localStorage.getItem('depshield_nvd_key') || '';
    inputGemini.value = localStorage.getItem('depshield_gemini_key') || '';
    
    btnOpen.addEventListener('click', (e) => {
        e.stopPropagation();
        modal.classList.remove('hidden');
    });
    
    btnClose.addEventListener('click', () => {
        modal.classList.add('hidden');
    });
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });
    
    btnSave.addEventListener('click', () => {
        localStorage.setItem('depshield_nvd_key', inputNvd.value.trim());
        localStorage.setItem('depshield_gemini_key', inputGemini.value.trim());
        modal.classList.add('hidden');
        alert('API keys saved successfully!');
    });
}

// ==============================================================================
// UTILITIES
// ==============================================================================
function showLoading(visible) {
    const overlay = document.getElementById('loading-overlay');
    if (visible) {
        overlay.classList.remove('hidden');
    } else {
        overlay.classList.add('hidden');
    }
}
