/**
 * CTI Extraction Dashboard Logic
 */

const API_BASE_EXTRACTED = "http://localhost:8000/api/extracted";
const API_BASE_ENRICHED = "http://localhost:8000/api/enriched";
let viewMode = 'extracted'; // 'extracted' or 'enriched'

let currentSource = null;
let currentPage = 1;
const PAGE_SIZE = 50;
let sources = [];

// Elements
const sourceList = document.getElementById('source-list');
const tableBody = document.getElementById('table-body');
const totalCountEl = document.getElementById('total-count');
const iocCountStat = document.getElementById('ioc-count-stat');
const cveCountStat = document.getElementById('cve-count-stat');
const lastUpdateStat = document.getElementById('last-update-stat');
const currentSourceName = document.getElementById('current-source-name');
const currentSourceInfo = document.getElementById('current-source-info');
const fileSizeEl = document.getElementById('file-size');
const pageInfo = document.getElementById('page-info');
const prevBtn = document.getElementById('prev-page');
const nextBtn = document.getElementById('next-page');
const searchInput = document.getElementById('global-search');
const refreshBtn = document.getElementById('refresh-btn');
const modalOverlay = document.getElementById('modal-overlay');
const jsonViewer = document.getElementById('raw-json-viewer');
const closeModal = document.getElementById('close-modal');

// Init
async function init() {
    await loadSources();
    setupEventListeners();
    
    // Auto-select first source if available
    if (sources.length > 0) {
        selectSource(sources[0].id);
    }
}

// View Mode Toggle
window.setMode = async (mode) => {
    if (viewMode === mode) return;
    
    viewMode = mode;
    
    // Update UI
    document.getElementById('mode-extracted').classList.toggle('active', mode === 'extracted');
    document.getElementById('mode-enriched').classList.toggle('active', mode === 'enriched');
    
    currentSource = null;
    currentPage = 1;
    
    await loadSources();
    
    if (sources.length > 0) {
        selectSource(sources[0].id);
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 40px; color: var(--text-secondary);">No sources found for this mode</td></tr>';
        currentSourceName.textContent = mode === 'extracted' ? "Extraction Overview" : "Enrichment Overview";
        currentSourceInfo.textContent = "Select a source to view data";
    }
};

// Load Sources
async function loadSources() {
    const api = viewMode === 'extracted' ? API_BASE_EXTRACTED : API_BASE_ENRICHED;
    try {
        const response = await fetch(`${api}/sources`);
        sources = await response.json();
        renderSourceList();
    } catch (err) {
        console.error("Failed to load sources:", err);
        sourceList.innerHTML = '<p class="error">API Offline</p>';
    }
}

function renderSourceList() {
    sourceList.innerHTML = sources.map(src => `
        <div class="source-item ${currentSource === src.id ? 'active' : ''}" onclick="selectSource('${src.id}')">
            <span class="src-name">${src.name}</span>
            <span class="badge">${formatSize(src.size)}</span>
        </div>
    `).join('');
}

// Select Source
async function selectSource(sourceId) {
    currentSource = sourceId;
    currentPage = 1;
    renderSourceList();
    await loadData();
    
    const srcObj = sources.find(s => s.id === sourceId);
    if (srcObj) {
        currentSourceName.textContent = srcObj.name;
        currentSourceInfo.textContent = `${viewMode === 'extracted' ? 'Extraction' : 'Enrichment'} results from ${srcObj.file}`;
        fileSizeEl.textContent = formatSize(srcObj.size);
        lastUpdateStat.textContent = new Date(srcObj.last_modified * 1000).toLocaleString();
    }
}

// Load Data
async function loadData() {
    if (!currentSource) return;
    
    const loader = document.getElementById('global-energy-loader');
    const statsGrid = document.querySelector('.stats-grid');
    if (loader) loader.classList.add('active');
    if (statsGrid) statsGrid.classList.add('loading');
    
    tableBody.innerHTML = Array(10).fill(0).map(() => `
        <tr class="animate-shimmer relative overflow-hidden">
            <td class="px-5 py-4"><div class="h-4 w-16 bg-slate-800/50 rounded"></div></td>
            <td><div class="h-6 w-12 bg-slate-800/50 rounded-full"></div></td>
            <td>
                <div class="flex flex-col gap-2">
                    <div class="h-4 w-48 bg-slate-800/50 rounded"></div>
                    <div class="h-3 w-24 bg-slate-800/30 rounded"></div>
                </div>
            </td>
            <td><div class="h-4 w-24 bg-slate-800/50 rounded"></div></td>
            <td><div class="h-4 w-16 bg-slate-800/50 rounded"></div></td>
            <td><div class="h-7 w-20 bg-slate-800/50 rounded"></div></td>
        </tr>
    `).join('');
    
    const api = viewMode === 'extracted' ? API_BASE_EXTRACTED : API_BASE_ENRICHED;
    const query = new URLSearchParams({
        page: currentPage,
        limit: PAGE_SIZE,
        search: searchInput.value || ""
    });

    try {
        const response = await fetch(`${api}/data/${currentSource}?${query}`);
        const result = await response.json();
        
        renderTable(result.data);
        updateDashboardStats(result);
    } catch (err) {
        console.error("Error loading data:", err);
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--danger-color);">Error loading data</td></tr>';
    } finally {
        if (loader) loader.classList.remove('active');
        if (statsGrid) statsGrid.classList.remove('loading');
    }
}

function renderTable(data) {
    if (data.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 40px; color: var(--text-secondary);">No records found matching criteria</td></tr>';
        return;
    }

    tableBody.innerHTML = data.map(item => {
        const ioc = item.iocs && item.iocs.length > 0 ? item.iocs[0] : null;
        const cve = item.cves && item.cves.length > 0 ? item.cves[0] : null;
        
        const mainIndicator = ioc ? ioc.value : (cve ? cve.id : item.record_id);
        const type = ioc ? ioc.type : (cve ? 'cve' : 'unknown');
        
        // Enrichment context
        let enrichmentBadge = "";
        if (viewMode === 'enriched' && item.enrichment) {
            const nlp = item.enrichment.nlp_extracted;
            if (nlp?.malware_families?.length > 0) {
                enrichmentBadge += `<span class="family-pill">${nlp.malware_families[0]}</span>`;
            }
            if (nlp?.threat_categories?.length > 0) {
                enrichmentBadge += `<span class="category-pill">${nlp.threat_categories[0]}</span>`;
            }
        }

        const tags = (item.tags || []).slice(0, 2).map(t => `<span class="tag">${t}</span>`).join('');
        const date = item.collected_at ? new Date(item.collected_at).toLocaleDateString() : 'N/A';

        return `
            <tr>
                <td style="font-family: monospace; font-size: 0.8rem; color: var(--text-secondary)">${item.record_id.substring(0, 10)}...</td>
                <td><span class="type-pill ${type}">${type}</span></td>
                <td>
                    <div style="display: flex; flex-direction: column; gap: 4px;">
                        <strong style="color: var(--text-primary); font-size: 0.95rem;">${truncate(mainIndicator, 32)}</strong>
                        <div style="display: flex; gap: 4px;">${enrichmentBadge}</div>
                    </div>
                </td>
                <td>${tags}${item.tags?.length > 2 ? '...' : ''}</td>
                <td>${date}</td>
                <td>
                    <button class="view-btn" onclick='viewRaw(${JSON.stringify(item.record_id)})'>View Details</button>
                </td>
            </tr>
        `;
    }).join('');
    
    window.lastLoadedData = data;
}

function updateDashboardStats(result) {
    totalCountEl.textContent = result.total;
    
    // Calculate total IOCs and CVEs in this view
    let iocsAcrossView = 0;
    let cvesAcrossView = 0;
    
    result.data.forEach(item => {
        iocsAcrossView += (item.iocs || []).length;
        cvesAcrossView += (item.cves || []).length;
    });

    iocCountStat.textContent = iocsAcrossView;
    cveCountStat.textContent = cvesAcrossView;
    
    // Pagination UI
    pageInfo.textContent = `Page ${result.page} of ${Math.ceil(result.total / PAGE_SIZE) || 1}`;
    prevBtn.disabled = result.page <= 1;
    nextBtn.disabled = result.page >= Math.ceil(result.total / PAGE_SIZE);
}

// Helpers
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

window.switchTab = (tabId) => {
    // Update tab buttons
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
        const isActive = btn.getAttribute('onclick').includes(`'${tabId}'`);
        btn.classList.toggle('active', isActive);
    });

    // Update tab panes
    const panes = document.querySelectorAll('.tab-pane');
    panes.forEach(pane => {
        pane.classList.toggle('active', pane.id === `tab-${tabId}`);
    });
};

function generateIntelligenceBrief(item) {
    const families = item.enrichment?.nlp_extracted?.malware_families || [];
    const iocs = item.iocs || [];
    const cves = item.cves || [];
    const source = (item.source || 'Threat Intel').toUpperCase();
    
    // 1. Try to get original summary and clean it
    let rawSummary = item.enrichment?.nlp_advanced?.nlp_summary || item.summary || "";
    
    // Remove JSON-like blocks: everything from the first '{' to the end
    let cleaned = rawSummary.split('{')[0].trim();
    
    // If the cleaned text is too generic or short, build a better one
    if (cleaned.length < 15) {
        cleaned = `Intelligence analysis of a record from **${source}** has been completed. `;
    }

    // Add specific counts if not already mentioned clearly
    if (!cleaned.includes('IOC') && !cleaned.includes('indicator')) {
        cleaned += `Identified **${iocs.length}** IOCs and **${cves.length}** CVEs. `;
    }

    // 2. Add intelligence insights if families are found
    if (families.length > 0) {
        cleaned += `<br><br><span style="color: var(--danger-color); font-weight: 700;">[THREAD INSIGHT]</span> This activity is associated with the **${families.join(', ')}** malware family.`;
    } else if (iocs.length > 0) {
        cleaned += `<br><br>The extracted indicators provide actionable technical data for incident response and proactive defense.`;
    }

    return cleaned;
}

window.viewRaw = (recordId) => {
    const item = window.lastLoadedData.find(d => d.record_id === recordId);
    if (!item) return;

    // Reset tabs to overview
    window.switchTab('overview');

    // Basic Meta
    document.getElementById('modal-record-id').textContent = `Record ID: ${item.record_id}`;
    document.getElementById('detail-source').textContent = item.source || 'Unknown';
    document.getElementById('detail-date').textContent = item.collected_at ? new Date(item.collected_at).toLocaleString() : 'N/A';

    // NLP Summary / Brief (Cleaned)
    const briefContent = document.getElementById('nlp-brief-content');
    briefContent.innerHTML = generateIntelligenceBrief(item);

    // Threat Level Logic
    const threatEl = document.getElementById('detail-threat-level');
    let level = 'low';
    const iocCount = (item.iocs || []).length;
    const families = item.enrichment?.nlp_extracted?.malware_families || [];
    if (families.length > 0) level = 'high';
    else if (iocCount > 3) level = 'medium';
    
    threatEl.textContent = level.toUpperCase();
    threatEl.className = `threat-badge ${level}`;

    // Intelligence Tab: IOCs, Families, Categories
    const iocList = document.getElementById('ioc-list');
    iocList.innerHTML = (item.iocs || []).map(ioc => `
        <div class="intel-badge ${ioc.type}">
            <i data-lucide="${getIconForType(ioc.type)}"></i>
            <span>${ioc.value}</span>
            <small style="opacity: 0.6; margin-left: 5px;">(${ioc.indicator_role?.role || 'indicator'})</small>
        </div>
    `).join('') || '<p class="empty-msg">No IOCs detected</p>';

    const familyList = document.getElementById('family-list');
    familyList.innerHTML = (item.enrichment?.nlp_extracted?.malware_families || []).map(f => `
        <span class="family-pill">${f}</span>
    `).join('') || '<p class="empty-msg">No malware families identified</p>';

    const catList = document.getElementById('category-list');
    catList.innerHTML = (item.enrichment?.nlp_extracted?.threat_categories || []).map(c => `
        <span class="category-pill">${c}</span>
    `).join('') || '<p class="empty-msg">No threat categories assigned</p>';

    // Context Tab: Orgs, Geo, Attrs
    const orgProdList = document.getElementById('org-prod-list');
    const orgs = item.enrichment?.nlp_advanced?.organizations || [];
    const prods = item.enrichment?.nlp_advanced?.affected_products || [];
    orgProdList.innerHTML = [...orgs.map(o => ({ k: 'Org', v: o })), ...prods.map(p => ({ k: 'Prod', v: p }))]
        .map(x => `<div class="context-item"><span class="context-key">${x.k}</span><span class="context-val">${x.v}</span></div>`).join('') 
        || '<p class="empty-msg">No organizational context</p>';

    const geoList = document.getElementById('geo-list');
    geoList.innerHTML = (item.enrichment?.nlp_advanced?.geography || []).map(g => `
        <div class="context-item"><span class="context-key">Location</span><span class="context-val">${g}</span></div>
    `).join('') || '<p class="empty-msg">No geographical data</p>';

    const attrList = document.getElementById('attr-list');
    const attrs = item.attributes || {};
    attrList.innerHTML = Object.entries(attrs).map(([k, v]) => `
        <div class="context-item"><span class="context-key">${k}</span><span class="context-val">${v}</span></div>
    `).join('') || '<p class="empty-msg">No additional attributes</p>';

    // Raw JSON
    jsonViewer.textContent = JSON.stringify(item, null, 2);

    // Show Modal
    modalOverlay.classList.remove('hidden');
    
    // Re-trigger Lucide icons for new content
    if (window.lucide) window.lucide.createIcons();
};

function getIconForType(type) {
    switch(type) {
        case 'ip': return 'network';
        case 'domain': return 'globe';
        case 'url': return 'link';
        case 'cve': return 'alert-triangle';
        case 'hash': return 'file-digit';
        default: return 'info';
    }
}

// Event Listeners
function setupEventListeners() {
    prevBtn.onclick = () => { if (currentPage > 1) { currentPage--; loadData(); } };
    nextBtn.onclick = () => { currentPage++; loadData(); };
    
    let searchTimeout;
    searchInput.oninput = () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            currentPage = 1;
            loadData();
        }, 500);
    };
    
    refreshBtn.onclick = () => loadData();
    
    closeModal.onclick = () => modalOverlay.classList.add('hidden');
    modalOverlay.onclick = (e) => { if (e.target === modalOverlay) closeModal.onclick(); };
}

// Start
init();
