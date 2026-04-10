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
    
    tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 40px;">Loading records...</td></tr>';
    
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
            if (nlp.malware_families?.length > 0) {
                enrichmentBadge += `<span class="family-pill">${nlp.malware_families[0]}</span>`;
            }
            if (nlp.threat_categories?.length > 0) {
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

window.viewRaw = (recordId) => {
    const item = window.lastLoadedData.find(d => d.record_id === recordId);
    if (item) {
        // Parse raw_text if stringified
        let display = item;
        try {
            if (typeof item.raw_text === 'string') {
                display = { ...item, raw_text: JSON.parse(item.raw_text) };
            }
        } catch(e) {}
        
        jsonViewer.textContent = JSON.stringify(display, null, 2);
        modalOverlay.classList.remove('hidden');
    }
};

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
