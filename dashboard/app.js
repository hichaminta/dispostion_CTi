/**
 * CTI Extraction Dashboard Logic
 */

const API_BASE = "http://localhost:8000/api/extracted";
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

// Load Sources
async function loadSources() {
    try {
        const response = await fetch(`${API_BASE}/sources`);
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
        currentSourceInfo.textContent = `Extracted results from ${srcObj.file}`;
        fileSizeEl.textContent = formatSize(srcObj.size);
        lastUpdateStat.textContent = new Date(srcObj.last_modified * 1000).toLocaleString();
    }
}

// Load Data
async function loadData() {
    if (!currentSource) return;
    
    tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 40px;">Loading records...</td></tr>';
    
    const query = new URLSearchParams({
        page: currentPage,
        limit: PAGE_SIZE,
        search: searchInput.value || ""
    });

    try {
        const response = await fetch(`${API_BASE}/data/${currentSource}?${query}`);
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
        const tags = (item.tags || []).slice(0, 3).map(t => `<span class="tag">${t}</span>`).join('');
        const date = item.collected_at ? new Date(item.collected_at).toLocaleDateString() : 'N/A';

        return `
            <tr>
                <td style="font-family: monospace; font-size: 0.8rem; color: var(--text-secondary)">${item.record_id.substring(0, 12)}...</td>
                <td><span class="type-pill ${type}">${type}</span></td>
                <td><strong style="color: var(--text-primary)">${truncate(mainIndicator, 30)}</strong></td>
                <td>${tags}${item.tags?.length > 3 ? '...' : ''}</td>
                <td>${date}</td>
                <td>
                    <button class="view-btn" onclick='viewRaw(${JSON.stringify(item.record_id)})'>View</button>
                </td>
            </tr>
        `;
    }).join('');
    
    // Add raw data back to elements for modal access
    // Note: In a real app we'd store the full objects in memory
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
