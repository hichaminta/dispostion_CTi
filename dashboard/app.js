/**
 * CTI Extraction Dashboard Logic
 */

const API_BASE_EXTRACTED = "http://localhost:8000/api/extracted";
const API_BASE_ENRICHED = "http://localhost:8000/api/enriched";
const API_BASE_STATS = "http://localhost:8000/api/stats";

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
const typeFilter = document.getElementById('type-filter');
const refreshBtn = document.getElementById('refresh-btn');
const modalOverlay = document.getElementById('modal-overlay');
const jsonViewer = document.getElementById('raw-json-viewer');
const closeModal = document.getElementById('close-modal');
const countryStatsList = document.getElementById('country-stats-list');
const scrollUpBtn = document.getElementById('scroll-up');
const scrollDownBtn = document.getElementById('scroll-down');

// Init
async function init() {
    await loadSources();
    await loadCountryStats(); // Load geography global overview
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
    sourceList.innerHTML = sources.map(src => {
        const logoUrl = getSourceLogo(src.name);
        const icon = logoUrl ? `<div class="source-logo-sm" style="margin-right: 12px;"><img src="${logoUrl}" alt="${src.name}"></div>` : `<i data-lucide="shield" class="source-logo-sm" style="margin-right: 12px;"></i>`;
        
        return `
            <div class="source-item ${currentSource === src.id ? 'active' : ''}" onclick="selectSource('${src.id}')">
                <div style="display: flex; align-items: center;">
                    ${icon}
                    <span class="src-name">${src.name}</span>
                </div>
                <span class="badge">${formatSize(src.size)}</span>
            </div>
        `;
    }).join('');
    if (window.lucide) window.lucide.createIcons();
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
        
        // Show enrichment panel when a source is selected
        const enrichPanel = document.getElementById('enrichment-panel');
        if (enrichPanel) enrichPanel.classList.remove('hidden');
    }
}

/**
 * Trigger an enrichment phase for the current source
 */
window.triggerEnrichmentStep = async (stepName) => {
    if (!currentSource) {
        showNotification("Please select a source first", "error");
        return;
    }

    const srcObj = sources.find(s => s.id === currentSource);
    if (!srcObj) return;

    try {
        showNotification(`Starting ${stepName} for ${srcObj.name}...`, "info");
        
        const response = await fetch(`http://localhost:8000/runs/targeted?step_name=${encodeURIComponent(stepName)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_name: srcObj.name,
                source_type: "manual_trigger"
            })
        });

        if (response.ok) {
            const run = await response.json();
            showNotification(`${stepName} initiated successfully (ID: ${run.run_id.substring(0,8)})`, "success");
        } else {
            const err = await response.json();
            showNotification(`Failed to start ${stepName}: ${err.detail || 'Unknown error'}`, "error");
        }
    } catch (err) {
        console.error("Enrichment trigger error:", err);
        showNotification("Connection error. Is the backend running?", "error");
    }
};

/**
 * Utility for UI notifications
 */
function showNotification(message, type = 'info') {
    // Create notification element if it doesn't exist
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px;';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `glass animate-fade-in toast toast-${type}`;
    toast.style.cssText = `
        padding: 12px 20px;
        border-radius: 10px;
        color: white;
        font-size: 0.9rem;
        border-left: 4px solid ${type === 'success' ? 'var(--success-color)' : type === 'error' ? 'var(--danger-color)' : 'var(--accent-color)'};
        min-width: 300px;
        backdrop-filter: blur(10px);
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    `;
    
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 12px;">
            <i data-lucide="${type === 'success' ? 'check-circle' : type === 'error' ? 'alert-circle' : 'info'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    container.appendChild(toast);
    if (window.lucide) window.lucide.createIcons();
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
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
        search: searchInput.value || "",
        ioc_type: (typeFilter && typeFilter.value) || ""
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

const SOURCE_LOGOS = {
    'AbuseIPDB': 'https://www.abuseipdb.com/favicon.ico',
    'VirusTotal': 'https://www.virustotal.com/gui/images/favicon.png',
    'OTX AlienVault': 'https://otx.alienvault.com/assets/favicon.ico',
    'AlienVault': 'https://otx.alienvault.com/assets/favicon.ico',
    'Spamhaus': 'https://www.spamhaus.org/favicon.ico',
    'URLHaus': 'https://urlhaus.abuse.ch/favicon.ico',
    'ThreatFox': 'https://threatfox.abuse.ch/favicon.ico',
    'MalwareBazaar': 'https://malwarebazaar.abuse.ch/favicon.ico',
    'PhishTank': 'https://www.phishtank.com/favicon_32x32.png',
    'OpenPhish': 'https://openphish.com/favicon.ico',
    'NVD': 'https://nvd.nist.gov/favicon.ico',
    'PulseDive': 'https://pulsedive.com/favicon.ico',
    'FeodoTracker': 'https://feodotracker.abuse.ch/favicon.ico'
};

function getSourceLogo(sourceName) {
    if (!sourceName) return null;
    const key = Object.keys(SOURCE_LOGOS).find(k => sourceName.toLowerCase().includes(k.toLowerCase()));
    return key ? SOURCE_LOGOS[key] : null;
}

const COUNTRY_NAME_TO_CODE = {
    'afghanistan': 'af', 'albania': 'al', 'algeria': 'dz', 'andorra': 'ad', 'angola': 'ao', 'argentina': 'ar', 'armenia': 'am', 'australia': 'au', 'austria': 'at', 'azerbaijan': 'az',
    'bahamas': 'bs', 'bahrain': 'bh', 'bangladesh': 'bd', 'barbados': 'bb', 'belarus': 'by', 'belgium': 'be', 'belize': 'bz', 'benin': 'bj', 'bhutan': 'bt', 'bolivia': 'bo',
    'brazil': 'br', 'bulgaria': 'bg', 'burkina faso': 'bf', 'burundi': 'bi', 'cambodia': 'kh', 'cameroon': 'cm', 'canada': 'ca', 'chad': 'td', 'chile': 'cl', 'china': 'cn',
    'colombia': 'co', 'congo': 'cg', 'costa rica': 'cr', 'croatia': 'hr', 'cuba': 'cu', 'cyprus': 'cy', 'czechia': 'cz', 'denmark': 'dk', 'djibouti': 'dj', 'dominica': 'dm',
    'ecuador': 'ec', 'egypt': 'eg', 'estonia': 'ee', 'ethiopia': 'et', 'fiji': 'fj', 'finland': 'fi', 'france': 'fr', 'gabon': 'ga', 'gambia': 'gm', 'georgia': 'ge', 'germany': 'de',
    'ghana': 'gh', 'greece': 'gr', 'guatemala': 'gt', 'guinea': 'gn', 'guyana': 'gy', 'haiti': 'ht', 'honduras': 'hn', 'hungary': 'hu', 'iceland': 'is', 'india': 'in', 'indonesia': 'id',
    'iran': 'ir', 'iraq': 'iq', 'ireland': 'ie', 'israel': 'il', 'italy': 'it', 'jamaica': 'jm', 'japan': 'jp', 'jordan': 'jo', 'kazakhstan': 'kz', 'kenya': 'ke', 'kuwait': 'kw',
    'kyrgyzstan': 'kg', 'laos': 'la', 'latvia': 'lv', 'lebanon': 'lb', 'lesotho': 'ls', 'liberia': 'lr', 'libya': 'ly', 'lithuania': 'lt', 'luxembourg': 'lu', 'madagascar': 'mg',
    'malaysia': 'my', 'maldives': 'mv', 'mali': 'ml', 'malta': 'mt', 'mexico': 'mx', 'moldova': 'md', 'monaco': 'mc', 'mongolia': 'mn', 'montenegro': 'me', 'morocco': 'ma',
    'myanmar': 'mm', 'namibia': 'na', 'nepal': 'np', 'netherlands': 'nl', 'new zealand': 'nz', 'nicaragua': 'ni', 'niger': 'ne', 'nigeria': 'ng', 'north korea': 'kp',
    'norway': 'no', 'oman': 'om', 'pakistan': 'pk', 'palau': 'pw', 'panama': 'pa', 'paraguay': 'py', 'peru': 'pe', 'philippines': 'ph', 'poland': 'pl', 'portugal': 'pt', 'qatar': 'qa',
    'romania': 'ro', 'russia': 'ru', 'rwanda': 'rw', 'saudi arabia': 'sa', 'senegal': 'sn', 'serbia': 'rs', 'seychelles': 'sc', 'sierra leone': 'sl', 'singapore': 'sg',
    'slovakia': 'sk', 'slovenia': 'si', 'somalia': 'so', 'south africa': 'za', 'south korea': 'kr', 'spain': 'es', 'sri lanka': 'lk', 'sudan': 'sd', 'suriname': 'sr',
    'sweden': 'se', 'switzerland': 'ch', 'syria': 'sy', 'taiwan': 'tw', 'tajikistan': 'tj', 'tanzania': 'tz', 'thailand': 'th', 'togo': 'tg', 'tonga': 'to', 'tunisia': 'tn',
    'turkey': 'tr', 'turkmenistan': 'tm', 'uganda': 'ug', 'ukraine': 'ua', 'uae': 'ae', 'united arab emirates': 'ae', 'uk': 'gb', 'united kingdom': 'gb', 'usa': 'us',
    'united states': 'us', 'uruguay': 'uy', 'uzbekistan': 'uz', 'vanuatu': 'vu', 'venezuela': 've', 'vietnam': 'vn', 'yemen': 'ye', 'zambia': 'zm', 'zimbabwe': 'zw'
};

const COUNTRY_CODE_TO_NAME = {
    'af': 'Afghanistan', 'al': 'Albania', 'dz': 'Algeria', 'ad': 'Andorra', 'ao': 'Angola', 'ar': 'Argentina', 'am': 'Armenia', 'au': 'Australia', 'at': 'Austria', 'az': 'Azerbaijan',
    'bs': 'Bahamas', 'bh': 'Bahrain', 'bd': 'Bangladesh', 'bb': 'Barbados', 'by': 'Belarus', 'be': 'Belgium', 'bz': 'Belize', 'bj': 'Benin', 'bt': 'Bhutan', 'bo': 'Bolivia',
    'br': 'Brazil', 'bg': 'Bulgaria', 'bf': 'Burkina Faso', 'bi': 'Burundi', 'kh': 'Cambodia', 'cm': 'Cameroon', 'ca': 'Canada', 'td': 'Chad', 'cl': 'Chile', 'cn': 'China',
    'co': 'Colombia', 'cg': 'Congo', 'cr': 'Costa Rica', 'hr': 'Croatia', 'cu': 'Cuba', 'cy': 'Cyprus', 'cz': 'Czechia', 'dk': 'Denmark', 'dj': 'Djibouti', 'dm': 'Dominica',
    'ec': 'Ecuador', 'eg': 'Egypt', 'ee': 'Estonia', 'et': 'Ethiopia', 'fj': 'Fiji', 'fi': 'Finland', 'fr': 'France', 'ga': 'Gabon', 'gm': 'Gambia', 'ge': 'Georgia', 'de': 'Germany',
    'gh': 'Ghana', 'gr': 'Greece', 'gt': 'Guatemala', 'gn': 'Guinea', 'gy': 'Guyana', 'ht': 'Haiti', 'hn': 'Honduras', 'hu': 'Hungary', 'is': 'Iceland', 'in': 'India', 'id': 'Indonesia',
    'ir': 'Iran', 'iq': 'Iraq', 'ie': 'Ireland', 'il': 'Israel', 'it': 'Italy', 'jm': 'Jamaica', 'jp': 'Japan', 'jo': 'Jordan', 'kz': 'Kazakhstan', 'ke': 'Kenya', 'kw': 'Kuwait',
    'kg': 'Kyrgyzstan', 'la': 'Laos', 'lv': 'Latvia', 'lb': 'Lebanon', 'ls': 'Lesotho', 'lr': 'Liberia', 'ly': 'Libya', 'lt': 'Lithuania', 'lu': 'Luxembourg', 'mg': 'Madagascar',
    'my': 'Malaysia', 'mv': 'Maldives', 'ml': 'Mali', 'mt': 'Malta', 'mx': 'Mexico', 'md': 'Moldova', 'mc': 'Monaco', 'mn': 'Mongolia', 'me': 'Montenegro', 'ma': 'Morocco',
    'mm': 'Myanmar', 'na': 'Namibia', 'np': 'Nepal', 'nl': 'Netherlands', 'nz': 'New Zealand', 'ni': 'Nicaragua', 'ne': 'Niger', 'ng': 'Nigeria', 'kp': 'North Korea',
    'no': 'Norway', 'om': 'Oman', 'pk': 'Pakistan', 'pw': 'Palau', 'pa': 'Panama', 'py': 'Paraguay', 'pe': 'Peru', 'ph': 'Philippines', 'pl': 'Poland', 'pt': 'Portugal', 'qa': 'Qatar',
    'ro': 'Romania', 'ru': 'Russia', 'rw': 'Rwanda', 'sa': 'Saudi Arabia', 'sn': 'Senegal', 'rs': 'Serbia', 'sc': 'Seychelles', 'sl': 'Sierra Leone', 'sg': 'Singapore',
    'sk': 'Slovakia', 'si': 'Slovenia', 'so': 'Somalia', 'za': 'South Africa', 'kr': 'South Korea', 'es': 'Spain', 'lk': 'Sri Lanka', 'sd': 'Sudan', 'sr': 'Suriname',
    'se': 'Sweden', 'ch': 'Switzerland', 'sy': 'Syria', 'tw': 'Taiwan', 'tj': 'Tajikistan', 'tz': 'Tanzania', 'th': 'Thailand', 'tg': 'Togo', 'to': 'Tonga', 'tn': 'Tunisia',
    'tr': 'Turkey', 'tm': 'Turkmenistan', 'ug': 'Uganda', 'ua': 'Ukraine', 'ae': 'United Arab Emirates', 'gb': 'United Kingdom', 'us': 'United States', 'uy': 'Uruguay',
    'uz': 'Uzbekistan', 'vu': 'Vanuatu', 've': 'Venezuela', 'vn': 'Vietnam', 'ye': 'Yemen', 'zm': 'Zambia', 'zw': 'Zimbabwe'
};

function getCountryFullName(country) {
    if (!country) return 'Unknown';
    const c = country.toLowerCase().trim();
    if (c.length === 2 && COUNTRY_CODE_TO_NAME[c]) return COUNTRY_CODE_TO_NAME[c];
    return country;
}

function getFlagUrl(country) {
    if (!country) return null;
    const c = country.toLowerCase().trim();
    let code = null;
    if (c.length === 2 && /^[a-z]+$/.test(c)) code = c;
    else if (COUNTRY_NAME_TO_CODE[c]) code = COUNTRY_NAME_TO_CODE[c];
    
    return code ? `https://flagcdn.com/w40/${code}.png` : null;
}

window.setCountryFilter = (country) => {
    searchInput.value = country;
    currentPage = 1;
    loadData();
    // Scroll to table
    document.querySelector('.table-workspace').scrollIntoView({ behavior: 'smooth' });
};

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

        // Source Icon
        const logoUrl = getSourceLogo(item.source);
        const sourceIcon = logoUrl ? `<div class="source-logo-sm"><img src="${logoUrl}" alt="${item.source}"></div>` : `<i data-lucide="shield" class="source-logo-sm"></i>`;

        return `
            <tr>
                <td style="font-family: monospace; font-size: 0.8rem; color: var(--text-secondary)">${item.record_id.substring(0, 10)}...</td>
                <td><span class="type-pill ${type}">${type}</span></td>
                <td>
                    <div style="display: flex; flex-direction: column; gap: 4px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            ${sourceIcon}
                            <strong style="color: var(--text-primary); font-size: 0.95rem;">${truncate(mainIndicator, 32)}</strong>
                        </div>
                        <div style="display: flex; gap: 4px;">${enrichmentBadge}</div>
                    </div>
                </td>
                <td>${tags}${item.tags?.length > 2 ? '...' : ''}</td>
                <td>${date}</td>
                <td>
                    <button class="view-btn action-view-details" data-record-id="${item.record_id}">View Details</button>
                </td>
            </tr>
        `;
    }).join('');
    
    window.lastLoadedData = data;
    if (window.lucide) window.lucide.createIcons();
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
    console.log("[ViewDetails] Opening record:", recordId);
    
    if (!window.lastLoadedData) {
        console.error("[ViewDetails] window.lastLoadedData is missing");
        return;
    }

    const item = window.lastLoadedData.find(d => String(d.record_id) === String(recordId));
    
    if (!item) {
        console.error("[ViewDetails] Record not found in local cache:", recordId);
        return;
    }

    // Reset tabs to overview
    window.switchTab('overview');

    // Basic Meta
    document.getElementById('modal-record-id').textContent = `Record ID: ${item.record_id}`;
    document.getElementById('detail-source').textContent = item.source || 'Unknown';
    document.getElementById('detail-date').textContent = item.collected_at ? new Date(item.collected_at).toLocaleString() : 'N/A';

    // Update Source Logo in Modal
    const logoContainer = document.getElementById('modal-source-logo-container');
    const logoUrl = getSourceLogo(item.source);
    if (logoUrl) {
        logoContainer.innerHTML = `<img src="${logoUrl}" alt="${item.source}">`;
    } else {
        logoContainer.innerHTML = `<i data-lucide="shield-alert" class="panel-icon"></i>`;
    }

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
        <div class="intel-badge ${ioc.type}" title="${ioc.indicator_role?.role || 'indicator'}">
            <i data-lucide="${getIconForType(ioc.type)}"></i>
            <span>${ioc.value}</span>
            <small style="opacity: 0.6; margin-left: 5px;">(${ioc.indicator_role?.role || 'indicator'})</small>
        </div>
    `).join('') || '<p class="empty-msg">No IOCs detected</p>';

    // Aggregators for indicator-level enrichment
    const allFamilies = new Set(item.enrichment?.nlp_extracted?.malware_families || []);
    const allCategories = new Set(item.enrichment?.nlp_extracted?.threat_categories || []);
    const allGeography = new Set(item.enrichment?.nlp_advanced?.geography || []);
    const allAttributes = { ...(item.attributes || {}) };

    (item.iocs || []).forEach(ioc => {
        const enr = ioc.ioc_enrichment || {};
        
        // Families
        if (enr.malware_family) allFamilies.add(enr.malware_family);
        if (enr.malware_families) enr.malware_families.forEach(f => allFamilies.add(f));
        
        // Categories
        if (enr.threat_categories) enr.threat_categories.forEach(c => allCategories.add(c));
        
        // Geography
        if (enr.geography) enr.geography.forEach(g => allGeography.add(g));
        if (enr.country) allGeography.add(enr.country);
        if (enr.country_name) allGeography.add(enr.country_name);
        
        // Attributes (merge)
        Object.entries(enr).forEach(([k, v]) => {
            if (!['geography', 'threat_categories', 'malware_families', 'malware_family'].includes(k)) {
                if (v !== null && v !== undefined && v !== "") {
                    allAttributes[k] = v;
                }
            }
        });
    });

    const familyList = document.getElementById('family-list');
    familyList.innerHTML = Array.from(allFamilies).map(f => `
        <span class="family-pill">${f}</span>
    `).join('') || '<p class="empty-msg">No malware families identified</p>';

    const catList = document.getElementById('category-list');
    catList.innerHTML = Array.from(allCategories).map(c => `
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
    geoList.innerHTML = Array.from(allGeography).map(g => {
        const flagUrl = getFlagUrl(g);
        const fullName = getCountryFullName(g);
        const flag = flagUrl ? `<img src="${flagUrl}" class="country-flag-inline" alt="${g}">` : '';
        return `
            <div class="context-item"><span class="context-key">Location</span><span class="context-val">${flag}${fullName}</span></div>
        `;
    }).join('') || '<p class="empty-msg">No geographical data</p>';

    const attrList = document.getElementById('attr-list');
    attrList.innerHTML = Object.entries(allAttributes).map(([k, v]) => `
        <div class="context-item"><span class="context-key">${k}</span><span class="context-val">${v}</span></div>
    `).join('') || '<p class="empty-msg">No additional attributes</p>';

    // Raw JSON
    jsonViewer.textContent = JSON.stringify(item, null, 2);

    // Dynamic Analysis (URLScan)
    const scanData = (item.iocs || []).find(i => i.ioc_enrichment?.url_scan)?.ioc_enrichment.url_scan;
    const screenContainer = document.getElementById('urlscan-screenshot-container');
    const metaContainer = document.getElementById('urlscan-metadata');

    if (scanData && scanData.scanned && scanData.screenshot) {
        screenContainer.innerHTML = `<img src="${scanData.screenshot}" class="urlscan-img" alt="Scan Screenshot">`;
        
        const details = [
            { k: 'Effective URL', v: scanData.effective_url },
            { k: 'IP Address',    v: scanData.ip },
            { k: 'Country',       v: scanData.country },
            { k: 'ASN',           v: `${scanData.asn} (${scanData.asnname})` },
            { k: 'Server',        v: scanData.server },
            { k: 'Reverse DNS',   v: scanData.ptr }
        ];

        metaContainer.innerHTML = details.map(d => d.v ? `
            <div class="context-item">
                <span class="context-key">${d.k}</span>
                <span class="context-val analysis-val">${d.v}</span>
            </div>
        ` : '').join('') || '<p class="empty-msg">No detailed metadata</p>';
    } else {
        screenContainer.innerHTML = `<div class="empty-msg">No screenshot available</div>`;
        metaContainer.innerHTML = `<p class="empty-msg">No scan data available</p>`;
    }

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
    
    refreshBtn.onclick = () => {
        loadData();
        loadCountryStats();
    };

    if (typeFilter) {
        typeFilter.onchange = () => {
            currentPage = 1;
            loadData();
        };
    }
    
    closeModal.onclick = () => modalOverlay.classList.add('hidden');
    if (modalOverlay) {
        modalOverlay.onclick = (e) => { if (e.target === modalOverlay) closeModal.onclick(); };
    }

    // Source List Scroll Controls
    if (scrollUpBtn && sourceList) {
        scrollUpBtn.onclick = () => {
            sourceList.scrollBy({ top: -100, behavior: 'smooth' });
        };
    }
    
    if (scrollDownBtn && sourceList) {
        scrollDownBtn.onclick = () => {
            sourceList.scrollBy({ top: 100, behavior: 'smooth' });
        };
    }

    // Event Delegation for Table Actions
    if (tableBody) {
        tableBody.onclick = (e) => {
            const viewBtn = e.target.closest('.action-view-details');
            if (viewBtn) {
                const recordId = viewBtn.getAttribute('data-record-id');
                window.viewRaw(recordId);
            }
        };
    }
}

// ─── Geographical Stats Logic ───
async function loadCountryStats() {
    if (!countryStatsList) return;
    
    try {
        const response = await fetch(`${API_BASE_STATS}/countries`);
        const stats = await response.json();
        renderCountryStats(stats);
    } catch (err) {
        console.error("Failed to load country stats:", err);
        countryStatsList.innerHTML = '<p class="empty-msg">Error loading geography data</p>';
    }
}

function renderCountryStats(stats) {
    if (!stats || stats.length === 0) {
        countryStatsList.innerHTML = '<p class="empty-msg">No geographical data available yet.</p>';
        return;
    }

    const maxCount = Math.max(...stats.map(s => s.count));
    
    countryStatsList.innerHTML = stats.map(s => {
        const percentage = (s.count / maxCount) * 100;
        const flagUrl = getFlagUrl(s.country);
        const flagImg = flagUrl ? `<img src="${flagUrl}" class="country-flag" alt="${s.country}">` : `<i data-lucide="globe" class="country-flag-icon"></i>`;
        
        return `
            <div class="country-row" title="Show logs for ${s.country}" onclick="setCountryFilter('${s.country}')">
                <div class="country-meta">
                    <div class="country-info">
                        ${flagImg}
                        <span class="country-name">${s.country}</span>
                    </div>
                    <span class="country-count">${s.count}</span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        `;
    }).join('');

    // Re-trigger Lucide for fallback icons
    if (window.lucide) window.lucide.createIcons();

    // Animate bars after a short delay
    setTimeout(() => {
        const fills = countryStatsList.querySelectorAll('.progress-fill');
        stats.forEach((s, i) => {
            const percentage = (s.count / maxCount) * 100;
            if (fills[i]) fills[i].style.width = `${percentage}%`;
        });
    }, 100);
}

// Start
init();
