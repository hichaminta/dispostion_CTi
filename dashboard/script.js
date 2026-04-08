/* ============================================================
   CTI Shield – script.js
   ============================================================ */

// ── Global state ──────────────────────────────────────────
const PAGE_SIZE   = 50;

let G_allIocs     = [];   // full dataset
let G_filtered    = [];   // after search + type + tag filters
let G_page        = 0;    // current page index (0-based)
let G_activeType   = null; // e.g. "ip"
let G_activeSource = null; // e.g. "alienvault"
let G_activeCountry = null; // e.g. "United States"
let G_query        = '';   // text search

let G_currentPageIocs = []; // IOCs on screen (for modal)
let G_visibleCves     = []; // CVEs on screen (for modal)
let G_allCves         = []; // full CVE dataset
let G_filteredCves    = []; // after search
let G_cvePage         = 0;    // current page index for CVEs
let G_activeCveSource = null; // e.g. "nvd"

const SOURCES_CONFIG = {
    abuseipdb:     { label: 'AbuseIPDB',      icon: 'shield-alert',    theme: 'src-abuseipdb' },
    alienvault:    { label: 'AlienVault OTX',  icon: 'radio',           theme: 'src-alienvault' },
    cins_army:     { label: 'CINS Army',       icon: 'swords',          theme: 'src-cins_army' },
    feodotracker:  { label: 'FeodoTracker',    icon: 'bug',             theme: 'src-feodotracker' },
    malwarebazaar: { label: 'MalwareBazaar',   icon: 'package-x',       theme: 'src-malwarebazaar' },
    nvd:           { label: 'NVD (CVE)',        icon: 'database-zap',    theme: 'src-nvd' },
    openphish:     { label: 'OpenPhish',       icon: 'fish',            theme: 'src-openphish' },
    phishtank:     { label: 'PhishTank',       icon: 'anchor',          theme: 'src-phishtank' },
    pulsedive:     { label: 'Pulsedive',       icon: 'activity',        theme: 'src-pulsedive' },
    threatfox:     { label: 'ThreatFox',       icon: 'biohazard',       theme: 'src-threatfox' },
    urlhaus:       { label: 'URLhaus',         icon: 'link',            theme: 'src-urlhaus' },
    virustotal:    { label: 'VirusTotal',      icon: 'scan-eye',        theme: 'src-virustotal' },
};

// Colour palettes
const TYPE_COLORS = {
    ip:      { bg: 'rgba(139, 92, 246, 0.18)', col: '#a78bfa' }, // Violet
    url:     { bg: 'rgba(245, 158, 11, 0.18)',  col: '#fbbf24' }, // Amber
    domain:  { bg: 'rgba(16, 185, 129, 0.18)', col: '#34d399' }, // Emerald
    sha256:  { bg: 'rgba(249, 115, 22, 0.18)',  col: '#fb923c' }, // Orange
    sha1:    { bg: 'rgba(239, 68, 68, 0.18)',  col: '#f87171' }, // Red
    md5:     { bg: 'rgba(244, 63, 94, 0.18)',  col: '#fb7185' }, // Rose
    email:   { bg: 'rgba(192, 132, 252, 0.18)', col: '#d8b4fe' }, // Light Purple
    unknown: { bg: 'rgba(100, 116, 139, 0.18)', col: '#94a3b8' },
};
function typeColor(t) { return TYPE_COLORS[t] || TYPE_COLORS.unknown; }

const TAG_PALETTE = [
    { bg: 'rgba(139, 92, 246, 0.18)', col: '#a78bfa' },
    { bg: 'rgba(245, 158, 11, 0.18)', col: '#fbbf24' },
    { bg: 'rgba(16, 185, 129, 0.18)', col: '#34d399' },
    { bg: 'rgba(249, 115, 22, 0.18)', col: '#fb923c' },
    { bg: 'rgba(239, 68, 68, 0.18)',  col: '#f87171' },
    { bg: 'rgba(244, 63, 94, 0.18)',  col: '#fb7185' },
    { bg: 'rgba(168, 85, 247, 0.18)', col: '#c084fc' },
    { bg: 'rgba(234, 179, 8, 0.18)',  col: '#facc15' },
];
const tagColor = (i) => TAG_PALETTE[i % TAG_PALETTE.length];

/* ============================================================
   BOOT
   ============================================================ */
document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    const statusEl = document.getElementById('loading-status');
    const overlay  = document.getElementById('loading-overlay');
    const barEl    = document.getElementById('loader-bar');

    const setLoad = (msg, pct) => {
        if (statusEl) statusEl.innerText = msg;
        if (barEl) barEl.style.width = pct + '%';
    };

    const parseRaw = (entry, s) => {
        let ctx = {};
        if (entry.raw_text) {
            try {
                const raw = JSON.parse(entry.raw_text);
                if (s === 'abuseipdb') {
                    if (raw.abuseConfidenceScore != null) ctx.abuseConfidenceScore = raw.abuseConfidenceScore;
                    if (raw.lastReportedAt) ctx.lastReported = raw.lastReportedAt;
                    if (raw.countryCode) ctx.countryCode = raw.countryCode;
                    if (raw.isp) ctx.isp = raw.isp;
                } else if (s === 'alienvault') {
                    if (raw.name) ctx.pulseName = raw.name;
                    if (raw.description) ctx.description = raw.description;
                    if (raw.tags) ctx.tags = raw.tags;
                } else if (s === 'malwarebazaar') {
                    if (raw.signature) ctx.signature = raw.signature;
                    if (raw.tags) ctx.tags = raw.tags;
                    if (raw.file_type) ctx.fileType = raw.file_type;
                } else if (s === 'threatfox' || s === 'urlhaus') {
                    if (raw.tags) ctx.tags = raw.tags;
                    if (raw.threat_type) ctx.threatType = raw.threat_type;
                    if (raw.reporter) ctx.reporter = raw.reporter;
                }
            } catch (e) { console.debug(`Failed to parse raw text for ${s}`); }
        }
        return Object.keys(ctx).length ? ctx : null;
    };

    try {
        setLoad('Scanning and Authenticating Source Nodes...', 5);
        
        const SOURCES = [
            'abuseipdb', 'alienvault', 'cins_army', 'feodotracker', 
            'malwarebazaar', 'nvd', 'openphish', 'phishtank', 
            'pulsedive', 'threatfox', 'urlhaus', 'virustotal'
        ];

        let loadedIocs = [];
        let loadedCves = [];
        let syncData = {};

        for (let i = 0; i < SOURCES.length; i++) {
            const s = SOURCES[i];
            const pct = Math.floor(10 + (i / SOURCES.length) * 80);
            setLoad(`Synchronizing source: ${s} (${i + 1}/${SOURCES.length})...`, pct);

            // 1. Fetch Tracking Info
            try {
                const trRes = await fetch(`/extraction_ioc_cve/tracking/${s}_tracking.json`);
                if (trRes.ok) syncData[s] = await trRes.json();
            } catch (e) { console.debug(`No tracking for ${s}`); }

            // 2. Fetch Data (Excl. massive files > 300MB to prevent browser crash)
            try {
                // Check size first via HEAD if possible, or just skip MalwareBazaar/Alienvault specifically if they are known huge
                if (s === 'malwarebazaar') {
                    console.warn(`Skipping data payload for ${s} (1.4GB) to avoid browser crash.`);
                    continue;
                }

                const res = await fetch(`/output_cve_ioc/${s}_extracted.json`);
                if (!res.ok) continue;

                // Safety: If it's Alienvault (220MB) or Threatfox (146MB), it might be slow but safe
                const data = await res.json();
                
                // Flatten entry-based structure
                if (Array.isArray(data)) {
                    data.forEach(entry => {
                        const enrichedCtx = parseRaw(entry, s);
                        if (entry.iocs) {
                            entry.iocs.forEach(ioc => {
                                if (!ioc.sources) ioc.sources = [s];
                                if (enrichedCtx) {
                                    if (!ioc.contexts) ioc.contexts = [];
                                    ioc.contexts.push(enrichedCtx);
                                }
                                loadedIocs.push(ioc);
                            });
                        }
                        if (entry.cves) {
                            entry.cves.forEach(cve => {
                                if (!cve.sources) cve.sources = [s];
                                if (enrichedCtx) {
                                    if (!cve.contexts) cve.contexts = [];
                                    cve.contexts.push(enrichedCtx);
                                    // Map NVD fields
                                    if (s === 'nvd') {
                                        try {
                                            const raw = JSON.parse(entry.raw_text);
                                            if (raw.vuln_summary) cve.summary = raw.vuln_summary;
                                            if (raw.base_score) cve.score = raw.base_score;
                                        } catch(e){}
                                    }
                                }
                                loadedCves.push(cve);
                            });
                        }
                    });
                }
            } catch (e) {
                console.error(`Failed to load data for ${s}:`, e);
            }
        }

        const iocs = loadedIocs;
        const cves = loadedCves;

        setLoad('Mapping global threat vectors...', 90);
        window._cveIndex = Object.fromEntries(
            cves.filter(c => c.cve_id).map(c => [c.cve_id.toUpperCase(), c])
        );

        document.getElementById('total-iocs').innerText = iocs.length.toLocaleString();
        document.getElementById('total-cves').innerText = cves.length.toLocaleString();

        // Render Sync Status Table
        const syncTable = document.getElementById('syncStatusTableBody');
        if (syncTable) {
            syncTable.innerHTML = SOURCES.map(s => {
                const tr = syncData[s] || {};
                const last = tr.recent_extracted_at ? fmtDate(tr.recent_extracted_at) : 'Never';
                const first = tr.oldest_extracted_at ? fmtDate(tr.oldest_extracted_at) : 'N/A';
                const status = tr.recent_extracted_at ? '<span class="sev-pill sev-l">Active</span>' : '<span class="sev-pill sev-n">Idle</span>';
                return `<tr>
                    <td style="font-weight:600; color:var(--primary);">${s}</td>
                    <td>${status}</td>
                    <td style="font-family:monospace; font-size:0.75rem;">${last}</td>
                    <td style="font-family:monospace; font-size:0.75rem;">${first}</td>
                </tr>`;
            }).join('');
        }

        // Compute unique IOC sources
        const iocSourceCount = {};
        iocs.forEach(i => { if(Array.isArray(i.sources)) i.sources.forEach(s => { if(s) iocSourceCount[s] = (iocSourceCount[s]||0)+1; }); });
        document.getElementById('total-ioc-sources').innerText = Object.keys(iocSourceCount).length.toLocaleString();

        // Compute unique CVE sources
        const cveSourceCount = {};
        cves.forEach(c => { if(Array.isArray(c.sources)) c.sources.forEach(s => { if(s) cveSourceCount[s] = (cveSourceCount[s]||0)+1; }); });
        document.getElementById('total-cve-sources').innerText = Object.keys(cveSourceCount).length.toLocaleString();

        // Compute countries
        const countryCount = {};
        const countryToCode = {};
        iocs.forEach(i => {
            if (Array.isArray(i.contexts)) {
                for (let c of i.contexts) {
                    if (c && (c.countryName || c.countryCode)) {
                        let cname = c.countryName || c.countryCode;
                        countryCount[cname] = (countryCount[cname]||0)+1;
                        if (c.countryCode && !countryToCode[cname]) {
                            countryToCode[cname] = c.countryCode;
                        }
                        break;
                    }
                }
            }
        });

        setLoad('Rendering visualization layers...', 95);

        // Charts
        const typeCount = {};
        iocs.forEach(i => { const t = i.ioc_type || 'unknown'; typeCount[t] = (typeCount[t]||0)+1; });
        renderIOCDistribution(typeCount);
        renderTypeBreakdown(typeCount, iocs.length);

        const yearCount = {};
        cves.forEach(c => { const y = (c.cve_id||'').split('-')[1]||'?'; yearCount[y]=(yearCount[y]||0)+1; });
        renderCVETrend(yearCount);

        // Bar charts
        renderBarChart('countryChart', countryCount, '#8b5cf6');   // Purple
        renderBarChart('iocSourcesChart', iocSourceCount, '#f59e0b'); // Amber
        renderBarChart('cveSourcesChart', cveSourceCount, '#10b981'); // Emerald

        // IOC section
        G_allIocs = iocs;
        buildTypeFilters(typeCount);
        buildSourceFilters(iocs);
        buildCountryFilters(countryCount, countryToCode);
        applyFilters();

        // CVE section
        G_allCves = cves.reverse();
        buildCveSourceFilters(cves);
        applyCveFilters();

        document.getElementById('cveSearch').addEventListener('input', e => {
            G_cvePage = 0;
            applyCveFilters();
        });

        document.getElementById('iocSearch').addEventListener('input', e => {
            G_query = e.target.value.toLowerCase().trim();
            G_page  = 0;
            applyFilters();
        });

        setupNavigation();
        setupModals();

        // [PHASE 1 & 2] Init Per-Source Dashboards
        initSourceDashboards(iocs, cves, syncData);

        setLoad('System Ready. Decrypting environment...', 100);
        
        setTimeout(() => {
            overlay.style.opacity = '0';
            setTimeout(() => overlay.style.display = 'none', 800);
        }, 600);

    } catch (err) {
        console.error(err);
        if (statusEl) {
            statusEl.innerHTML = `<span style="color:#f87171">Fatal Execution Error: ${err.message}</span>`;
        }
    }
});

/* ============================================================
   CHARTS
   ============================================================ */
function renderIOCDistribution(typeCount) {
    new Chart(document.getElementById('iocDistributionChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(typeCount),
            datasets: [{ data: Object.values(typeCount), borderWidth: 2, borderColor: '#0b0e14',
                backgroundColor: ['#8b5cf6','#f59e0b','#10b981','#f97316','#ef4444','#ec4899','#a855f7'] }]
        },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
    });
}

function renderTypeBreakdown(typeCount, total) {
    const row = document.getElementById('typeBreakdownRow');
    if (!row) return;
    const entries = Object.entries(typeCount).sort((a,b) => b[1]-a[1]);
    row.innerHTML = entries.map(([type, count]) => {
        const c = typeColor(type);
        const pct = total > 0 ? ((count/total)*100).toFixed(1) : 0;
        return `<div class="type-mini-card" style="--tmc-bg:${c.bg};--tmc-col:${c.col}">
            <span class="tmc-type">${type}</span>
            <span class="tmc-count">${count.toLocaleString()}</span>
            <span class="tmc-pct">${pct}%</span>
            <div class="tmc-bar"><div class="tmc-fill" style="width:${pct}%;background:${c.col}"></div></div>
        </div>`;
    }).join('');
}

function renderBarChart(canvasId, dataCount, bgColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const sorted = Object.entries(dataCount).sort((a,b) => b[1]-a[1]).slice(0, 7);
    const labels = sorted.map(x => x[0].length > 15 ? x[0].substring(0, 15) + '...' : x[0]);
    const data = sorted.map(x => x[1]);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ data: data, backgroundColor: bgColor, borderRadius: 4 }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(148,163,184,0.1)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function renderCVETrend(yearCount) {
    const yrs = Object.keys(yearCount).sort();
    new Chart(document.getElementById('cveTrendChart'), {
        type: 'line',
        data: {
            labels: yrs,
            datasets: [{ label:'CVEs', data: yrs.map(y=>yearCount[y]),
                borderColor:'#10b981', backgroundColor:'rgba(16, 185, 129, 0.1)',
                shadowBlur: 10, shadowColor: 'rgba(16, 185, 129, 0.5)',
                fill:true, tension:0.4 }]
        },
        options: { responsive:true, maintainAspectRatio:false,
            scales: { y:{grid:{color:'rgba(148,163,184,0.1)'},ticks:{color:'#94a3b8'}}, x:{ticks:{color:'#94a3b8'}} },
            plugins:{ legend:{display:false} } }
    });
}

/* ============================================================
   FILTER BARS
   ============================================================ */
function buildTypeFilters(typeCount) {
    const bar = document.getElementById('typeFilterBar');
    bar.innerHTML = '';

    const mkBtn = (label, type, c) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (type === null ? ' flt-active' : '');
        b.textContent = label;
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.onclick = () => {
            document.querySelectorAll('#typeFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeType = type;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Types', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    Object.keys(typeCount).sort().forEach(t => bar.appendChild(mkBtn(t, t, typeColor(t))));
}

function buildTagFilters(iocs) {
    const bar = document.getElementById('tagFilterBar');
    bar.innerHTML = '';

    // Collect unique non-null tags
    const tagSet = new Set();
    iocs.forEach(ioc => { if (Array.isArray(ioc.tags)) ioc.tags.forEach(t => t && tagSet.add(t)); });

    if (tagSet.size === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucun tag dans les données</span>';
        return;
    }

    const mkBtn = (label, tag, c) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (tag === null ? ' flt-active' : '');
        b.textContent = label;
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.dataset.tag = tag || '';
        b.onclick = () => {
            document.querySelectorAll('#tagFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeTag = tag;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Tags', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    [...tagSet].sort().forEach((t, i) => bar.appendChild(mkBtn(t, t, tagColor(i))));
}

function buildSourceFilters(iocs) {
    const bar = document.getElementById('sourceFilterBar');
    if (!bar) return;
    bar.innerHTML = '';

    // Count occurrences per source
    const srcCount = {};
    iocs.forEach(ioc => {
        if (Array.isArray(ioc.sources)) ioc.sources.forEach(s => { if(s) srcCount[s] = (srcCount[s]||0)+1; });
    });

    if (Object.keys(srcCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucune source dans les données</span>';
        return;
    }

    const SOURCE_PALETTE = [
        { bg:'rgba(96,165,250,0.18)',  col:'#60a5fa' },
        { bg:'rgba(52,211,153,0.18)',  col:'#34d399' },
        { bg:'rgba(251,146,60,0.18)',  col:'#fb923c' },
        { bg:'rgba(167,139,250,0.18)', col:'#a78bfa' },
        { bg:'rgba(244,114,182,0.18)', col:'#f472b6' },
        { bg:'rgba(56,189,248,0.18)',  col:'#38bdf8' },
        { bg:'rgba(251,191,36,0.18)',  col:'#fbbf24' },
        { bg:'rgba(248,113,113,0.18)', col:'#f87171' },
    ];
    const srcColor = i => SOURCE_PALETTE[i % SOURCE_PALETTE.length];

    const mkBtn = (label, src, c, badge) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (src === null ? ' flt-active' : '');
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.dataset.src = src || '';
        b.innerHTML = `${label}${badge ? `<span class="flt-badge">${badge.toLocaleString()}</span>` : ''}`;
        b.onclick = () => {
            document.querySelectorAll('#sourceFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeSource = src;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Sources', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    // Sort by count descending
    Object.entries(srcCount)
        .sort((a,b) => b[1]-a[1])
        .forEach(([s, cnt], i) => bar.appendChild(mkBtn(s, s, srcColor(i), cnt)));
}

function buildCountryFilters(countryCount, countryToCode) {
    const bar = document.getElementById('countryFilterBar');
    if (!bar) return;
    bar.innerHTML = '';
    if (Object.keys(countryCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucun pays dans les données</span>';
        return;
    }
    const mkBtn = (label, country, badge, code) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (country === null ? ' flt-active' : '');
        b.style.cssText = `--fb:rgba(47,128,237,0.18);--fc:#60a5fa;display:inline-flex;align-items:center;gap:4px;`;
        let flagHtml = (code && code.length === 2) ? `<img src="https://flagcdn.com/w20/${code.toLowerCase()}.png" width="14" alt="${esc(code)}" style="border-radius:1px;">` : '';
        let displayLabel = (code && code.length >= 2 && code.length <= 3) ? code.toUpperCase() : label;
        b.innerHTML = `${flagHtml}<span>${esc(displayLabel)}</span>${badge ? `<span class="flt-badge">${badge.toLocaleString()}</span>` : ''}`;
        b.onclick = () => {
            document.querySelectorAll('#countryFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeCountry = country;
            G_page = 0;
            applyFilters();
        };
        return b;
    };
    bar.appendChild(mkBtn('Tous les pays', null));
    Object.entries(countryCount).sort((a,b) => b[1]-a[1]).slice(0, 20).forEach(([c, cnt]) => bar.appendChild(mkBtn(c, c, cnt, countryToCode[c])));
}

function buildCveSourceFilters(cves) {
    const bar = document.getElementById('cveSourceFilterBar');
    if (!bar) return;
    bar.innerHTML = '';

    // Count occurrences per source
    const srcCount = {};
    cves.forEach(cve => {
        if (Array.isArray(cve.sources)) cve.sources.forEach(s => { if(s) srcCount[s] = (srcCount[s]||0)+1; });
    });

    if (Object.keys(srcCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucune source dans les données</span>';
        return;
    }

    const SOURCE_PALETTE = [
        { bg:'rgba(167,139,250,0.18)', col:'#a78bfa' },
        { bg:'rgba(96,165,250,0.18)',  col:'#60a5fa' },
        { bg:'rgba(52,211,153,0.18)',  col:'#34d399' },
        { bg:'rgba(251,146,60,0.18)',  col:'#fb923c' },
        { bg:'rgba(244,114,182,0.18)', col:'#f472b6' },
        { bg:'rgba(56,189,248,0.18)',  col:'#38bdf8' },
        { bg:'rgba(251,191,36,0.18)',  col:'#fbbf24' },
        { bg:'rgba(248,113,113,0.18)', col:'#f87171' },
    ];
    const srcColor = i => SOURCE_PALETTE[i % SOURCE_PALETTE.length];

    const mkBtn = (label, src, c, badge) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (src === null ? ' flt-active' : '');
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.dataset.src = src || '';
        b.innerHTML = `${label}${badge ? `<span class="flt-badge">${badge.toLocaleString()}</span>` : ''}`;
        b.onclick = () => {
            document.querySelectorAll('#cveSourceFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeCveSource = src;
            G_cvePage = 0;
            applyCveFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Sources', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    // Sort by count descending
    Object.entries(srcCount)
        .sort((a,b) => b[1]-a[1])
        .forEach(([s, cnt], i) => bar.appendChild(mkBtn(s, s, srcColor(i), cnt)));
}

/* ============================================================
   FILTER + PAGINATION ENGINE
   ============================================================ */
function applyFilters() {
    G_filtered = G_allIocs.filter(ioc => {
        // text search
        if (G_query) {
            const v = (ioc.value       || '').toLowerCase();
            const t = (ioc.ioc_type    || '').toLowerCase();
            const s = Array.isArray(ioc.sources) ? ioc.sources.join(' ').toLowerCase() : '';
            const g = Array.isArray(ioc.tags)    ? ioc.tags.join(' ').toLowerCase()    : '';
            if (!v.includes(G_query) && !t.includes(G_query) && !s.includes(G_query) && !g.includes(G_query)) return false;
        }
        // type filter
        if (G_activeType !== null && (ioc.ioc_type || 'unknown') !== G_activeType) return false;
        // source filter
        if (G_activeSource !== null) {
            if (!Array.isArray(ioc.sources) || !ioc.sources.includes(G_activeSource)) return false;
        }
        // country filter
        if (G_activeCountry !== null) {
            let matchesCountry = false;
            if (Array.isArray(ioc.contexts)) {
                for (let c of ioc.contexts) {
                    if (c && (c.countryName || c.countryCode)) {
                        let cname = c.countryName || c.countryCode;
                        if (cname === G_activeCountry) matchesCountry = true;
                        break;
                    }
                }
            }
            if (!matchesCountry) return false;
        }
        return true;
    });

    renderPage();
    renderPaginator();
}

function renderPage() {
    const tbody  = document.getElementById('iocTableBody');
    const start  = G_page * PAGE_SIZE;
    const slice  = G_filtered.slice(start, start + PAGE_SIZE);
    G_currentPageIocs = slice;

    // results count
    const rc = document.getElementById('iocResultsCount');
    if (rc) rc.textContent = `${G_filtered.length.toLocaleString()} résultats`;

    tbody.innerHTML = slice.map((ioc, i) => {
        const tc  = typeColor(ioc.ioc_type);
        const src = Array.isArray(ioc.sources) ? ioc.sources.join(', ') : '—';
        const tgs = Array.isArray(ioc.tags)  && ioc.tags.length
            ? `<div class="pill-container">${ioc.tags.map((t, j) => {
                const c = tagColor(j);
                return `<span class="tag-pill" style="background:${c.bg};color:${c.col}">${esc(t)}</span>`;
              }).join('')}</div>`
            : '<span style="color:#475569">—</span>';

        let locationHtml = '<span style="color:#475569">—</span>';
        if (Array.isArray(ioc.contexts)) {
            for (let c of ioc.contexts) {
                if (c && (c.countryName || c.countryCode)) {
                    let cname = c.countryName || c.countryCode;
                    let ccode = c.countryCode;
                    let isp = c.isp || '';
                    let flag = (ccode && ccode.length === 2) 
                        ? `<img src="https://flagcdn.com/w20/${ccode.toLowerCase()}.png" width="16" alt="${esc(ccode)}">` 
                        : '';
                    let displayCode = ccode && (ccode.length === 2 || ccode.length === 3) ? ccode.toUpperCase() : cname;
                    locationHtml = `<div class="location-pill">${flag}${esc(displayCode)}</div>`;
                    break;
                }
            }
        }

        return `<tr onclick="openIOCModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#60a5fa;font-weight:600;font-family:monospace;font-size:0.82rem;">${esc(ioc.value)}</td>
            <td><span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></td>
            <td>${locationHtml}</td>
            <td style="color:#94a3b8;font-size:0.74rem">${esc(src)}</td>
            <td>${tgs}</td>
        </tr>`;
    }).join('');
}

function renderPaginator() {
    const el    = document.getElementById('iocPaginator');
    const total = G_filtered.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    if (!el) return;
    if (pages <= 1) { el.innerHTML = ''; return; }

    const cur = G_page;
    const WIN = 5;
    let lo = Math.max(0, cur - Math.floor(WIN/2));
    let hi = Math.min(pages - 1, lo + WIN - 1);
    if (hi - lo < WIN - 1) lo = Math.max(0, hi - WIN + 1);

    const btn = (label, page, active=false, disabled=false) =>
        `<button class="pg-btn${active?' pg-active':''}" ${disabled?'disabled':''} onclick="goPage(${page})">${label}</button>`;

    let html = btn('‹', cur-1, false, cur===0);

    if (lo > 0) { html += btn('1', 0); if (lo > 1) html += '<span class="pg-dots">…</span>'; }
    for (let p = lo; p <= hi; p++) html += btn(p+1, p, p===cur);
    if (hi < pages-1) { if (hi < pages-2) html += '<span class="pg-dots">…</span>'; html += btn(pages, pages-1); }

    html += btn('›', cur+1, false, cur===pages-1);

    const s = cur*PAGE_SIZE+1, e = Math.min((cur+1)*PAGE_SIZE, total);
    el.innerHTML = `<span class="pg-info">${s.toLocaleString()}–${e.toLocaleString()} / ${total.toLocaleString()}</span>
                    <div class="pg-btns">${html}</div>`;
}

function goPage(p) {
    G_page = p;
    renderPage();
    renderPaginator();
    document.getElementById('iocTableBody').closest('.table-container')
        .scrollIntoView({ behavior:'smooth', block:'start' });
}

/* ============================================================
   IOC MODAL
   ============================================================ */
function openIOCModal(i) {
    const ioc = G_currentPageIocs[i];
    if (!ioc) return;

    const modal = document.getElementById('ioc-modal');
    const body  = document.getElementById('modal-body');

    const tc   = typeColor(ioc.ioc_type);
    const src  = Array.isArray(ioc.sources)  ? ioc.sources  : [];
    const tags = Array.isArray(ioc.tags)      ? ioc.tags.filter(Boolean) : [];
    const pts  = Array.isArray(ioc.ports)     ? ioc.ports    : [];
    const ctx  = Array.isArray(ioc.contexts)  ? ioc.contexts : [];

    const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;
    const linkCve = s => String(s).replace(CVE_RE, m =>
        `<span class="cve-link" onclick="jumpToCve('${m.toUpperCase()}')">${m}</span>`);

    const renderCtxVal = v => {
        if (v === null || v === undefined) return '<em style="color:#475569">null</em>';
        if (typeof v === 'object') return `<pre class="ctx-pre">${esc(JSON.stringify(v,null,2))}</pre>`;
        return linkCve(esc(String(v)));
    };
    const renderCtx = c => {
        if (typeof c !== 'object' || !c) return `<div class="ctx-box"><pre>${linkCve(esc(String(c)))}</pre></div>`;
        return `<div class="ctx-box">${Object.entries(c).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${renderCtxVal(v)}</span></div>`
        ).join('')}</div>`;
    };

    let cname = 'N/A', isp = 'N/A', usage = 'N/A', abuseScore = 'N/A', ccode = null;
    if (Array.isArray(ioc.contexts)) {
        for (let c of ioc.contexts) {
            if (c) {
                if (c.countryName || c.countryCode) {
                    cname = c.countryName || c.countryCode;
                    ccode = c.countryCode;
                }
                if (c.isp) isp = c.isp;
                if (c.usageType) usage = c.usageType;
                if (c.abuseConfidenceScore != null) abuseScore = c.abuseConfidenceScore + '%';
            }
        }
    }

    let countryHtml = esc(cname);
    if (ccode && ccode.length === 2 && cname !== 'N/A') {
        let flag = `<img src="https://flagcdn.com/w20/${ccode.toLowerCase()}.png" width="18" alt="${esc(ccode)}" style="margin-right:6px;vertical-align:middle;border-radius:2.5px;box-shadow:0 0 2px rgba(0,0,0,0.5);">`;
        countryHtml = `<div style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.06);padding:0.3rem 0.6rem;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">${flag} <span>${esc(cname)}</span></div>`;
    } else if (cname !== 'N/A') {
        countryHtml = `<div style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.06);padding:0.3rem 0.6rem;border-radius:6px;border:1px solid rgba(255,255,255,0.08);"><span>${esc(cname)}</span></div>`;
    }

    body.innerHTML = `
      <div class="dr">
        <div class="dl">Valeur</div>
        <div style="color:#60a5fa;font-weight:700;font-size:1.35rem;font-family:monospace;word-break:break-all">${esc(ioc.value)}</div>
      </div>
      <div class="dg4">
        <div class="dr"><div class="dl">Type</div>
          <span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></div>
        <div class="dr"><div class="dl">Score Abus</div>
          <div>${abuseScore}</div></div>
        <div class="dr"><div class="dl">Pays</div>
          <div>${countryHtml}</div></div>
        <div class="dr"><div class="dl">ISP / FAI</div>
          <div>${esc(isp)}</div></div>
      </div>
      <!-- Add a second grid to avoid breaking the 4-column layout if it gets too wide -->
      <div class="dg4" style="margin-top:-0.5rem">
        <div class="dr"><div class="dl">Confiance</div>
          <div>${ioc.confidence!=null ? ioc.confidence+'%' : 'N/A'}</div></div>
        <div class="dr"><div class="dl">Usage</div>
          <div>${esc(usage)}</div></div>
        <div class="dr"><div class="dl">Première vue</div>
          <div style="font-size:0.85rem">${ioc.first_seen ? fmtDate(ioc.first_seen) : 'N/A'}</div></div>
        <div class="dr"><div class="dl">Dernière vue</div>
          <div style="font-size:0.85rem">${ioc.last_seen ? fmtDate(ioc.last_seen) : 'N/A'}</div></div>
      </div>
      <div class="dr">
        <div class="dl">Ports</div>
        <div>${pts.length ? pts.map(p=>`<span class="port-pill">${p}</span>`).join('') : '<span style="color:#475569">Aucun port</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Sources</div>
        <div>${src.length ? src.map(s=>`<span class="src-pill">${esc(s)}</span>`).join('') : '<span style="color:#475569">N/A</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Tags</div>
        <div>${tags.length ? tags.map((t,i)=>{const c=tagColor(i);return`<span class="tag-pill" style="background:${c.bg};color:${c.col};cursor:pointer"
              onclick="filterByTagFromModal('${esc(t)}')" title="Filtrer par ce tag">${esc(t)}</span>`;}).join('') : '<span style="color:#475569">Aucun tag</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Contextes</div>
        <div>${ctx.length ? ctx.map(renderCtx).join('') : '<span style="color:#475569">Pas de contexte</span>'}</div>
      </div>`;

    modal.classList.add('active');
}


/* ============================================================
   CVE TABLE + MODAL
   ============================================================ */
function renderCVETable() {
    const tbody = document.getElementById('cveTableBody');
    const start = G_cvePage * PAGE_SIZE;
    const slice = G_filteredCves.slice(start, start + PAGE_SIZE);
    G_visibleCves = slice;

    const rc = document.getElementById('cveResultsCount');
    if (rc) rc.textContent = `${G_filteredCves.length.toLocaleString()} résultats`;

    tbody.innerHTML = slice.map((cve, i) => {
        const yr  = (cve.cve_id||'').split('-')[1]||'N/A';
        const sev = cve.severity || 'N/A';
        const sc  = sevClass(sev);
        const scoop = cve.score != null ? cve.score.toFixed(1) : 'N/A';
        const scc = scoreClass(cve.score);
        const src = Array.isArray(cve.sources) ? cve.sources.join(', ') : 'N/A';
        const dt  = cve.published_date ? fmtDate(cve.published_date) : 'N/A';
        return `<tr onclick="openCVEModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#a78bfa;font-weight:600;font-family:monospace">${esc(cve.cve_id||'N/A')}</td>
            <td>${yr}</td>
            <td><span class="sev-pill ${sc}">${sev}</span></td>
            <td><span class="score-pill ${scc}">${scoop}</span></td>
            <td style="color:#94a3b8;font-size:0.74rem">${esc(src)}</td>
            <td style="color:#94a3b8;font-size:0.74rem">${dt}</td>
        </tr>`;
    }).join('');
}

function applyCveFilters() {
    const q = document.getElementById('cveSearch').value.toLowerCase().trim();
    G_filteredCves = G_allCves.filter(c => {
        // source filter
        if (G_activeCveSource !== null) {
            if (!Array.isArray(c.sources) || !c.sources.includes(G_activeCveSource)) return false;
        }

        if (!q) return true;
        return (c.cve_id   || '').toLowerCase().includes(q) ||
               (c.severity || '').toLowerCase().includes(q) ||
               (Array.isArray(c.sources) && c.sources.some(s => s.toLowerCase().includes(q)));
    });
    renderCvePage();
}

function renderCvePage() {
    renderCVETable();
    renderCvePaginator();
}

function renderCvePaginator() {
    const el    = document.getElementById('cvePaginator');
    const total = G_filteredCves.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    if (!el) return;
    if (pages <= 1) { el.innerHTML = ''; return; }

    const cur = G_cvePage;
    const WIN = 5;
    let lo = Math.max(0, cur - Math.floor(WIN/2));
    let hi = Math.min(pages - 1, lo + WIN - 1);
    if (hi - lo < WIN - 1) lo = Math.max(0, hi - WIN + 1);

    const btn = (label, page, active=false, disabled=false) =>
        `<button class="pg-btn${active?' pg-active':''}" ${disabled?'disabled':''} onclick="goCvePage(${page})">${label}</button>`;

    let html = btn('‹', cur-1, false, cur===0);

    if (lo > 0) { html += btn('1', 0); if (lo > 1) html += '<span class="pg-dots">…</span>'; }
    for (let p = lo; p <= hi; p++) html += btn(p+1, p, p===cur);
    if (hi < pages-1) { if (hi < pages-2) html += '<span class="pg-dots">…</span>'; html += btn(pages, pages-1); }

    html += btn('›', cur+1, false, cur===pages-1);

    const s = cur*PAGE_SIZE+1, e = Math.min((cur+1)*PAGE_SIZE, total);
    el.innerHTML = `<span class="pg-info">${s.toLocaleString()}–${e.toLocaleString()} / ${total.toLocaleString()}</span>
                    <div class="pg-btns">${html}</div>`;
}

function goCvePage(p) {
    G_cvePage = p;
    renderCvePage();
    document.getElementById('cveTableBody').closest('.table-container')
        .scrollIntoView({ behavior:'smooth', block:'start' });
}

function openCVEModal(i) {
    const cve = G_visibleCves[i];
    if (!cve) return;

    const modal = document.getElementById('cve-modal');
    const body  = document.getElementById('cve-modal-body');
    const src   = Array.isArray(cve.sources) ? cve.sources : [];
    const cvss  = Array.isArray(cve.cvss) ? cve.cvss : (cve.cvss ? [cve.cvss] : []);
    const ctx   = Array.isArray(cve.contexts) ? cve.contexts : [];
    const sev   = cve.severity||'N/A';
    const sc    = sevClass(sev);
    const score = cve.score != null ? cve.score.toFixed(1) : 'N/A';
    const scc   = scoreClass(cve.score);

    const renderCvssEntry = e => {
        if (typeof e !== 'object') return `<span>${esc(String(e))}</span>`;
        return `<div class="ctx-box">${Object.entries(e).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${esc(String(v))}</span></div>`).join('')}</div>`;
    };
    const renderCtx = c => {
        if (typeof c!=='object'||!c) return `<div class="ctx-box">${esc(String(c))}</div>`;
        return `<div class="ctx-box">${Object.entries(c).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${typeof v==='object'?`<pre class="ctx-pre">${esc(JSON.stringify(v,null,2))}</pre>`:esc(String(v))}</span></div>`).join('')}</div>`;
    };

    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1.5rem">
        <div>
          <div class="dl">CVE Identifiant</div>
          <div style="color:#a78bfa;font-weight:700;font-size:1.6rem;font-family:monospace">${esc(cve.cve_id||'N/A')}</div>
        </div>
        <div style="text-align:right">
          <div class="dl">CVSS Score</div>
          <div class="score-pill ${scc}" style="font-size:1.5rem; padding:.4rem .8rem">${score}</div>
        </div>
      </div>

      <div class="dr">
         <div class="dl">Description</div>
         <div class="description-box">${esc(cve.description || 'Aucune description disponible pour cette vulnérabilité.')}</div>
      </div>

      <div class="dg4">
        <div class="dr"><div class="dl">Sévérité</div>
          <span class="sev-pill ${sc}" style="font-size:0.9rem">${sev}</span></div>
        <div class="dr"><div class="dl">Année</div>
          <div>${(cve.cve_id||'').split('-')[1]||'N/A'}</div></div>
        <div class="dr"><div class="dl">Publication</div>
          <div style="font-size:0.85rem">${cve.published_date ? fmtDate(cve.published_date) : 'N/A'}</div></div>
      </div>

      <div class="dr">
        <div class="dl">Sources</div>
        <div>${src.length ? src.map(s=>`<span class="src-pill">${esc(s)}</span>`).join('') : '<span style="color:#475569">N/A</span>'}</div>
      </div>

      <div class="dr">
        <div class="dl">Détails CVSS</div>
        <div>${cvss.length ? cvss.map(renderCvssEntry).join('') : '<span style="color:#475569">Pas de CVSS</span>'}</div>
      </div>

      <div class="dr">
        <div class="dl">Contextes (Auto-extraction)</div>
        <div>${ctx.length ? ctx.map(renderCtx).join('') : '<span style="color:#475569">Pas de contexte</span>'}</div>
      </div>`;

    modal.classList.add('active');
}

/* ============================================================
   JUMP TO CVE FROM IOC CONTEXT
   ============================================================ */
function jumpToCve(cveId) {
    document.getElementById('ioc-modal').classList.remove('active');
    document.querySelectorAll('.sidebar nav li').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.dashboard-section').forEach(s => s.classList.remove('active'));
    document.querySelector('[data-section="cves"]').classList.add('active');
    document.getElementById('cves').classList.add('active');
    document.getElementById('section-title').innerText = 'CVEs';
    const input = document.getElementById('cveSearch');
    input.value = cveId;
    input.dispatchEvent(new Event('input'));
}

/* ============================================================
   MODALS SETUP
   ============================================================ */
function setupModals() {
    const iocM = document.getElementById('ioc-modal');
    const cveM = document.getElementById('cve-modal');
    document.getElementById('close-modal').onclick     = () => iocM.classList.remove('active');
    document.getElementById('close-cve-modal').onclick = () => cveM.classList.remove('active');
    window.addEventListener('click', e => {
        if (e.target === iocM) iocM.classList.remove('active');
        if (e.target === cveM) cveM.classList.remove('active');
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { iocM.classList.remove('active'); cveM.classList.remove('active'); }
    });
}

/* ============================================================
   NAVIGATION
   ============================================================ */
function setupNavigation() {
    const items    = document.querySelectorAll('.sidebar nav li');
    const sections = document.querySelectorAll('.dashboard-section');
    const title    = document.getElementById('section-title');
    items.forEach(item => item.addEventListener('click', () => {
        items.forEach(i   => i.classList.remove('active'));
        sections.forEach(s => s.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(item.dataset.section).classList.add('active');
        title.innerText = item.innerText.trim();
    }));
}

/* ============================================================
   HELPERS
   ============================================================ */
function esc(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDate(s) {
    try { return new Date(s).toLocaleString('fr-FR',{dateStyle:'medium',timeStyle:'short'}); }
    catch { return String(s); }
}
function sevClass(s) {
    const u = (s||'').toUpperCase();
    if (u==='CRITICAL') return 'sev-c';
    if (u==='HIGH')     return 'sev-h';
    if (u==='MEDIUM')   return 'sev-m';
    if (u==='LOW')      return 'sev-l';
    return 'sev-n';
}

function scoreClass(s) {
    const n = parseFloat(s);
    if (isNaN(n) || n === 0) return 'sc-n';
    if (n >= 9.0) return 'sc-c';
    if (n >= 7.0) return 'sc-h';
    if (n >= 4.0) return 'sc-m';
    return 'sc-l';
}
/* ============================================================
   PER-SOURCE DASHBOARDS [PHASE 1 & 2]
   ============================================================ */
function initSourceDashboards(allIocs, allCves, syncData) {
    const tabBar = document.getElementById('sourceTabBar');
    const panels = document.getElementById('sourcePanels');
    const sideList = document.getElementById('sidebarSourceList');

    if (!tabBar || !panels) return;

    tabBar.innerHTML = '';
    panels.innerHTML = '';
    if (sideList) {
        sideList.innerHTML = '<div class="sidebar-sources-title">Sources Nodes</div>';
    }

    const sourceIds = Object.keys(SOURCES_CONFIG);

    sourceIds.forEach((id, idx) => {
        const cfg = SOURCES_CONFIG[id];
        
        // Count entries for this source
        const sIocs = allIocs.filter(i => Array.isArray(i.sources) && i.sources.includes(id));
        const sCves = allCves.filter(c => Array.isArray(c.sources) && c.sources.includes(id));
        const total = sIocs.length + sCves.length;

        // 1. Create Tab
        const tab = document.createElement('div');
        tab.className = `src-tab ${idx === 0 ? 'active' : ''}`;
        tab.dataset.source = id;
        tab.innerHTML = `
            <i data-lucide="${cfg.icon}" style="width:14px;height:14px;"></i>
            <span>${cfg.label}</span>
            <span class="tab-badge">${total.toLocaleString()}</span>
        `;
        tab.onclick = () => switchSourceTab(id);
        tabBar.appendChild(tab);

        // 2. Create Sidebar Item (Optional but nice)
        if (sideList) {
            const ss = document.createElement('div');
            ss.className = 'ss-item';
            ss.innerHTML = `
                <div class="ss-dot" style="background:${idx % 2 === 0 ? 'var(--primary)' : 'var(--secondary)'}"></div>
                <span>${cfg.label}</span>
                <span class="ss-badge">${total.toLocaleString()}</span>
            `;
            ss.onclick = () => {
                // Switch to sources section then select this tab
                document.querySelector('[data-section="sources"]').click();
                switchSourceTab(id);
            };
            sideList.appendChild(ss);
        }

        // 3. Create Panel
        const panel = document.createElement('div');
        panel.className = `source-panel ${idx === 0 ? 'active' : ''} ${cfg.theme}`;
        panel.id = `panel-${id}`;
        panel.innerHTML = `
            <div class="sp-header">
                <div class="sp-icon" style="background:var(--sp-bg); color:var(--sp-accent)">
                    <i data-lucide="${cfg.icon}"></i>
                </div>
                <div class="sp-meta">
                    <div style="display:flex; align-items:center; gap:0.6rem;">
                        <h2>${cfg.label} Dashboard</h2>
                        <div class="ss-dot" id="dot-${id}" style="background:var(--txt3); width:8px; height:8px;"></div>
                    </div>
                    <p>Source Node: ${id}_extractor.py | Status: Active Data Stream</p>
                </div>
                <div class="sp-stats" style="margin-right:1rem;">
                    <div class="sp-stat-item"><div class="sp-stat-val">${sIocs.length.toLocaleString()}</div><div class="sp-stat-lbl">IOCs</div></div>
                    <div class="sp-stat-item"><div class="sp-stat-val">${sCves.length.toLocaleString()}</div><div class="sp-stat-lbl">CVEs</div></div>
                </div>
                <div style="display:flex; flex-direction:column; gap:0.4rem; align-items:flex-end;">
                    <button class="flt-btn" onclick="runSourceScript('${id}')" id="btn-run-${id}" style="background:var(--primary); color:#fff; border:none; padding: 0.5rem 1rem; border-radius:8px; font-weight:700; display:flex; align-items:center; gap:0.5rem;">
                        <i data-lucide="play" style="width:14px;height:14px;"></i> Lancer
                    </button>
                    <label style="display:flex; align-items:center; gap:0.4rem; font-size:0.65rem; color:var(--txt2); cursor:pointer;">
                        <input type="checkbox" id="chk-full-${id}" style="accent-color:var(--primary);"> 
                        Extraction Complète
                    </label>
                </div>
            </div>
            
            <div id="log-container-${id}" style="display:none; margin-bottom:1.5rem; background:#020617; border:1px solid var(--brd); border-radius:12px; overflow:hidden;">
                <div style="padding:0.5rem 1rem; background:rgba(255,255,255,0.03); border-bottom:1px solid var(--brd); font-size:0.7rem; color:var(--txt2); display:flex; justify-content:space-between;">
                    <span>Terminal - ${id}_extractor.py</span>
                    <span id="log-status-${id}">INITIALIZING</span>
                </div>
                <div id="log-${id}" style="padding:1rem; max-height:150px; overflow-y:auto; font-family:monospace; font-size:0.75rem; color:#34d399; line-height:1.5;"></div>
            </div>

            <div class="sp-body" id="sp-body-${id}">
                <div class="empty-state"><i data-lucide="loader-2" class="spin"></i><p>Initialisation de la vue source...</p></div>
            </div>
        `;
        panels.appendChild(panel);
    });

    lucide.createIcons();

    // Render first source if exists
    if (sourceIds.length > 0) {
        renderSourceDashboard(sourceIds[0]);
    }
}

function switchSourceTab(id) {
    document.querySelectorAll('.src-tab').forEach(t => t.classList.toggle('active', t.dataset.source === id));
    document.querySelectorAll('.source-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${id}`));
    renderSourceDashboard(id);
}

/* ============================================================
   PER-SOURCE DASHBOARDS [PHASE 3]
   ============================================================ */
const G_sourceState = {}; // cache filtered lists { iocs: [], cves: [] }

function renderSourceDashboard(id) {
    console.log(`Rendering Dashboard for ${id}`);
    const body = document.getElementById(`sp-body-${id}`);
    if (!body) return;

    // 1. Get/Cache Source Data
    if (!G_sourceState[id]) {
        G_sourceState[id] = {
            iocs: G_allIocs.filter(i => Array.isArray(i.sources) && i.sources.includes(id)),
            cves: G_allCves.filter(c => Array.isArray(c.sources) && c.sources.includes(id)),
            query: ''
        };
    }

    const { iocs, cves } = G_sourceState[id];

    // 2. Setup Base UI (only once)
    if (body.dataset.rendered !== 'true') {
        body.innerHTML = `
            <div class="charts-grid" style="grid-template-columns: 1fr; margin-bottom: 2rem; height: 180px;">
                <div class="chart-container" style="height: 100%;">
                    <h3>Distribution des Indicateurs / Sévérité</h3>
                    <canvas id="sourceChart-${id}"></canvas>
                </div>
            </div>
            <div class="sp-toolbar">
                <input type="text" placeholder="Rechercher dans ${id}..." oninput="filterSourceData('${id}', this.value)">
                <span class="results-count" id="count-${id}">${(iocs.length + cves.length).toLocaleString()} records</span>
            </div>
            <div class="sp-cards-grid" id="grid-${id}">
                <div class="empty-state"><p>Génération des modules de données...</p></div>
            </div>
        `;
        body.dataset.rendered = 'true';
        
        // Render Chart
        renderSourceSpecificChart(id, iocs, cves);
    }

    // 3. Render Cards
    renderSourceCards(id);
}

function renderSourceSpecificChart(id, iocs, cves) {
    const canvas = document.getElementById(`sourceChart-${id}`);
    if (!canvas) return;

    let labels = [], data = [], colors = [];

    if (iocs.length > 0) {
        const typeMap = {};
        iocs.forEach(i => { const t = i.ioc_type || 'unknown'; typeMap[t] = (typeMap[t]||0)+1; });
        labels = Object.keys(typeMap);
        data = Object.values(typeMap);
        colors = labels.map(t => typeColor(t).col);
    } else if (cves.length > 0) {
        const sevMap = {};
        cves.forEach(c => { const s = c.severity || 'UNKNOWN'; sevMap[s] = (sevMap[s]||0)+1; });
        labels = Object.keys(sevMap);
        data = Object.values(sevMap);
        colors = labels.map(s => {
            if (s === 'CRITICAL') return '#f87171';
            if (s === 'HIGH') return '#fb923c';
            if (s === 'MEDIUM') return '#fbbf24';
            if (s === 'LOW') return '#34d399';
            return '#94a3b8';
        });
    }

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ data: data, backgroundColor: colors, borderRadius: 6 }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(148,163,184,0.05)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11, weight: '600' } } }
            }
        }
    });
}

function filterSourceData(id, val) {
    G_sourceState[id].query = val.toLowerCase().trim();
    renderSourceCards(id);
}

function renderSourceCards(id) {
    const grid = document.getElementById(`grid-${id}`);
    const countEl = document.getElementById(`count-${id}`);
    if (!grid) return;

    const { iocs, cves, query } = G_sourceState[id];
    
    // Filter
    const filteredIocs = iocs.filter(i => !query || (i.value||'').toLowerCase().includes(query) || (i.ioc_type||'').toLowerCase().includes(query));
    const filteredCves = cves.filter(c => !query || (c.cve_id||'').toLowerCase().includes(query) || (c.description||'').toLowerCase().includes(query));
    
    const combined = [...filteredIocs, ...filteredCves].slice(0, 100); // Limit to 100 for performance
    
    if (countEl) countEl.innerText = `${(filteredIocs.length + filteredCves.length).toLocaleString()} records`;

    if (combined.length === 0) {
        grid.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;"><i data-lucide="search-x"></i><p>Aucun résultat pour "${esc(query)}"</p></div>`;
        lucide.createIcons();
        return;
    }

    grid.innerHTML = combined.map((item, idx) => {
        if (item.cve_id) return renderCveCardTemplate(item);
        return renderIocCardTemplate(item, id);
    }).join('');

    lucide.createIcons();
}

function renderIocCardTemplate(ioc, sourceId) {
    const tc = typeColor(ioc.ioc_type);
    const date = ioc.last_seen ? fmtDate(ioc.last_seen) : (ioc.first_seen ? fmtDate(ioc.first_seen) : 'N/A');
    
    // Specific metadata from context
    let country = 'N/A', extra = '';
    if (ioc.contexts && ioc.contexts[0]) {
        const ctx = ioc.contexts[0];
        if (ctx.countryCode || ctx.countryName) country = ctx.countryName || ctx.countryCode;
        if (ctx.abuseConfidenceScore) extra = `<div class="sp-card-row"><span class="k">Abuse Score</span><span class="v" style="color:#f87171">${ctx.abuseConfidenceScore}%</span></div>`;
        if (ctx.threatType) extra += `<div class="sp-card-row"><span class="k">Threat</span><span class="v">${ctx.threatType}</span></div>`;
    }

    // Determine card class based on source
    let cardClass = 'sp-card';
    if (sourceId === 'phishtank' || sourceId === 'openphish') cardClass += ' phish-card';
    if (sourceId === 'malwarebazaar' || sourceId === 'threatfox') cardClass += ' hash-card';

    return `
        <div class="${cardClass}" onclick="openIOCFromSource('${esc(ioc.value)}')">
            <div class="sp-card-value">${esc(ioc.value)}</div>
            <div class="sp-card-row">
                <span class="type-pill" style="background:${tc.bg}; color:${tc.col}; font-size:0.6rem; padding: 0.1rem 0.4rem;">${ioc.ioc_type}</span>
                <span style="font-size:0.65rem; color:var(--txt2)">${date}</span>
            </div>
            <div class="sp-card-row"><span class="k">Pays</span><span class="v">${esc(country)}</span></div>
            ${extra}
            <div class="sp-card-tags">
                ${(ioc.tags||[]).slice(0,3).map(t => `<span class="tag-pill" style="font-size:0.6rem; padding:0.1rem 0.4rem; background:rgba(255,255,255,0.05); color:var(--txt2)">${esc(t)}</span>`).join('')}
            </div>
        </div>
    `;
}

function renderCveCardTemplate(cve) {
    const sev = cve.severity || 'N/A';
    const sc = sevClass(sev);
    const score = cve.score != null ? cve.score.toFixed(1) : 'N/A';
    const scc = scoreClass(cve.score);
    
    return `
        <div class="nvd-card" onclick="openCVEFromSource('${esc(cve.cve_id)}')">
            <div class="nvd-card-id">${esc(cve.cve_id)}</div>
            <div class="nvd-card-desc">${esc(cve.description || 'N/A')}</div>
            <div class="nvd-card-footer">
                <span class="sev-pill ${sc}" style="font-size:0.6rem; padding:0.1rem 0.4rem;">${sev}</span>
                <span class="score-pill ${scc}" style="font-size:0.6rem; padding:0.1rem 0.4rem;">CVSS: ${score}</span>
                <span style="font-size:0.65rem; color:var(--txt2); margin-left:auto;">${cve.published_date ? fmtDate(cve.published_date) : ''}</span>
            </div>
        </div>
    `;
}

function openIOCFromSource(val) {
    // Navigate back to global IOC list and find it
    const iocIndex = G_allIocs.findIndex(i => i.value === val);
    if (iocIndex !== -1) {
        // We'll just open the modal directly for simplicity
        const ioc = G_allIocs[iocIndex];
        // Prepare G_currentPageIocs so the modal can find it
        G_currentPageIocs = [ioc];
        openIOCModal(0);
    }
}

function openCVEFromSource(id) {
    const cveIndex = G_allCves.findIndex(c => c.cve_id === id);
    if (cveIndex !== -1) {
        const cve = G_allCves[cveIndex];
        G_visibleCves = [cve];
        openCVEModal(0);
    }
}

/* ============================================================
   RUN SCRIPT INTEGRATION
   ============================================================ */
async function runSourceScript(id) {
    const btn = document.getElementById(`btn-run-${id}`);
    const logContainer = document.getElementById(`log-container-${id}`);
    const logArea = document.getElementById(`log-${id}`);
    const statusLabel = document.getElementById(`log-status-${id}`);
    const dot = document.getElementById(`dot-${id}`);
    const chkFull = document.getElementById(`chk-full-${id}`);

    if (!btn || !logArea) return;

    const isFull = chkFull ? chkFull.checked : false;

    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader-2" class="spin" style="width:14px;height:14px;"></i> En cours...`;
    logContainer.style.display = 'block';
    logArea.innerHTML = `> Starting node ${id}_extractor.py (Mode: ${isFull ? 'FULL' : 'INCREMENTAL'})...\n`;
    statusLabel.innerText = 'RUNNING';
    statusLabel.style.color = '#fbbf24';
    if(dot) { dot.style.background = '#fbbf24'; dot.style.boxShadow = '0 0 8px #fbbf24'; }
    lucide.createIcons();

    try {
        const url = `/api/run-script/${id}${isFull ? '?mode=full' : ''}`;
        const resp = await fetch(url);
        const data = await resp.json();
        
        if (data.job_id) {
            pollSourceJob(id, data.job_id);
        } else {
            throw new Error(data.error || 'Failed to start job');
        }
    } catch (e) {
        logArea.innerHTML += `<span style="color:#f87171">! Error: ${e.message}</span>\n`;
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="play" style="width:14px;height:14px;"></i> Lancer`;
        statusLabel.innerText = 'FAILED';
        statusLabel.style.color = '#f87171';
        if(dot) { dot.style.background = '#f87171'; dot.style.boxShadow = 'none'; }
        lucide.createIcons();
    }
}

async function pollSourceJob(id, jobId) {
    const logArea = document.getElementById(`log-${id}`);
    const btn = document.getElementById(`btn-run-${id}`);
    const statusLabel = document.getElementById(`log-status-${id}`);
    const dot = document.getElementById(`dot-${id}`);

    const interval = setInterval(async () => {
        try {
            const res = await fetch(`/api/job-status/${jobId}`);
            const status = await res.json();

            // Render logs
            if (status.logs && status.logs.length > 0) {
                logArea.innerHTML = status.logs.map(line => `> ${esc(line)}`).join('\n');
                logArea.scrollTop = logArea.scrollHeight;
            }

            if (status.status === 'completed' || status.status === 'failed') {
                clearInterval(interval);
                btn.disabled = false;
                btn.innerHTML = `<i data-lucide="play" style="width:14px;height:14px;"></i> Lancer`;
                statusLabel.innerText = status.status.toUpperCase();
                statusLabel.style.color = status.status === 'completed' ? '#34d399' : '#f87171';
                if(dot) { 
                    dot.style.background = status.status === 'completed' ? '#34d399' : '#f87171'; 
                    dot.style.boxShadow = status.status === 'completed' ? '0 0 8px #34d399' : 'none';
                }
                lucide.createIcons();
                
                if (status.status === 'completed') {
                    logArea.innerHTML += `\n<span style="color:#34d399">✓ Extraction terminée avec succès.</span>`;
                }
            }
        } catch (e) {
            clearInterval(interval);
            console.error(e);
        }
    }, 1500);
}
