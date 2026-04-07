/* ════════════════════════════════════════════════════════════════════
   CTI Pipeline Platform — Application Logic
   ════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
    currentSource: null,        // source name being viewed
    currentPage:   1,
    totalPages:    1,
    logInterval:   null,
    autoScroll:    true,
    activeFilter:  'all',       // 'all' | 'IOC' | 'CVE'
    lastData:      null,        // cached status.json data
    runningBtn:    null,        // the ► button currently executing
    runningBtnOrig:null,        // its original innerHTML
    runningPipeline: false,     // true when full pipeline is running
};

// ── DOM refs (lazy cached) ─────────────────────────────────────────────────
const el = id => document.getElementById(id);

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    fetchDashboard();
    setupRunBtn();
    setupRefreshBtn();
    setupDataViewerControls();
    setupTypeFilters();
    setupNavTabs();
    setupConsoleControls(); // Initialize only once!

    // Auto-refresh every 30 s
    setInterval(fetchDashboard, 30_000);
});

// ── Navigation & Views ───────────────────────────────────────────────────

function setupNavTabs() {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.onclick = () => switchView(btn.dataset.view);
    });
}

function switchView(viewId) {
    // Buttons
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === viewId);
    });
    // Containers
    document.querySelectorAll('.app-view').forEach(view => {
        view.classList.toggle('active', view.id === `view-${viewId}`);
    });
    
    // Auto-scroll logic for logs if switching to logs
    if (viewId === 'logs') {
        state.autoScroll = true;
        pollLogs();
    }
}

async function fetchDashboard() {
    try {
        const res = await fetch('/api/status?t=' + Date.now());
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        state.lastData = data;
        renderDashboard(data);
    } catch (err) {
        el('last-updated').textContent = 'Serveur non disponible';
        console.warn('[Dashboard]', err.message);
    }
}

function renderDashboard(data) {
    // Header stats
    const lastDate = new Date(data.last_updated);
    const timeStr  = isNaN(lastDate) ? '--' :
        lastDate.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    el('last-updated').textContent = timeStr;

    animateCounter(el('total-sources'), data.total_sources || 0);
    animateCounter(el('total-iocs'),    data.total_iocs    || 0);
    animateCounter(el('total-cves'),    data.total_cves    || 0);

    // System health
    const sources   = Array.isArray(data.sources) ? data.sources : [];
    const active    = sources.filter(s => s.status === 'Actif').length;
    const total     = data.total_sources || sources.length;
    const statusEl  = el('overall-status');
    const subEl     = el('active-count');
    const centerEl  = el('system-center-icon');

    el('active-count').textContent = `${active}/${total} sources actives`;

    if (active === total && total > 0) {
        statusEl.textContent  = 'Opérationnel';
        statusEl.className    = 'system-status-label';
        if (centerEl) { centerEl.className = 'pulse-center'; centerEl.innerHTML = '<i data-lucide="check"></i>'; }
    } else if (active > 0) {
        statusEl.textContent  = 'Partiellement actif';
        statusEl.className    = 'system-status-label warn';
        if (centerEl) { centerEl.className = 'pulse-center'; centerEl.innerHTML = '<i data-lucide="alert-triangle"></i>'; }
    } else {
        statusEl.textContent  = 'Hors ligne';
        statusEl.className    = 'system-status-label error';
        if (centerEl) { centerEl.className = 'pulse-center error'; centerEl.innerHTML = '<i data-lucide="x"></i>'; }
    }

    // CVE alert banner
    const totalCves  = data.total_cves || 0;
    const cvesBanner = el('cve-alert-banner');
    if (totalCves > 0) {
        cvesBanner.style.display = 'flex';
        el('cve-alert-count').textContent = `${totalCves.toLocaleString('fr-FR')} vulnérabilités référencées`;
    } else {
        cvesBanner.style.display = 'none';
    }

    // IOC/CVE progress bars
    const totalAll  = (data.total_iocs || 0) + (data.total_cves || 0);
    const iocPct    = totalAll > 0 ? Math.round((data.total_iocs || 0) / totalAll * 100) : 0;
    const cvePct    = totalAll > 0 ? Math.round((data.total_cves || 0) / totalAll * 100) : 0;

    const barIoc = el('bar-ioc');
    const barCve = el('bar-cve');
    if (barIoc) { barIoc.style.width = iocPct + '%'; }
    if (barCve) { barCve.style.width = cvePct + '%'; }
    const barIocVal = el('bar-ioc-val');
    const barCveVal = el('bar-cve-val');
    if (barIocVal) barIocVal.textContent = (data.total_iocs || 0).toLocaleString('fr-FR');
    if (barCveVal) barCveVal.textContent = (data.total_cves || 0).toLocaleString('fr-FR');

    // Extraction stage label
    const descEl = document.getElementById('stage-extraction-desc');
    if (descEl) descEl.textContent = `Collecte depuis ${total} sources CTI`;

    // Sources table
    renderSourcesTable(sources);
    updateConsoleSourceSelector(sources);

    lucide.createIcons();
}

/** Populate the console filter dropdown with available source names */
function updateConsoleSourceSelector(sources) {
    const sel = el('console-source-selector');
    if (!sel) return;
    
    // Keep only "Flux Global"
    const currentVal = sel.value;
    sel.innerHTML = '<option value="Global">Flux Global</option>';
    
    sources.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.name;
        opt.textContent = `Source: ${s.name}`;
        sel.appendChild(opt);
    });
    
    // Restore selection if it still exists
    if (sources.some(s => s.name === currentVal)) {
        sel.value = currentVal;
    }
}

// ════════════════════════════════════════════════════════════════════
// SOURCES TABLE
// ════════════════════════════════════════════════════════════════════

function renderSourcesTable(sources) {
    const tbody = el('sources-body');
    const filter = state.activeFilter;

    let filtered = sources;
    if (filter === 'IOC' || filter === 'CVE') {
        filtered = sources.filter(s => s.type === filter);
    } else if (filter === 'success') {
        filtered = sources.filter(s => s.run_state === 'success');
    } else if (filter === 'error') {
        filtered = sources.filter(s => s.run_state === 'error');
    }

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="table-loading">Aucune source pour ce filtre.</td></tr>`;
        return;
    }

    tbody.innerHTML = '';
    filtered.forEach((src, i) => {
        const tr = document.createElement('tr');
        tr.style.animation = `fade-in-up 0.3s ease-out ${i * 0.035}s both`;

        const isActive  = src.status === 'Actif';
        const isCve     = src.type === 'CVE';
        const isViewing = state.currentSource === src.name;

        const statusIcon  = isActive ? 'check-circle' : 'alert-circle';
        const statusClass = isActive ? 'badge-ok' : 'badge-err';
        const typeClass   = isCve    ? 'type-cve'  : 'type-ioc';
        const dotClass    = isActive ? 'source-dot' : 'source-dot inactive';

        tr.innerHTML = `
            <td>
                <div class="source-name-cell">
                    <span class="${dotClass}" aria-hidden="true"></span>
                    <span class="source-name-text">${esc(src.name)}</span>
                </div>
            </td>
            <td><span class="type-badge ${typeClass}">${esc(src.type)}</span></td>
            <td>
                <span class="status-badge ${statusClass}">
                    <i data-lucide="${statusIcon}"></i>
                    ${esc(src.status)}
                </span>
            </td>
            <td><span class="records-cell">${(src.records || 0).toLocaleString('fr-FR')}</span></td>
            <td>
                <div class="range-cell">
                    <span class="range-min">${fmtCompact(src.earliest_modified)}</span>
                    <span class="range-sep">↓</span>
                    <span class="range-max">${fmtCompact(src.latest_modified)}</span>
                </div>
            </td>
            <td style="font-size:0.78rem;color:var(--text-secondary)">${fmtDate(src.last_sync)}</td>
                <div class="actions-cell">
                    <button class="row-btn row-view-btn ${isViewing ? 'active-view' : ''}"
                            data-source="${esc(src.name)}"
                            title="Voir les données de ${esc(src.name)}"
                            aria-label="Voir ${esc(src.name)}">
                        <i data-lucide="eye"></i>
                    </button>
                    <button class="row-btn row-log-btn"
                            data-source="${esc(src.name)}"
                            title="Voir l'historique des logs de ${esc(src.name)}"
                            aria-label="Logs ${esc(src.name)}">
                        <i data-lucide="scroll-text"></i>
                    </button>
                    ${renderRunButton(src)}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });

    setupRowRunButtons();
    setupRowViewButtons();
    setupRowLogButtons();
    lucide.createIcons();
}

/** New: access logs directly from table */
function setupRowLogButtons() {
    document.querySelectorAll('.row-log-btn').forEach(btn => {
        btn.onclick = function() {
            const source = this.dataset.source;
            showConsole(source);
            startLogPolling();
        };
    });
}

/** Returns the correct HTML for the run/stop/error button */
function renderRunButton(src) {
    const state = src.run_state || 'idle';
    let icon = 'play';
    let cls  = '';
    let hint = `Lancer ${src.name}`;

    if (state === 'running') {
        icon = 'square';
        cls  = 'btn-stop';
        hint = `Arrêter ${src.name}`;
    } else if (state === 'error') {
        icon = 'alert-circle';
        cls  = 'btn-error';
        hint = `Dernière tentative : Erreur. Relancer ?`;
    } else if (state === 'success') {
        icon = 'check-circle'; // green check for sources that just finished
        cls  = 'btn-done-static'; 
        hint = `Dernier succès. Relancer ?`;
    }

    return `
        <button class="row-btn row-run-btn ${cls}"
                data-source="${esc(src.name)}"
                data-state="${state}"
                title="${esc(hint)}"
                aria-label="${esc(hint)}">
            <i data-lucide="${icon}"></i>
        </button>
    `;
}

function setupTypeFilters() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            state.activeFilter = btn.dataset.filter;
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.toggle('filter-active', b.dataset.filter === state.activeFilter);
                b.setAttribute('aria-pressed', b.dataset.filter === state.activeFilter);
            });
            if (state.lastData) renderSourcesTable(state.lastData.sources || []);
        });
    });
}

// ── Row buttons ─────────────────────────────────────────────────────────────

// ── Pipeline Stage Visual State ──────────────────────────────────────────────

let _stageResetTimer = null;

/**
 * Mark the Extraction pipeline stage as actively running.
 * @param {string|null} sourceName  — name of the source (or null for full pipeline)
 * @param {number}      durationMs  — how long to keep the running state visible
 */
function setExtractionRunning(sourceName, durationMs = 20_000) {
    const stage   = el('stage-extraction');
    const descEl  = el('stage-extraction-desc');
    const badgeEl = stage ? stage.querySelector('.stage-status-badge') : null;

    if (stage)   stage.classList.add('running');
    if (descEl)  descEl.textContent = sourceName
        ? `⚡ Extraction : ${sourceName}`
        : `⚡ Pipeline complet en cours...`;
    if (badgeEl) {
        badgeEl.className = 'stage-status-badge badge-active';
        badgeEl.innerHTML = '<span class="pulse-dot"></span> En cours';
    }

    // Update footer too
    const footer = el('footer-status');
    if (footer) footer.textContent = sourceName
        ? `⚡  Extraction: ${sourceName}`
        : `⚡  Pipeline en cours…`;

    // Clear any pending reset
    if (_stageResetTimer) clearTimeout(_stageResetTimer);
    _stageResetTimer = null;
}

function setExtractionIdle(totalSources) {
    const stage   = el('stage-extraction');
    const descEl  = el('stage-extraction-desc');
    const badgeEl = stage ? stage.querySelector('.stage-status-badge') : null;

    const isAnyRunning = state.lastData?.sources?.some(s => s.run_state === 'running');
    if (isAnyRunning) return; // Wait until all really finish

    if (stage)   stage.classList.remove('running');
    if (descEl)  descEl.textContent = `Collecte depuis ${totalSources || 13} sources CTI`;
    if (badgeEl) {
        badgeEl.className = 'stage-status-badge badge-active';
        badgeEl.innerHTML = '<span class="pulse-dot"></span> Opérationnel';
    }

    const footer = el('footer-status');
    if (footer) footer.textContent = '●  en ligne';
}

// ── Row-level source run ──────────────────────────────────────────────────────

function setupRowRunButtons() {
    document.querySelectorAll('.row-run-btn').forEach(btn => {
        btn.onclick = async function () {
            const source = this.dataset.source;
            const curState = this.dataset.state;

            if (curState === 'running') {
                // STOP LOGIC
                this.disabled = true;
                this.innerHTML = '<i data-lucide="loader-2" class="spin"></i>';
                lucide.createIcons();
                try {
                    await fetch(`/api/stop?source=${encodeURIComponent(source)}`, { method: 'POST' });
                    showToast(`Arrêt demandé pour ${source}`, 'info');
                    fetchDashboard();
                } catch(e) { 
                    showToast("Erreur arrêt", "error"); 
                    this.disabled = false;
                    fetchDashboard();
                }
                return;
            }

            // RUN LOGIC
            this.disabled  = true;
            this.innerHTML = '<i data-lucide="loader-2" class="spin"></i>';
            this.classList.add('btn-running');
            lucide.createIcons();

            setExtractionRunning(source);

            try {
                const res = await fetch(`/api/run?source=${encodeURIComponent(source)}`, { method: 'POST' });
                if (!res.ok) throw new Error((await res.json()).error || 'Échec');
                
                showConsole(source); // Show specific logs for this source
                startLogPolling();
                setTimeout(fetchDashboard, 800);
            } catch (err) {
                showToast(`Erreur [${source}] : ${err.message}`, 'error');
                fetchDashboard();
            }
        };
    });
}

/** Reset the running button back to its idle ▶ state. */
function resetRunningBtn(success = false) {
    if (_stageResetTimer) { clearTimeout(_stageResetTimer); _stageResetTimer = null; }

    if (state.runningBtn) {
        const btn  = state.runningBtn;
        const orig = state.runningBtnOrig || '<i data-lucide="play"></i>';

        btn.classList.remove('btn-running');
        btn.disabled = false;

        if (success) {
            // Show ✓ for 1.5 s then restore ►
            btn.innerHTML = '<i data-lucide="check"></i>';
            btn.classList.add('btn-done');
            lucide.createIcons();
            setTimeout(() => {
                btn.innerHTML = orig;
                btn.classList.remove('btn-done');
                lucide.createIcons();
            }, 1_500);
        } else {
            btn.innerHTML = orig;
            lucide.createIcons();
        }

        state.runningBtn      = null;
        state.runningBtnOrig  = null;
    }

    setExtractionIdle(state.lastData?.total_sources);
}

function setupRowViewButtons() {
    document.querySelectorAll('.row-view-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const source = this.dataset.source;
            if (state.currentSource === source) {
                closeDataViewer(); return;
            }
            document.querySelectorAll('.row-view-btn').forEach(b => b.classList.remove('active-view'));
            this.classList.add('active-view');
            state.currentSource = source;
            state.currentPage   = 1;
            loadSourceData(source, 1);
        });
    });
}

// ── Run full pipeline ─────────────────────────────────────────────────────────

function setupRunBtn() {
    el('run-pipeline-btn').addEventListener('click', async function () {
        const btn  = this;
        btn._origHTML = btn.innerHTML;
        btn.disabled  = true;
        btn.innerHTML = '<i data-lucide="loader-2" class="spin"></i><span>Extraction en cours...</span>';
        lucide.createIcons();

        state.runningPipeline = true;
        setExtractionRunning(null);

        try {
            const res = await fetch('/api/run', { method: 'POST' });
            if (!res.ok) throw new Error((await res.json()).error || 'Échec');
            showConsole();
            startLogPolling();
            setTimeout(fetchDashboard, 1000);
        } catch (err) {
            showToast('Échec du pipeline : ' + err.message, 'error');
            btn.disabled  = false;
            btn.innerHTML = btn._origHTML;
            state.runningPipeline = false;
            setExtractionIdle(state.lastData?.total_sources);
        }
    });
}

function setupRefreshBtn() {
    el('refresh-btn').addEventListener('click', async () => {
        const btn = el('refresh-btn');
        btn.style.pointerEvents = 'none';
        btn.querySelector('svg')?.classList.add('spin');
        try {
            await fetch('/api/refresh', { method: 'POST' });
            await fetchDashboard();
        } catch (e) {
            await fetchDashboard();
        }
        btn.style.pointerEvents = '';
        btn.querySelector('svg')?.classList.remove('spin');
    });
}

function scheduleStatusRefresh(delays = []) {
    delays.forEach(d => setTimeout(fetchDashboard, d));
}

// ════════════════════════════════════════════════════════════════════
// LIVE CONSOLE
// ════════════════════════════════════════════════════════════════════

function showConsole(sourceName = 'Global') {
    switchView('logs');
    
    // Set selector
    const sel = el('console-source-selector');
    if (sel && sourceName) sel.value = sourceName;

    const badge = el('console-status-badge');
    if (badge) {
        badge.className = 'console-running-badge';
        badge.innerHTML = '<span class="pulse-dot"></span> En cours';
    }
 
    el('console-output').innerHTML = 'Chargement des logs...\n';
    state.autoScroll = true;
 
    lucide.createIcons();
    // No more setupConsoleControls() call here to avoid redundant listeners
    startLogPolling(); // ensure polling starts (it handles finished vs running)
}

function startLogPolling() {
    stopLogPolling();
    // Initial fetch
    pollLogs(true);
    state.logInterval = setInterval(() => pollLogs(false), 2_000);
}

function stopLogPolling() {
    if (state.logInterval) {
        clearInterval(state.logInterval);
        state.logInterval = null;
    }
}

async function pollLogs(forceFetch = false) {
    try {
        const sel = el('console-source-selector');
        const source = sel ? sel.value : 'Global';
        
        // Find active console filter
        const activeBtn = document.querySelector('.console-filter-btn.active');
        const filter = activeBtn ? activeBtn.dataset.filter : 'all';
        
        const res = await fetch(`/api/logs?source=${encodeURIComponent(source)}&lines=400&filter=${filter}`);
        if (!res.ok) return;
        const data = await res.json();

        const output = el('console-output');
        const body   = el('console-body');
        const badge  = el('console-status-badge');

        if (data.lines && data.lines.length > 0) {
            output.innerHTML = data.lines.map(highlightLine).join('\n');
        } else {
            output.textContent = 'Aucune ligne de log correspondante.\n';
        }

        if (state.autoScroll) body.scrollTop = body.scrollHeight;

        // System state sync
        if (data.running) {
             if (badge) {
                badge.className = 'console-running-badge';
                badge.innerHTML = '<span class="pulse-dot"></span> En cours';
             }
             // sync dashboard occasionally
             if (Math.random() > 0.8) fetchDashboard();
        } else {
             if (badge) {
                 badge.className = 'console-running-badge finished';
                 badge.innerHTML = '<span class="pulse-dot"></span> Terminé';
             }
             // If not force fetching and process is done, we can stop polling IF it's not the user browsing manually
             // Actually, for simplicity, we only stop if we aren't force fetching and it's definitely finished.
             // But if the user is in the Logs tab, we might want to keep it "live" for the next run.
             if (!forceFetch && data.lines && data.lines.length > 2) {
                 // stopLogPolling(); // Keeping it alive for now to allow historical browsing feel stable
             }
        }
    } catch (err) {
        console.warn('[ConsolePolling]', err);
    }
}

function highlightLine(raw) {
    let s = raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    if (/===|DÉMARRAGE|RÉSUMÉ|FIN DES|Pipeline/.test(s))
        return `<span class="log-header">${s}</span>`;
    if (/^[=\-─]{8,}/.test(s))
        return `<span class="log-separator">${s}</span>`;
    if (/CVE-\d{4}-\d+|vulnérabilit|cve_id/.test(s))
        return `<span class="log-cve">${s}</span>`;
    if (/SUCCESS|succès|Succès|terminé|Terminé|✔|✓/.test(s))
        return `<span class="log-success">${s}</span>`;
    if (/ERROR|FAILED|Erreur|erreur|échoué|❌/.test(s))
        return `<span class="log-error">${s}</span>`;
    if (/WARNING|warning|Attention|⚠/.test(s))
        return `<span class="log-warning">${s}</span>`;
    if (/nouvelle|nouveau|ajouté|détecté|trouvé|new/.test(s))
        return `<span class="log-new-item">${s}</span>`;
    if (/INFO|Requête|Extraction|Lancement|Progression|\[/.test(s))
        return `<span class="log-info">${s}</span>`;

    return s;
}

function setupConsoleControls() {
    el('console-clear-btn')?.addEventListener('click', async () => {
        const sel = el('console-source-selector');
        const source = sel ? sel.value : 'Global';
        await fetch(`/api/logs/clear?source=${encodeURIComponent(source)}`, { method: 'POST' });
        el('console-output').textContent = `Logs de [${source}] vidés.\n`;
    });

    el('console-source-selector')?.addEventListener('change', () => {
        const sel = el('console-source-selector');
        const source = sel ? sel.value : 'Global';
        el('console-output').textContent = `Chargement des logs de ${source}...\n`;
        pollLogs(true); // force fetch
    });

    // Console line-level filters
    document.querySelectorAll('.console-filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.currentTarget;
            document.querySelectorAll('.console-filter-btn').forEach(b => b.classList.remove('active'));
            target.classList.add('active');
            el('console-output').textContent = 'Initialisation du filtre...\n';
            pollLogs(true); // force fetch
        });
    });

    // Manual scroll detection
    el('console-body')?.addEventListener('scroll', () => {
        const b = el('console-body');
        state.autoScroll = (b.scrollTop + b.clientHeight >= b.scrollHeight - 40);
    }, { passive: true });
}

// ════════════════════════════════════════════════════════════════════
// DATA VIEWER
// ════════════════════════════════════════════════════════════════════

function setupDataViewerControls() {
    el('close-viewer-btn').addEventListener('click', closeDataViewer);

    el('prev-page-btn').addEventListener('click', () => {
        if (state.currentPage > 1 && state.currentSource) {
            state.currentPage--;
            loadSourceData(state.currentSource, state.currentPage);
        }
    });

    el('next-page-btn').addEventListener('click', () => {
        if (state.currentPage < state.totalPages && state.currentSource) {
            state.currentPage++;
            loadSourceData(state.currentSource, state.currentPage);
        }
    });
}

function closeDataViewer() {
    el('data-viewer-section').style.display = 'none';
    state.currentSource = null;
    state.currentPage   = 1;
    document.querySelectorAll('.row-view-btn').forEach(b => b.classList.remove('active-view'));
}

async function loadSourceData(sourceName, page) {
    const section    = el('data-viewer-section');
    const titleEl    = el('viewer-heading');
    const countEl    = el('data-viewer-count');
    const pageInfoEl = el('page-info');
    const prevBtn    = el('prev-page-btn');
    const nextBtn    = el('next-page-btn');
    const loadingEl  = el('viewer-loading');
    const tableWrap  = el('viewer-table-wrap');
    const headEl     = el('data-table-head');
    const bodyEl     = el('data-table-body');

    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    loadingEl.style.display = 'flex';
    loadingEl.innerHTML = `<i data-lucide="loader-2" class="spin" style="width:32px;height:32px;color:var(--accent)"></i><p>Chargement...</p>`;
    tableWrap.style.display = 'none';
    titleEl.textContent = `Données — ${sourceName}`;
    countEl.textContent = 'Chargement...';
    lucide.createIcons();

    try {
        const res = await fetch(`/api/data?source=${encodeURIComponent(sourceName)}`);
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        // The Flask API returns the array directly now, or we can adapt
        const records = Array.isArray(data) ? data : (data.data || []);
        
        state.currentPage = 1;
        state.totalPages  = 1;

        countEl.textContent  = `${(records.length || 0).toLocaleString('fr-FR')} enregistrements`;
        pageInfoEl.textContent = `Aperçu (1000 max)`;
        prevBtn.disabled = true;
        nextBtn.disabled = true;

        if (records.length === 0) {
            bodyEl.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:2rem">Aucune donnée trouvée.</td></tr>';
            loadingEl.style.display = 'none';
            tableWrap.style.display = 'block';
            return;
        }

        // Build table based on keys of first object
        const cols = Object.keys(records[0]);
        headEl.innerHTML = '<tr>' + cols.map(c => `<th scope="col">${esc(c)}</th>`).join('') + '</tr>';

        bodyEl.innerHTML = '';
        records.forEach((row, i) => {
            const tr = document.createElement('tr');
            tr.style.animation = `fade-in-up 0.2s ease-out ${i * 0.005}s both`;
            tr.innerHTML = cols.map(col => {
                const v = row[col];
                return `<td>${truncate(v)}</td>`;
            }).join('');
            bodyEl.appendChild(tr);
        });

        loadingEl.style.display = 'none';
        tableWrap.style.display = 'block';
        lucide.createIcons();

    } catch (err) {
        loadingEl.innerHTML = `
            <i data-lucide="alert-triangle" style="width:32px;height:32px;color:var(--red)"></i>
            <p style="color:var(--red);font-weight:600">Erreur : ${esc(err.message)}</p>
            <p style="font-size:0.78rem;color:var(--text-dim)">Vérifiez que le serveur tourne via start_platform.py</p>
        `;
        lucide.createIcons();
    }
}

// ════════════════════════════════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════════════════════════════════

function animateCounter(el, target) {
    if (!el) return;
    const start    = parseInt(el.textContent.replace(/[\s,]/g, '')) || 0;
    if (start === target) { el.textContent = target.toLocaleString('fr-FR'); return; }
    const duration = 900;
    const t0       = performance.now();

    (function step(now) {
        const p   = Math.min((now - t0) / duration, 1);
        const val = Math.round(start + (target - start) * (1 - Math.pow(1 - p, 3)));
        el.textContent = val.toLocaleString('fr-FR');
        if (p < 1) requestAnimationFrame(step);
    })(performance.now());
}

function fmtDate(iso) {
    if (!iso || iso === 'Jamais' || iso === 'N/A') return 'Jamais';
    try {
        const d = new Date(iso);
        if (isNaN(d)) return iso;
        return d.toLocaleDateString('fr-FR', { day:'2-digit', month:'short' }) + ' ' +
               d.toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit' });
    } catch { return iso; }
}

function fmtCompact(iso) {
    if (!iso || iso === 'Inconnu' || iso === 'N/A') return '—';
    try {
        const d = new Date(iso);
        if (isNaN(d)) return iso;
        return d.toLocaleDateString('fr-FR', { day:'numeric', month:'short', year:'2-digit' });
    } catch { return iso; }
}

function esc(str) {
    if (str === null || str === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
}

function truncate(val, max = 70) {
    if (val === null || val === undefined) return '<span class="val-null">null</span>';
    const s = typeof val === 'object' ? JSON.stringify(val) : String(val);
    const safe = esc(s);
    if (s.length <= max) return safe;
    return `<span title="${esc(s)}">${esc(s.substring(0, max))}…</span>`;
}

function showToast(msg, type = 'info') {
    // Simple alert fallback — could be enhanced with a toast library
    console.warn(`[Toast][${type}]`, msg);
    if (type === 'error') alert(msg);
}
