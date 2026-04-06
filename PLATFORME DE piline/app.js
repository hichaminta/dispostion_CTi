/* ============================================
   CTI Pipeline Platform — App Logic
   ============================================ */

// ---- State ----
let currentViewSource = null;
let currentPage = 1;
let totalPages = 1;
let logPollingInterval = null;
let consoleAutoScroll = true;

// ---- Dashboard Update ----
async function updateDashboard() {
    const lastUpdatedEl = document.getElementById('last-updated');
    const totalSourcesEl = document.getElementById('total-sources');
    const totalIocsEl = document.getElementById('total-iocs');
    const totalCvesEl = document.getElementById('total-cves');
    const sourcesBody = document.getElementById('sources-body');
    const overallStatus = document.getElementById('overall-status');
    const activeCount = document.getElementById('active-count');

    try {
        const response = await fetch('status.json?t=' + Date.now());
        if (!response.ok) throw new Error('Status data not available');
        const data = await response.json();

        // --- Header stats ---
        const lastDate = new Date(data.last_updated);
        lastUpdatedEl.textContent = `Dernière mise à jour : ${lastDate.toLocaleDateString('fr-FR')} à ${lastDate.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}`;

        animateCounter(totalSourcesEl, data.total_sources);
        if (totalIocsEl) animateCounter(totalIocsEl, data.total_iocs);
        if (totalCvesEl) animateCounter(totalCvesEl, data.total_cves);

        // --- System status ---
        const activeSources = data.sources.filter(s => s.status === 'Actif').length;
        if (activeCount) activeCount.textContent = `${activeSources}/${data.total_sources} sources actives`;

        if (activeSources === data.total_sources) {
            overallStatus.textContent = 'Opérationnel';
            overallStatus.style.color = 'var(--green)';
        } else if (activeSources > 0) {
            overallStatus.textContent = 'Partiellement actif';
            overallStatus.style.color = 'var(--amber)';
        } else {
            overallStatus.textContent = 'Hors ligne';
            overallStatus.style.color = 'var(--red)';
        }

        // --- Extraction stage badge update ---
        const stageExtraction = document.getElementById('stage-extraction');
        if (stageExtraction) {
            const descEl = stageExtraction.querySelector('.stage-desc');
            if (descEl) descEl.textContent = `Collecte de données depuis ${data.total_sources} sources CTI`;
        }

        // --- Sources Table ---
        sourcesBody.innerHTML = '';
        data.sources.forEach((source, index) => {
            const tr = document.createElement('tr');
            tr.style.animation = `fade-in-up 0.35s ease-out ${index * 0.04}s both`;

            const statusClass = source.status === 'Actif' ? 'badge-ok' : 'badge-error';
            const typeClass = source.type === 'CVE' ? 'type-cve' : 'type-ioc';
            const statusIcon = source.status === 'Actif' ? 'check-circle' : 'alert-circle';
            const isActiveView = currentViewSource === source.name;

            tr.innerHTML = `
                <td>
                    <div class="source-name">
                        <span class="source-icon" style="${source.status !== 'Actif' ? 'background:var(--red);box-shadow:0 0 8px var(--red-dim)' : ''}"></span>
                        ${source.name}
                    </div>
                </td>
                <td><span class="type-badge ${typeClass}">${source.type}</span></td>
                <td><span class="badge ${statusClass}"><i data-lucide="${statusIcon}" style="width:12px;height:12px"></i> ${source.status}</span></td>
                <td><span class="records-num">${source.records.toLocaleString('fr-FR')}</span></td>
                <td>
                    <div class="range-cell">
                        <span class="range-min">${formatDateCompact(source.earliest_modified)}</span>
                        <span class="range-arrow">↓</span>
                        <span class="range-max">${formatDateCompact(source.latest_modified)}</span>
                    </div>
                </td>
                <td style="font-size:0.8rem; color:var(--text-secondary)">${formatDate(source.last_sync)}</td>
                <td>
                    <div class="actions-cell">
                        <button class="row-view-btn ${isActiveView ? 'active-view' : ''}" data-source="${source.name}" title="Voir les données de ${source.name}">
                            <i data-lucide="eye"></i>
                        </button>
                        <button class="row-run-btn" data-source="${source.name}" title="Lancer ${source.name}">
                            <i data-lucide="play"></i>
                        </button>
                    </div>
                </td>
            `;
            sourcesBody.appendChild(tr);
        });

        setupRowButtons();
        setupViewButtons();
        lucide.createIcons();

    } catch (err) {
        lastUpdatedEl.textContent = 'En attente des données...';
        console.error('Dashboard update error:', err);
    }
}

// ---- Animated counter ----
function animateCounter(el, target) {
    const current = parseInt(el.textContent.replace(/\s/g, '').replace(/,/g, '')) || 0;
    if (current === target) {
        el.textContent = target.toLocaleString('fr-FR');
        return;
    }

    const duration = 800;
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(current + (target - current) * eased);
        el.textContent = value.toLocaleString('fr-FR');
        if (progress < 1) {
            requestAnimationFrame(step);
        }
    }

    requestAnimationFrame(step);
}

// ---- Date formatters ----
function formatDate(isoString) {
    if (!isoString || isoString === 'Jamais') return 'Jamais';
    try {
        const d = new Date(isoString);
        if (isNaN(d.getTime())) return isoString;
        return d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' }) + ' ' +
               d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    } catch {
        return isoString;
    }
}

function formatDateCompact(isoString) {
    if (!isoString || isoString === 'Inconnu' || isoString === 'N/A') return '---';
    try {
        const d = new Date(isoString);
        if (isNaN(d.getTime())) return isoString;
        return d.toLocaleDateString('fr-FR', { month: 'short', day: 'numeric', year: '2-digit' });
    } catch {
        return isoString;
    }
}

// ---- Truncate long cell values ----
function truncateValue(val, maxLen = 60) {
    if (val === null || val === undefined) return '<span style="color:var(--text-dim)">—</span>';
    const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
    if (str.length <= maxLen) return escapeHtml(str);
    return `<span title="${escapeHtml(str)}">${escapeHtml(str.substring(0, maxLen))}…</span>`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ---- Initial load ----
document.addEventListener('DOMContentLoaded', () => {
    updateDashboard();
    lucide.createIcons();
    setupDataViewerControls();
});

// Refresh every 30 seconds
setInterval(updateDashboard, 30000);

// ---- Force refresh status.json from backend ----
async function refreshStatus() {
    try {
        await fetch('/api/refresh', { method: 'POST' });
        console.log('[Refresh] status.json actualisé');
    } catch (e) {
        console.warn('[Refresh] Erreur:', e);
    }
    await updateDashboard();
}

// ---- Run Pipeline ----
document.getElementById('run-pipeline-btn').addEventListener('click', async function () {
    const btn = this;
    const originalContent = btn.innerHTML;

    try {
        btn.disabled = true;
        btn.innerHTML = '<i data-lucide="loader-2" class="spin"></i><span>Extraction en cours...</span>';
        lucide.createIcons();

        const extractionStage = document.getElementById('stage-extraction');
        if (extractionStage) extractionStage.classList.add('running');

        const response = await fetch('/run', { method: 'POST' });
        if (!response.ok) throw new Error('Échec du lancement');

        console.log('Pipeline started successfully');

        // Show the live console and start polling logs
        showConsole();
        startLogPolling();

        // Rafraîchir status.json après un délai
        setTimeout(refreshStatus, 10000);
        setTimeout(refreshStatus, 30000);

        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = originalContent;
            lucide.createIcons();
            if (extractionStage) extractionStage.classList.remove('running');
        }, 15000);

    } catch (err) {
        alert('Échec du lancement du pipeline : ' + err.message);
        btn.disabled = false;
        btn.innerHTML = originalContent;
        lucide.createIcons();
    }
});

// ---- Row-level source run ----
function setupRowButtons() {
    document.querySelectorAll('.row-run-btn').forEach(btn => {
        btn.addEventListener('click', async function () {
            const source = this.dataset.source;
            const originalIcon = this.innerHTML;

            try {
                this.disabled = true;
                this.innerHTML = '<i data-lucide="loader-2" class="spin"></i>';
                lucide.createIcons();

                const response = await fetch(`/run?source=${encodeURIComponent(source)}`, { method: 'POST' });
                if (!response.ok) throw new Error('Échec du lancement');

                console.log(`Source ${source} started`);

                // Show console and start polling
                showConsole();
                startLogPolling();

                setTimeout(refreshStatus, 10000);
                setTimeout(refreshStatus, 30000);

                setTimeout(() => {
                    this.disabled = false;
                    this.innerHTML = originalIcon;
                    lucide.createIcons();
                }, 10000);

            } catch (err) {
                alert(`Échec du lancement de ${source}: ` + err.message);
                this.disabled = false;
                this.innerHTML = originalIcon;
                lucide.createIcons();
            }
        });
    });
}

// ============================================
// LIVE CONSOLE
// ============================================

function showConsole() {
    const section = document.getElementById('console-section');
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    const badge = document.getElementById('console-status-badge');
    badge.className = 'console-status-badge';
    badge.innerHTML = '<span class="pulse-dot"></span> En cours';

    const output = document.getElementById('console-output');
    output.innerHTML = 'Lancement en cours...\n';

    consoleAutoScroll = true;
    lucide.createIcons();
    setupConsoleControls();
}

function startLogPolling() {
    stopLogPolling();
    // Poll every 2 seconds
    logPollingInterval = setInterval(pollLogs, 2000);
    // First immediate poll
    setTimeout(pollLogs, 500);
}

function stopLogPolling() {
    if (logPollingInterval) {
        clearInterval(logPollingInterval);
        logPollingInterval = null;
    }
}

async function pollLogs() {
    try {
        const response = await fetch('/api/logs?lines=300');
        if (!response.ok) return;
        const data = await response.json();

        const output = document.getElementById('console-output');
        const consoleBody = document.getElementById('console-body');
        const badge = document.getElementById('console-status-badge');

        if (data.lines && data.lines.length > 0) {
            // Render with syntax highlighting
            output.innerHTML = data.lines.map(highlightLogLine).join('\n');
        } else {
            output.innerHTML = 'En attente de la sortie du script...\n';
        }

        // Auto-scroll to bottom
        if (consoleAutoScroll) {
            consoleBody.scrollTop = consoleBody.scrollHeight;
        }

        // Update run status badge
        if (!data.running && data.lines && data.lines.length > 2) {
            badge.className = 'console-status-badge finished';
            badge.innerHTML = '<span class="pulse-dot"></span> Terminé';
            stopLogPolling();
            // Final status refresh
            refreshStatus();
        }

    } catch (err) {
        console.warn('Log polling error:', err);
    }
}

function highlightLogLine(line) {
    // Escape HTML
    let safe = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // === Headers ===
    if (safe.includes('===') || safe.includes('DÉMARRAGE') || safe.includes('RÉSUMÉ') || safe.includes('FIN DES')) {
        return `<span class="log-line-header">${safe}</span>`;
    }
    // Separators
    if (/^[=\-]{10,}/.test(safe)) {
        return `<span class="log-line-separator">${safe}</span>`;
    }
    // Success lines
    if (safe.includes('SUCCESS') || safe.includes('succès') || safe.includes('terminé') || safe.includes('Terminé')) {
        return `<span class="log-line-success">${safe}</span>`;
    }
    // ERROR / FAILED
    if (safe.includes('ERROR') || safe.includes('FAILED') || safe.includes('Erreur') || safe.includes('erreur') || safe.includes('échoué')) {
        return `<span class="log-line-error">${safe}</span>`;
    }
    // WARNING
    if (safe.includes('WARNING') || safe.includes('warning') || safe.includes('Attention')) {
        return `<span class="log-line-warning">${safe}</span>`;
    }
    // New items detected
    if (safe.includes('nouvelle') || safe.includes('nouveau') || safe.includes('new') || safe.includes('ajouté') || safe.includes('détecté') || safe.includes('trouvé')) {
        return `<span class="log-line-new-item">${safe}</span>`;
    }
    // Progression / INFO
    if (safe.includes('Progression') || safe.includes('INFO') || safe.includes('Requête') || safe.includes('Extraction') || safe.includes('Lancement')) {
        return `<span class="log-line-info">${safe}</span>`;
    }
    // Numbers/counts
    if (/Total|IOCs|CVEs|Succès|Échecs|sources/.test(safe)) {
        return `<span class="log-line-info">${safe}</span>`;
    }

    return safe;
}

function setupConsoleControls() {
    const closeBtn = document.getElementById('console-close-btn');
    const clearBtn = document.getElementById('console-clear-btn');
    const consoleBody = document.getElementById('console-body');

    // Remove old listeners by cloning
    const newCloseBtn = closeBtn.cloneNode(true);
    closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
    newCloseBtn.addEventListener('click', () => {
        document.getElementById('console-section').style.display = 'none';
        stopLogPolling();
    });

    const newClearBtn = clearBtn.cloneNode(true);
    clearBtn.parentNode.replaceChild(newClearBtn, clearBtn);
    newClearBtn.addEventListener('click', async () => {
        await fetch('/api/logs/clear', { method: 'POST' });
        document.getElementById('console-output').innerHTML = 'Console vidée.\n';
    });

    lucide.createIcons();

    // Detect manual scroll to disable auto-scroll
    consoleBody.addEventListener('scroll', () => {
        const atBottom = consoleBody.scrollTop + consoleBody.clientHeight >= consoleBody.scrollHeight - 30;
        consoleAutoScroll = atBottom;
    });
}

// ============================================
// DATA VIEWER
// ============================================

function setupViewButtons() {
    document.querySelectorAll('.row-view-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const source = this.dataset.source;

            // Toggle: if already viewing this source, close it
            if (currentViewSource === source) {
                closeDataViewer();
                return;
            }

            // Remove active class from all view buttons
            document.querySelectorAll('.row-view-btn').forEach(b => b.classList.remove('active-view'));
            this.classList.add('active-view');

            currentViewSource = source;
            currentPage = 1;
            loadSourceData(source, 1);
        });
    });
}

function setupDataViewerControls() {
    // Close button
    document.getElementById('close-viewer-btn').addEventListener('click', closeDataViewer);

    // Pagination
    document.getElementById('prev-page-btn').addEventListener('click', () => {
        if (currentPage > 1 && currentViewSource) {
            currentPage--;
            loadSourceData(currentViewSource, currentPage);
        }
    });

    document.getElementById('next-page-btn').addEventListener('click', () => {
        if (currentPage < totalPages && currentViewSource) {
            currentPage++;
            loadSourceData(currentViewSource, currentPage);
        }
    });
}

function closeDataViewer() {
    const section = document.getElementById('data-viewer-section');
    section.style.display = 'none';
    currentViewSource = null;
    currentPage = 1;
    document.querySelectorAll('.row-view-btn').forEach(b => b.classList.remove('active-view'));
}

async function loadSourceData(sourceName, page) {
    const section = document.getElementById('data-viewer-section');
    const titleEl = document.getElementById('data-viewer-title');
    const countEl = document.getElementById('data-viewer-count');
    const pageInfoEl = document.getElementById('page-info');
    const prevBtn = document.getElementById('prev-page-btn');
    const nextBtn = document.getElementById('next-page-btn');
    const loadingEl = document.getElementById('data-loading');
    const tableEl = document.getElementById('data-table');
    const headEl = document.getElementById('data-table-head');
    const bodyEl = document.getElementById('data-table-body');

    // Show the section
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Show loading
    loadingEl.style.display = 'flex';
    tableEl.style.display = 'none';
    titleEl.textContent = `Données — ${sourceName}`;
    countEl.textContent = 'Chargement...';

    try {
        const response = await fetch(`/api/data?source=${encodeURIComponent(sourceName)}&page=${page}&per_page=50`);
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Erreur serveur');
        }

        const result = await response.json();

        currentPage = result.page;
        totalPages = result.total_pages;

        // Update header info
        countEl.textContent = `${result.total.toLocaleString('fr-FR')} enregistrements`;
        pageInfoEl.textContent = `Page ${result.page} / ${result.total_pages}`;
        prevBtn.disabled = result.page <= 1;
        nextBtn.disabled = result.page >= result.total_pages;

        // Build table header
        const columns = result.columns;
        headEl.innerHTML = '<tr>' + columns.map(col =>
            `<th>${escapeHtml(col)}</th>`
        ).join('') + '</tr>';

        // Build table rows
        bodyEl.innerHTML = '';
        result.data.forEach((row, idx) => {
            const tr = document.createElement('tr');
            tr.style.animation = `fade-in-up 0.2s ease-out ${idx * 0.015}s both`;
            tr.innerHTML = columns.map(col => {
                const val = row[col];
                return `<td>${truncateValue(val)}</td>`;
            }).join('');
            bodyEl.appendChild(tr);
        });

        // Show table, hide loading
        loadingEl.style.display = 'none';
        tableEl.style.display = 'table';

        lucide.createIcons();

    } catch (err) {
        loadingEl.innerHTML = `
            <i data-lucide="alert-triangle" style="width:32px;height:32px;color:var(--red)"></i>
            <p style="color:var(--red)">Erreur : ${escapeHtml(err.message)}</p>
            <p style="font-size:0.8rem;color:var(--text-dim)">Assurez-vous que le serveur est lancé via start_platform.py</p>
        `;
        lucide.createIcons();
    }
}
