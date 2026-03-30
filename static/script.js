/**
 * MailGuard — Email Security Platform
 * Frontend logic: analysis, XAI, phishing, URL scan, batch, analytics, history
 */

// ── State ──────────────────────────────────────────────────────
let selectedModel = 'ensemble';
let historyFilter = 'all';
let inboxFilter = 'all';
let charts = {};
let imapSession = null;
let autoRefreshInterval = null;
let currentInboxEmails = [];
let isLoading = false;
let lastAnalysisResult = null;
let lastAnalysisText = '';

// ── Loading Overlay Functions ───────────────────────────────────
function showLoading(message = 'Analyzing') {
    isLoading = true;
    let overlay = document.getElementById('loadingOverlay');
    
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="ai-loader">
                <div class="ai-loader-ring"></div>
                <div class="ai-loader-ring"></div>
                <div class="ai-loader-ring"></div>
                <div class="ai-loader-core">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                    </svg>
                </div>
            </div>
            <div class="loading-text"><span class="loading-dots">${message}</span></div>
        `;
        document.body.appendChild(overlay);
    } else {
        overlay.querySelector('.loading-dots').textContent = message;
    }
    
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function hideLoading() {
    isLoading = false;
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.remove('active');
        setTimeout(() => overlay.remove(), 300);
    }
}

function updateLoadingMessage(message) {
    const dots = document.querySelector('.loading-dots');
    if (dots) dots.textContent = message;
}

// ── Empty State Renderer ────────────────────────────────────────
function renderEmptyState(container, config) {
    const { icon, title, description, action, actionText, actionIcon } = config;
    
    container.innerHTML = `
        <div class="empty-state">
            <div class="empty-state-icon">
                <i data-lucide="${icon || 'inbox'}"></i>
            </div>
            <h4 class="empty-state-title">${title || 'No Data'}</h4>
            <p class="empty-state-description">${description || 'There\'s nothing here yet.'}</p>
            ${action ? `
                <button class="empty-state-action" onclick="${action}">
                    ${actionIcon ? `<i data-lucide="${actionIcon}"></i>` : ''}
                    <span>${actionText || 'Get Started'}</span>
                </button>
            ` : ''}
        </div>
    `;
    
    if (window.lucide) lucide.createIcons();
}

// ── Skeleton Loading ────────────────────────────────────────────
function renderSkeleton(container, count = 3) {
    let html = '';
    for (let i = 0; i < count; i++) {
        html += `
            <div class="skeleton-item" style="margin-bottom: 12px;">
                <div class="skeleton" style="width: ${60 + Math.random() * 40}%; height: 16px; margin-bottom: 8px;"></div>
                <div class="skeleton" style="width: ${40 + Math.random() * 50}%; height: 14px;"></div>
            </div>
        `;
    }
    container.innerHTML = html;
}

// ── Samples ────────────────────────────────────────────────────
const SAMPLES = {
    spam: `Subject: CONGRATULATIONS! You've been selected as our WINNER!

Dear Lucky Winner,

You have been randomly selected from over 2,000,000 email addresses to receive our Grand Prize of $5,000,000! 
To claim your prize IMMEDIATELY, click the link below and provide your personal details for the wire transfer.

CLAIM YOUR PRIZE NOW >>> http://claim-your-prize-now.xyz/winner

This offer expires in 24 HOURS! Act NOW or lose your winnings FOREVER!

Best regards,
International Lottery Commission
support@free-lottery-winner.tk`,

    ham: `Subject: Team meeting agenda for Thursday

Hi everyone,

Just wanted to share the agenda for our weekly team meeting this Thursday at 2 PM:

1. Sprint review and demo of the new authentication module
2. Discussion on the new CI/CD pipeline improvements
3. Quick update on the customer feedback survey results
4. Planning for next quarter's roadmap

Please add any items you'd like to discuss by replying to this email.

Thanks,
Sarah Johnson
Engineering Manager`,

    phishing: `Subject: URGENT: Your Account Has Been Suspended!

Dear Customer,

We have detected unauthorized access to your account. Your account has been temporarily suspended due to suspicious login activity detected from an unknown device.

To restore your account access, please verify your identity immediately by clicking the secure link below:

http://secure-banking-verify.xyz/login?user=verify&token=abc123

You must confirm your identity within 48 hours or your account will be permanently locked. Please have the following ready:
- Your Social Security Number
- Credit card number and PIN
- Date of birth
- Mother's maiden name

This is an automated security alert. Do not reply to this email.

Security Team
noreply@security-alerts-banking.top`
};

// ── DOM Ready ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Load theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeUI(savedTheme);

    // Setup listeners
    const emailInput = document.getElementById('emailInput');
    const charCount = document.getElementById('charCount');
    const fileInput = document.getElementById('emailFile');
    const batchFile = document.getElementById('batchFile');
    const batchZone = document.getElementById('batchUploadZone');

    emailInput.addEventListener('input', () => {
        charCount.textContent = emailInput.value.length + ' chars';
    });

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (evt) => {
            emailInput.value = evt.target.result;
            emailInput.dispatchEvent(new Event('input'));
            showToast(`Loaded ${file.name}`, 'success');
        };
        reader.onerror = () => showToast('Error reading file', 'danger');
        reader.readAsText(file);
    });

    // Batch file upload
    batchFile.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        batchClassifyCSV(file);
    });

    // Drag and drop for batch
    batchZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        batchZone.classList.add('dragover');
    });
    batchZone.addEventListener('dragleave', () => batchZone.classList.remove('dragover'));
    batchZone.addEventListener('drop', (e) => {
        e.preventDefault();
        batchZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.csv')) {
            batchClassifyCSV(file);
        } else {
            showToast('Please upload a CSV file', 'warning');
        }
    });

    // Keyboard shortcut
    emailInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            classifyEmail();
        }
    });

    // Load initial data
    loadStats();
    loadHistory();
    checkExistingSession();
    loadUserInfo();
    if (window.lucide) lucide.createIcons();
});

// ── Theme ──────────────────────────────────────────────────────
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeUI(next);
}

function updateThemeUI(theme) {
    const icon = document.getElementById('themeIcon');
    const toggleIcon = document.getElementById('themeToggleIcon');
    const label = document.getElementById('themeLabel');
    if (theme === 'dark') {
        if (icon) icon.innerHTML = '<i data-lucide="moon"></i>';
        if (toggleIcon) toggleIcon.innerHTML = '<i data-lucide="moon"></i>';
        if (label) label.textContent = 'Dark Mode';
    } else {
        if (icon) icon.innerHTML = '<i data-lucide="sun"></i>';
        if (toggleIcon) toggleIcon.innerHTML = '<i data-lucide="sun"></i>';
        if (label) label.textContent = 'Light Mode';
    }
    if (window.lucide) lucide.createIcons();
}

// ── Navigation ─────────────────────────────────────────────────
function switchPanel(name) {
    // Get current active panel
    const currentPanel = document.querySelector('.panel.active');
    const targetPanel = document.getElementById(`panel-${name}`);
    
    if (currentPanel === targetPanel) return; // Same panel, do nothing
    
    // Animate out current panel
    if (currentPanel) {
        currentPanel.style.opacity = '0';
        currentPanel.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
            currentPanel.classList.remove('active');
            currentPanel.style.opacity = '';
            currentPanel.style.transform = '';
        }, 200);
    }
    
    // Update nav items
    document.querySelectorAll('.nav-item[data-panel]').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-panel="${name}"]`);
    if (navItem) navItem.classList.add('active');

    // Show target panel with animation
    setTimeout(() => {
        if (targetPanel) {
            targetPanel.classList.add('active');
        }
    }, 200);

    // Update title
    const titles = {
        analyze: 'Email Analysis',
        batch: 'Batch Processing',
        inbox: 'Live Inbox',
        analytics: 'Analytics Dashboard',
        history: 'Analysis History'
    };
    document.getElementById('pageTitle').textContent = titles[name] || 'Dashboard';

    // Load data for panel
    if (name === 'analytics') loadAnalytics();
    if (name === 'history') loadHistory();
    if (name === 'inbox') checkExistingSession();

    closeSidebar();
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('active');
}

function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('active');
}


// ── Stats ──────────────────────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        const d = await res.json();

        // Use default model stats or top-level stats
        const modelData = d.models ? d.models[d.default_model || 'nb'] : d;
        animateValue('statAccuracy', (modelData.accuracy || d.accuracy || 0) * 100, '%');
        animateValue('statPrecision', (modelData.precision || d.precision || 0) * 100, '%');
        animateValue('statRecall', (modelData.recall || d.recall || 0) * 100, '%');
        animateValue('statF1', (modelData.f1_score || d.f1_score || 0) * 100, '%');
        animateValue('statPredictions', d.predictions_made || 0, '');
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

function animateValue(id, end, suffix) {
    const el = document.getElementById(id);
    if (!el) return;
    const isFloat = suffix === '%';
    const duration = 1200;
    const start = performance.now();

    function step(ts) {
        const progress = Math.min((ts - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const val = eased * end;
        el.textContent = (isFloat ? val.toFixed(1) : Math.floor(val)) + suffix;
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ── Toast ──────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    const icons = { success: '<i data-lucide="check-circle" class="inline-icon"></i>', danger: '<i data-lucide="alert-triangle" class="inline-icon"></i>', warning: '<i data-lucide="alert-circle" class="inline-icon"></i>', info: '<i data-lucide="info" class="inline-icon"></i>' };
    const toast = document.createElement('div');
    toast.className = `toast-msg ${type}`;
    toast.innerHTML = `<span>${icons[type] || ''}</span><span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// ── Single Classification ──────────────────────────────────────
async function classifyEmail() {
    const text = document.getElementById('emailInput').value.trim();
    if (!text) {
        showToast('Please paste email text or upload a file first.', 'warning');
        return;
    }

    const btn = document.getElementById('classifyBtn');
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing...';

    // Show loading overlay (near-instant updates)
    showLoading('Initializing AI Engine');
    
    // Instead of hardcoded delays, we'll just update the status quickly
    // or let the backend response trigger the next phase.
    const updateStatus = (msg) => updateLoadingMessage(msg);
    
    setTimeout(() => updateStatus('Running AI Analysis...'), 100);

    try {
        const res = await fetch('/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_text: text, model: selectedModel })
        });
        const d = await res.json();

        if (d.error) {
            hideLoading();
            showToast(d.error, 'danger');
            return;
        }

        // Final loading message before showing results
        updateLoadingMessage('Rendering results');
        
        hideLoading();

        // Store for PDF report
        lastAnalysisResult = d;
        lastAnalysisText = text;

        renderResult(d);
        renderXAI(d);
        renderPhishing(d.phishing);
        renderURLScan(d.url_scan);
        renderIntelligence(d.intelligence);
        renderHighlightedEmail(d.highlighted_text, d.prediction);

        loadHistory();
        loadStats();
    } catch (err) {
        messageTimeouts.forEach(t => clearTimeout(t));
        hideLoading();
        showToast('Network error. Is server running?', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// ── Render Result Verdict ──────────────────────────────────────
function renderResult(d) {
    // Show/Hide containers
    document.getElementById('resultPlaceholder').style.display = 'none';
    document.getElementById('analysisResults').style.display = 'block';
    document.getElementById('analysisEvidence').style.display = 'block';

    const isSpam = d.prediction === 'spam';
    
    // 1. Render Verdict Header
    const vHeader = document.getElementById('verdictHeader');
    vHeader.innerHTML = `
        <div class="verdict-header-box">
            <div class="verdict-badge ${isSpam ? 'spam' : 'safe'}">
                ${isSpam ? '<i data-lucide="alert-triangle"></i> SPAM DETECTED' : '<i data-lucide="shield-check"></i> SAFE EMAIL'}
            </div>
            <div class="verdict-subtitle">Analyzed by Unified AI Engine • ${d.model_name || 'Ensemble'}</div>
        </div>
    `;

    // 2. Render Risk Meter (SVG Gauge)
    renderRiskMeter(d.spam_probability);

    // 3. Render Confidence Bars
    renderConfidenceBars(d);

    // 4. Render Model Votes (if ensemble)
    const votesDiv = document.getElementById('modelVotes');
    if (d.model_used === 'ensemble' && d.individual_predictions) {
        votesDiv.style.display = 'grid';
        votesDiv.innerHTML = Object.entries(d.individual_predictions).map(([key, data]) => {
            const mSpam = data.prediction === 'spam';
            return `
                <div class="vote-card">
                    <div class="vote-name">${data.model_name}</div>
                    <div class="vote-result ${mSpam ? 'spam' : 'safe'}">${mSpam ? 'SPAM' : 'SAFE'}</div>
                </div>
            `;
        }).join('');
    } else {
        votesDiv.style.display = 'none';
    }

    if (window.lucide) lucide.createIcons();
}

function renderRiskMeter(score) {
    const container = document.getElementById('riskMeterContainer');
    const color = score > 70 ? '#ef4444' : (score > 30 ? '#f59e0b' : '#06d6a0');
    const radius = 30;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    container.innerHTML = `
        <div class="gauge-container">
            <svg class="gauge-svg" width="70" height="70">
                <circle class="gauge-bg" cx="35" cy="35" r="${radius}"></circle>
                <circle class="gauge-fill" cx="35" cy="35" r="${radius}" 
                    style="stroke: ${color}; stroke-dasharray: ${circumference}; stroke-dashoffset: ${circumference};">
                </circle>
            </svg>
            <div class="gauge-text" style="color: ${color}">${Math.round(score)}%</div>
        </div>
    `;

    // Animate the fill
    setTimeout(() => {
        const fill = container.querySelector('.gauge-fill');
        if (fill) fill.style.strokeDashoffset = offset;
    }, 100);
}

function renderConfidenceBars(d) {
    const container = document.getElementById('confidenceBars');
    const isSpam = d.prediction === 'spam';
    
    container.innerHTML = `
        <div class="conf-bar-item">
            <div class="conf-label">SPAM</div>
            <div class="conf-progress">
                <div class="conf-fill" style="width: 0%; background: #ef4444;" id="spamConfFill"></div>
            </div>
            <div class="conf-val">${d.spam_probability}%</div>
        </div>
        <div class="conf-bar-item">
            <div class="conf-label">SAFE</div>
            <div class="conf-progress">
                <div class="conf-fill" style="width: 0%; background: #06d6a0;" id="hamConfFill"></div>
            </div>
            <div class="conf-val">${d.ham_probability}%</div>
        </div>
    `;

    setTimeout(() => {
        document.getElementById('spamConfFill').style.width = d.spam_probability + '%';
        document.getElementById('hamConfFill').style.width = d.ham_probability + '%';
    }, 200);
}

// ── Download PDF Report ────────────────────────────────────────
function downloadPDFReport() {
    if (!lastAnalysisResult) {
        showToast('No analysis data available. Analyze an email first.', 'warning');
        return;
    }

    const btn = document.getElementById('dlPdfBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner" style="width: 16px; height: 16px;"></span> Generating PDF...';
    btn.disabled = true;

    // Send data to server for PDF generation
    fetch('/api/generate-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            result: lastAnalysisResult,
            email_text: lastAnalysisText
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to generate PDF');
        }
        return response.blob();
    })
    .then(blob => {
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        
        // Extract filename from Content-Disposition header or generate
        const now = new Date();
        const reportId = `MG-${now.toISOString().split('T')[0].replace(/-/g, '')}-${now.getHours().toString().padStart(2, '0')}${now.getMinutes().toString().padStart(2, '0')}`;
        a.download = `MailGuard_Report_${reportId}.pdf`;
        
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        btn.innerHTML = originalText;
        btn.disabled = false;
        showToast('Report downloaded successfully', 'success');
    })
    .catch(err => {
        console.error('[PDF] Error:', err);
        btn.innerHTML = originalText;
        btn.disabled = false;
        showToast('Failed to generate PDF: ' + err.message, 'danger');
    });
}

// ── Render XAI ─────────────────────────────────────────────────
function renderXAI(d) {
    const kwDiv = document.getElementById('xaiKeywords');
    const contribDiv = document.getElementById('xaiContributions');

    if (!d.keyword_contributions || d.keyword_contributions.length === 0) {
        return;
    }

    const isSpam = d.prediction === 'spam';

    // Keyword tags
    kwDiv.innerHTML = d.detected_keywords.map(kw =>
        `<span class="xai-tag ${isSpam ? 'spam' : 'safe'}">${escapeHtml(kw)}</span>`
    ).join('');

    // Contribution bars
    const maxContrib = Math.max(...d.keyword_contributions.map(k => Math.abs(k.contribution)));
    contribDiv.innerHTML = d.keyword_contributions.slice(0, 6).map(k => {
        const isPositive = k.contribution > 0;
        const color = isPositive ? '#ef4444' : '#06d6a0';
        const pct = maxContrib > 0 ? (Math.abs(k.contribution) / maxContrib * 100) : 0;
        
        return `
            <div class="conf-bar-item" style="margin-bottom: 8px;">
                <div class="conf-label" style="width: 80px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(k.word)}</div>
                <div class="conf-progress">
                    <div class="conf-fill" style="width: 0%; background: ${color};" data-width="${pct}"></div>
                </div>
                <div class="conf-val" style="width: 45px;">${k.contribution > 0 ? '+' : ''}${k.contribution.toFixed(3)}</div>
            </div>
        `;
    }).join('');

    // Animate bars
    setTimeout(() => {
        contribDiv.querySelectorAll('.conf-fill').forEach(bar => {
            bar.style.width = bar.getAttribute('data-width') + '%';
        });
    }, 300);

    if (window.lucide) lucide.createIcons();
}

// ── Render Phishing ────────────────────────────────────────────
function renderPhishing(phishing) {
    const div = document.getElementById('phishingResult');
    if (!phishing) {
        div.innerHTML = '<p style="color:var(--text-muted); font-size:12px;">No phishing analysis available.</p>';
        return;
    }

    const threats = phishing.threats || [];
    if (threats.length === 0) {
        div.innerHTML = `
            <div class="threat-row low">
                <div class="threat-info">
                    <h5>Clean Scan</h5>
                    <p>No phishing indicators detected in this email.</p>
                </div>
            </div>
        `;
        return;
    }

    div.innerHTML = threats.map(t => `
        <div class="threat-row ${t.severity === 'high' ? 'high' : (t.severity === 'medium' ? 'med' : 'low')}">
            <div class="threat-info">
                <h5>${escapeHtml(t.type)}</h5>
                <p>${escapeHtml(t.details)}</p>
            </div>
        </div>
    `).join('');
    
    if (window.lucide) lucide.createIcons();
}

// ── Render URL Scan ────────────────────────────────────────────
function renderURLScan(urlScan) {
    const div = document.getElementById('urlResult');
    if (!urlScan || urlScan.length === 0) {
        div.innerHTML = '<p style="color:var(--text-muted); font-size:12px;">No URLs detected in email.</p>';
        return;
    }

    div.innerHTML = `
        <div style="max-height: 150px; overflow-y: auto;">
            ${urlScan.map(u => {
                const isShortener = u.is_shortener;
                const riskClass = u.status === 'Safe' ? 'low' : (u.status === 'Suspicious' ? 'med' : 'high');
                return `
                    <div class="threat-row ${riskClass}" style="padding: 6px 10px;">
                        <div class="threat-info">
                            <h5 style="font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px;">
                                ${escapeHtml(u.url)}
                            </h5>
                            <p style="font-size: 10px;">${u.is_https ? 'HTTPS' : 'HTTP'} • ${u.is_trusted ? 'Trusted' : 'Unknown'} ${isShortener ? '• Shortener' : ''}</p>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

// ── Render Email Intelligence ──────────────────────────────────
function renderIntelligence(intel) {
    const div = document.getElementById('intelResult');
    if (!intel) return;

    const sentimentColor = intel.sentiment === 'Positive' ? 'var(--accent-cyan)' :
        intel.sentiment === 'Negative' ? '#ef4444' : 'var(--accent-orange)';

    div.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
            <div class="vote-card" style="text-align: left;">
                <div class="vote-name">Language</div>
                <div class="vote-result" style="color: var(--text-heading)">${escapeHtml(intel.language)}</div>
            </div>
            <div class="vote-card" style="text-align: left;">
                <div class="vote-name">Sentiment</div>
                <div class="vote-result" style="color: ${sentimentColor}">${intel.sentiment}</div>
            </div>
            <div class="vote-card" style="text-align: left;">
                <div class="vote-name">Words</div>
                <div class="vote-result" style="color: var(--text-heading)">${intel.word_count}</div>
            </div>
            <div class="vote-card" style="text-align: left;">
                <div class="vote-name">Links</div>
                <div class="vote-result" style="color: ${intel.link_count > 0 ? '#f59e0b' : 'var(--text-heading)'}">${intel.link_count}</div>
            </div>
        </div>
    `;
}

// ── Render Highlighted Email ───────────────────────────────────
function renderHighlightedEmail(text, prediction) {
    const div = document.getElementById('highlightedEmail');
    if (!text) return;

    const isSpam = prediction === 'spam';
    const hClass = isSpam ? 'highlight-word' : 'highlight-word safe';

    let html = escapeHtml(text);
    html = html.replace(/\[\[HIGHLIGHT\]\]/g, `<span class="${hClass}">`);
    html = html.replace(/\[\[\/HIGHLIGHT\]\]/g, '</span>');

    div.innerHTML = html;
}

// ── Batch Classification ───────────────────────────────────────
async function batchClassify() {
    const raw = document.getElementById('batchInput').value.trim();
    if (!raw) {
        showToast('Enter multiple emails separated by blank lines.', 'warning');
        return;
    }

    const emails = raw.split(/\n\s*\n/).filter(e => e.trim());
    if (!emails.length) return;

    const btn = document.getElementById('batchBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Processing...';

    try {
        const res = await fetch('/api/batch_predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emails, model: selectedModel })
        });
        const d = await res.json();

        if (d.error) {
            showToast(d.error, 'danger');
            return;
        }

        renderBatchResults(d);
        loadHistory();
        loadStats();
        showToast(`Classified ${d.total} emails`, 'success');
    } catch (err) {
        showToast('Network error.', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="zap" class="inline-icon"></i> Classify Batch';
        if (window.lucide) lucide.createIcons();
    }
}

async function batchClassifyCSV(file) {
    const btn = document.getElementById('batchBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Uploading...';

    const formData = new FormData();
    formData.append('file', file);
    formData.append('model', selectedModel);

    try {
        const res = await fetch('/api/batch_predict', {
            method: 'POST',
            body: formData
        });
        const d = await res.json();

        if (d.error) {
            showToast(d.error, 'danger');
            return;
        }

        renderBatchResults(d);
        loadHistory();
        loadStats();
        showToast(`Classified ${d.total} emails from CSV`, 'success');
    } catch (err) {
        showToast('Failed to process CSV.', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="zap" class="inline-icon"></i> Classify Batch';
        if (window.lucide) lucide.createIcons();
    }
}

function renderBatchResults(d) {
    const container = document.getElementById('batchResults');

    let html = `
        <div class="batch-summary">
            <div class="batch-stat">
                <div class="bs-value">${d.total}</div>
                <div class="bs-label">Total</div>
            </div>
            <div class="batch-stat">
                <div class="bs-value" style="color:#ef4444;">${d.spam_count}</div>
                <div class="bs-label">Spam</div>
            </div>
            <div class="batch-stat">
                <div class="bs-value" style="color:var(--accent-cyan);">${d.ham_count}</div>
                <div class="bs-label">Safe</div>
            </div>
            <div class="batch-stat">
                <div class="bs-value" style="color:var(--accent-orange);">${d.high_risk_count || 0}</div>
                <div class="bs-label">High Risk</div>
            </div>
            <div class="batch-stat">
                <div class="bs-value">${d.avg_confidence || 0}%</div>
                <div class="bs-label">Avg Confidence</div>
            </div>
        </div>

        <div style="overflow-x:auto;">
            <table class="batch-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Email Preview</th>
                        <th>Prediction</th>
                        <th>Spam Prob.</th>
                        <th>Risk Level</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
    `;

    d.results.forEach((r, i) => {
        const isSpam = r.prediction === 'spam';
        const statusClass = isSpam ? 'high-risk' : 'safe';
        const riskLevel = r.phishing ? r.phishing.risk_level : 'Low';
        const riskClass = riskLevel.toLowerCase();

        html += `
            <tr>
                <td>${i + 1}</td>
                <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(r.snippet || '')}</td>
                <td><span class="status-badge ${statusClass}">${isSpam ? 'SPAM' : 'SAFE'}</span></td>
                <td>${r.spam_probability}%</td>
                <td><span class="status-badge ${riskClass === 'high' ? 'high-risk' : riskClass === 'medium' ? 'suspicious' : 'safe'}">${riskLevel}</span></td>
                <td>${r.confidence}%</td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// ── History ────────────────────────────────────────────────────
async function loadHistory() {
    try {
        const search = document.getElementById('historySearch')?.value || '';
        const res = await fetch(`/api/history?filter=${historyFilter}&search=${encodeURIComponent(search)}&limit=50`);
        const items = await res.json();
        const list = document.getElementById('historyList');
        const badge = document.getElementById('historyCount');

        if (badge) badge.textContent = items.length;

        if (items.length === 0) {
            renderEmptyState(list, {
                icon: 'inbox',
                title: 'No Analysis History',
                description: 'Your analyzed emails will appear here. Start by analyzing an email to build your history.',
                action: "switchPanel('analyze')",
                actionText: 'Analyze Email',
                actionIcon: 'scan-search'
            });
            return;
        }

        list.innerHTML = items.map(h => {
            const isSpam = h.prediction === 'spam';
            const badgeClass = isSpam ? 'high-risk' : 'safe';
            const riskClass = (h.risk_level || 'Low').toLowerCase();
            const time = h.timestamp ? new Date(h.timestamp).toLocaleString([], {
                month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
            }) : '';

            return `
                <div class="history-item">
                    <span class="hi-badge"><span class="status-badge ${badgeClass}">${isSpam ? 'SPAM' : 'SAFE'}</span></span>
                    <span class="hi-snippet">${escapeHtml(h.snippet || '')}</span>
                    <div class="hi-meta">
                        <span class="hi-confidence">${h.confidence ? h.confidence.toFixed(1) : '—'}%</span>
                        <span class="hi-risk"><span class="status-badge ${riskClass === 'high' ? 'high-risk' : riskClass === 'medium' ? 'suspicious' : 'safe'}" style="font-size:10px;">${h.risk_level || 'Low'}</span></span>
                        <span class="hi-time">${time}</span>
                    </div>
                </div>
            `;
        }).join('');
        if (window.lucide) lucide.createIcons();
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

function setFilter(filter) {
    historyFilter = filter;
    document.querySelectorAll('.filter-chip').forEach(c => {
        c.classList.toggle('active', c.dataset.filter === filter);
    });
    loadHistory();
}

// ── Analytics ──────────────────────────────────────────────────
async function loadAnalytics() {
    try {
        const res = await fetch('/api/analytics');
        const d = await res.json();

        renderCharts(d);
        if (window.lucide) lucide.createIcons();
    } catch (err) {
        console.error('Failed to load analytics:', err);
    }
}

function renderCharts(d) {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#475569';
    const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';

    // Destroy existing charts
    Object.values(charts).forEach(c => c.destroy());
    charts = {};

    // 1. Spam vs Ham (Doughnut)
    const ctx1 = document.getElementById('chartSpamHam');
    if (ctx1) {
        charts.spamHam = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['Spam', 'Ham (Safe)'],
                datasets: [{
                    data: [d.spam_ham.spam, d.spam_ham.ham],
                    backgroundColor: ['#ef4444', '#06d6a0'],
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { position: 'bottom', labels: { color: textColor, padding: 16, font: { family: 'Inter', size: 12 } } },
                }
            }
        });
    }

    // 2. Risk Distribution (Doughnut)
    const ctx2 = document.getElementById('chartRisk');
    if (ctx2) {
        charts.risk = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    data: [d.risk_distribution.low, d.risk_distribution.medium, d.risk_distribution.high],
                    backgroundColor: ['#06d6a0', '#f59e0b', '#ef4444'],
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { position: 'bottom', labels: { color: textColor, padding: 16, font: { family: 'Inter', size: 12 } } },
                }
            }
        });
    }

    // 3. Model Comparison (Bar)
    const ctx3 = document.getElementById('chartModels');
    if (ctx3 && d.model_comparison && d.model_comparison.length > 0) {
        charts.models = new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: d.model_comparison.map(m => m.name),
                datasets: [
                    {
                        label: 'Accuracy',
                        data: d.model_comparison.map(m => (m.accuracy * 100).toFixed(1)),
                        backgroundColor: '#3b82f6',
                        borderRadius: 4,
                    },
                    {
                        label: 'Precision',
                        data: d.model_comparison.map(m => (m.precision * 100).toFixed(1)),
                        backgroundColor: '#7c3aed',
                        borderRadius: 4,
                    },
                    {
                        label: 'Recall',
                        data: d.model_comparison.map(m => (m.recall * 100).toFixed(1)),
                        backgroundColor: '#06d6a0',
                        borderRadius: 4,
                    },
                    {
                        label: 'F1 Score',
                        data: d.model_comparison.map(m => (m.f1_score * 100).toFixed(1)),
                        backgroundColor: '#ec4899',
                        borderRadius: 4,
                    },
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: { color: textColor, font: { family: 'Inter' } },
                        grid: { color: gridColor },
                    },
                    x: {
                        ticks: { color: textColor, font: { family: 'Inter' } },
                        grid: { display: false },
                    }
                },
                plugins: {
                    legend: { labels: { color: textColor, font: { family: 'Inter', size: 11 } } }
                }
            }
        });
    }

    // 4. Confidence Trend (Line)
    const ctx4 = document.getElementById('chartTrend');
    if (ctx4 && d.recent_trend && d.recent_trend.length > 0) {
        const reversed = [...d.recent_trend].reverse();
        charts.trend = new Chart(ctx4, {
            type: 'line',
            data: {
                labels: reversed.map((_, i) => `#${i + 1}`),
                datasets: [
                    {
                        label: 'Confidence %',
                        data: reversed.map(r => r.confidence),
                        borderColor: '#06d6a0',
                        backgroundColor: 'rgba(6, 214, 160, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointBackgroundColor: '#06d6a0',
                    },
                    {
                        label: 'Risk Score',
                        data: reversed.map(r => r.risk_score),
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointBackgroundColor: '#ef4444',
                    },
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: textColor, font: { family: 'Inter' } },
                        grid: { color: gridColor },
                    },
                    x: {
                        ticks: { color: textColor, font: { family: 'Inter' } },
                        grid: { display: false },
                    }
                },
                plugins: {
                    legend: { labels: { color: textColor, font: { family: 'Inter', size: 11 } } }
                }
            }
        });
    }
}

// ── Helpers ────────────────────────────────────────────────────
function loadSample(type) {
    document.getElementById('emailInput').value = SAMPLES[type];
    document.getElementById('emailInput').dispatchEvent(new Event('input'));
    showToast(`${type.charAt(0).toUpperCase() + type.slice(1)} sample loaded`, 'info');
}

function clearInput() {
    // Clear input fields
    document.getElementById('emailInput').value = '';
    document.getElementById('emailFile').value = '';
    document.getElementById('charCount').textContent = '0 chars';
    
    // Show placeholder, hide results
    document.getElementById('resultPlaceholder').style.display = 'block';
    document.getElementById('analysisResults').style.display = 'none';
    document.getElementById('analysisEvidence').style.display = 'none';
    
    // Clear all analysis content
    const verdictHeader = document.getElementById('verdictHeader');
    const riskMeterContainer = document.getElementById('riskMeterContainer');
    const confidenceBars = document.getElementById('confidenceBars');
    const modelVotes = document.getElementById('modelVotes');
    const phishingResult = document.getElementById('phishingResult');
    const urlResult = document.getElementById('urlResult');
    const intelResult = document.getElementById('intelResult');
    const highlightedEmail = document.getElementById('highlightedEmail');
    const xaiKeywords = document.getElementById('xaiKeywords');
    const xaiContributions = document.getElementById('xaiContributions');
    
    if (verdictHeader) verdictHeader.innerHTML = '';
    if (riskMeterContainer) riskMeterContainer.innerHTML = '';
    if (confidenceBars) confidenceBars.innerHTML = '';
    if (modelVotes) modelVotes.innerHTML = '';
    if (phishingResult) phishingResult.innerHTML = '';
    if (urlResult) urlResult.innerHTML = '';
    if (intelResult) intelResult.innerHTML = '';
    if (highlightedEmail) highlightedEmail.innerHTML = '';
    if (xaiKeywords) xaiKeywords.innerHTML = '';
    if (xaiContributions) xaiContributions.innerHTML = '';
    
    // Reset state variables
    lastAnalysisResult = null;
    lastAnalysisText = '';
    
    showToast('Analysis cleared', 'info');
}

function escapeHtml(s) {
    if (!s) return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMAP Inbox Integration
// ═══════════════════════════════════════════════════════════════════════════════

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;
}

function toggleAdvancedSettings() {
    const group = document.getElementById('imapServerGroup');
    group.style.display = group.style.display === 'none' ? 'block' : 'none';
}

async function detectIMAPServer() {
    const email = document.getElementById('imapEmail').value.trim();
    if (!email || !email.includes('@')) return;
    
    try {
        const res = await fetch('/api/imap/detect-server', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        
        if (data.imap_server) {
            document.getElementById('imapServer').placeholder = `Auto-detected: ${data.imap_server}`;
        }
    } catch (err) {
        console.error('Failed to detect server:', err);
    }
}

function clearInboxFields() {
    document.getElementById('imapEmail').value = '';
    document.getElementById('imapPassword').value = '';
    const serverInput = document.getElementById('imapServer');
    if (serverInput) {
        serverInput.value = '';
        serverInput.placeholder = 'Auto-detected';
    }
    showToast('Credentials cleared', 'info');
}

async function connectInbox() {
    const email = document.getElementById('imapEmail').value.trim();
    const password = document.getElementById('imapPassword').value.trim();
    const imapServer = document.getElementById('imapServer').value.trim();
    
    if (!email || !email.includes('@')) {
        showToast('Please enter a valid email address', 'warning');
        return;
    }
    if (!password) {
        showToast('Please enter your app password', 'warning');
        return;
    }
    
    const btn = document.getElementById('connectInboxBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Connecting...';
    
    try {
        const res = await fetch('/api/imap/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, imap_server: imapServer })
        });
        const data = await res.json();
        
        if (data.error) {
            showToast('Error: ' + data.error, 'danger');
            return;
        }
        
        // Save session
        imapSession = {
            session_id: data.session_id,
            email: data.email
        };
        localStorage.setItem('imapSession', JSON.stringify(imapSession));
        
        // Clear password field
        document.getElementById('imapPassword').value = '';
        
        showToast('Connected successfully!', 'success');
        showConnectedState();
        refreshInbox();
        
    } catch (err) {
        showToast('Connection failed. For Gmail, you must use an App Password (not your regular password). Click "Gmail" link below for instructions.', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="link" class="inline-icon"></i> Connect Inbox';
        if (window.lucide) lucide.createIcons();
    }
}

async function disconnectInbox() {
    if (!imapSession) return;
    
    // Stop auto-refresh
    stopAutoRefresh();
    
    try {
        await fetch('/api/imap/disconnect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: imapSession.session_id })
        });
    } catch (err) {
        console.error('Disconnect error:', err);
    }
    
    // Clear session
    imapSession = null;
    localStorage.removeItem('imapSession');
    currentInboxEmails = [];
    
    showToast('Disconnected', 'info');
    showConnectState();
}

async function checkExistingSession() {
    const saved = localStorage.getItem('imapSession');
    if (!saved) {
        showConnectState();
        return;
    }
    
    try {
        imapSession = JSON.parse(saved);
        
        // Check if it's a demo session
        if (imapSession.demo) {
            showConnectedState();
            loadDemoEmails();
            return;
        }
        
        // Verify session is still valid
        const res = await fetch(`/api/imap/session/${imapSession.session_id}`);
        if (res.ok) {
            showConnectedState();
            loadFetchedEmails();
        } else {
            // Session expired
            imapSession = null;
            localStorage.removeItem('imapSession');
            showConnectState();
        }
    } catch (err) {
        showConnectState();
    }
}

function showConnectState() {
    document.getElementById('inboxConnectCard').style.display = 'block';
    document.getElementById('inboxConnectedCard').style.display = 'none';
}

function showConnectedState() {
    document.getElementById('inboxConnectCard').style.display = 'none';
    document.getElementById('inboxConnectedCard').style.display = 'block';
    document.getElementById('connectedEmail').textContent = imapSession?.email || '';
}

async function refreshInbox() {
    if (!imapSession) return;
    
    // Handle demo mode
    if (imapSession.demo) {
        loadDemoEmails();
        return;
    }
    
    const emailList = document.getElementById('emailList');
    emailList.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon"><span class="spinner" style="width:48px;height:48px;"></span></div>
            <div class="empty-text">Fetching emails...</div>
        </div>
    `;
    
    try {
        const res = await fetch('/api/imap/fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: imapSession.session_id, limit: 30 })
        });
        const data = await res.json();
        
        if (data.error) {
            showToast(data.error, 'danger');
            emailList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon"><i data-lucide="alert-triangle" style="width:48px;height:48px"></i></div>
                    <div class="empty-text">Failed to fetch emails</div>
                </div>
            `;
            if (window.lucide) lucide.createIcons();
            return;
        }
        
        currentInboxEmails = data.emails || [];
        document.getElementById('lastFetchTime').textContent = 'Just now';
        document.getElementById('inboxCount').textContent = currentInboxEmails.length;
        document.getElementById('inboxCount').style.display = 'inline-flex';
        
        renderInboxEmails();
        showToast(`Fetched ${data.count} emails`, 'success');
        
    } catch (err) {
        showToast('Failed to fetch emails', 'danger');
        emailList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon"><i data-lucide="alert-triangle" style="width:48px;height:48px"></i></div>
                <div class="empty-text">Failed to fetch emails</div>
            </div>
        `;
        if (window.lucide) lucide.createIcons();
    }
}

async function loadFetchedEmails() {
    if (!imapSession) return;
    
    try {
        const res = await fetch(`/api/imap/emails?session_id=${imapSession.session_id}&limit=50`);
        const data = await res.json();
        
        if (Array.isArray(data)) {
            currentInboxEmails = data;
            renderInboxEmails();
            
            if (data.length > 0) {
                document.getElementById('inboxCount').textContent = data.length;
                document.getElementById('inboxCount').style.display = 'inline-flex';
            }
        }
    } catch (err) {
        console.error('Failed to load emails:', err);
    }
}

function renderInboxEmails() {
    const emailList = document.getElementById('emailList');
    
    // Filter emails
    let filtered = currentInboxEmails;
    if (inboxFilter === 'spam') {
        filtered = currentInboxEmails.filter(e => e.prediction === 'spam');
    } else if (inboxFilter === 'ham') {
        filtered = currentInboxEmails.filter(e => e.prediction === 'ham');
    }
    
    if (filtered.length === 0) {
        emailList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon"><i data-lucide="inbox" style="width:48px;height:48px"></i></div>
                <div class="empty-text">${inboxFilter === 'all' ? 'No emails fetched yet' : `No ${inboxFilter} emails found`}</div>
                ${inboxFilter === 'all' ? `<button class="btn btn-primary" onclick="refreshInbox()" style="margin-top:16px;"><i data-lucide="download" class="inline-icon"></i> Fetch Emails</button>` : ''}
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        return;
    }
    
    emailList.innerHTML = filtered.map(email => {
        const isSpam = email.prediction === 'spam';
        const riskClass = (email.risk_level || 'Low').toLowerCase();
        const date = email.date ? new Date(email.date).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
        
        return `
            <div class="email-item ${isSpam ? 'spam' : 'safe'}">
                <div class="email-status">
                    <span class="status-badge ${isSpam ? 'high-risk' : 'safe'}">${isSpam ? 'SPAM' : 'SAFE'}</span>
                </div>
                <div class="email-content">
                    <div class="email-header">
                        <span class="email-sender">${escapeHtml(email.sender || 'Unknown')}</span>
                        <span class="email-date">${date}</span>
                    </div>
                    <div class="email-subject">${escapeHtml(email.subject || '(No Subject)')}</div>
                    <div class="email-preview">${escapeHtml((email.body || '').substring(0, 120))}...</div>
                    <div class="email-meta">
                        <span class="email-confidence">${email.confidence?.toFixed(1) || 0}% confidence</span>
                        <span class="risk-badge ${riskClass}">${email.risk_level || 'Low'} Risk</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    if (window.lucide) lucide.createIcons();
}

function filterInbox(filter) {
    inboxFilter = filter;
    
    // Update UI
    document.querySelectorAll('#panel-inbox .filter-chip').forEach(chip => {
        chip.classList.toggle('active', chip.dataset.filter === filter);
    });
    
    renderInboxEmails();
}

function toggleAutoRefresh() {
    const toggle = document.getElementById('autoRefreshToggle');
    
    if (toggle.checked) {
        // Start auto-refresh every 30 seconds
        autoRefreshInterval = setInterval(() => {
            if (imapSession) {
                refreshInbox();
            }
        }, 30000);
        showToast('Auto-refresh enabled (30s)', 'info');
    } else {
        stopAutoRefresh();
        showToast('Auto-refresh disabled', 'info');
    }
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
    const toggle = document.getElementById('autoRefreshToggle');
    if (toggle) toggle.checked = false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Demo mode - connect without real credentials
async function connectDemo() {
    const email = document.getElementById('imapEmail').value.trim() || 'demo@example.com';
    
    const btn = document.getElementById('connectInboxBtn');
    if (btn) btn.disabled = true;
    
    try {
        const res = await fetch('/api/imap/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: 'demo', demo: true })
        });
        const data = await res.json();
        
        if (data.error) {
            showToast('Error: ' + data.error, 'danger');
            return;
        }
        
        imapSession = {
            session_id: data.session_id,
            email: data.email,
            demo: true
        };
        localStorage.setItem('imapSession', JSON.stringify(imapSession));
        
        showToast('Demo mode activated!', 'success');
        showConnectedState();
        
        // Load demo emails
        loadDemoEmails();
        
    } catch (err) {
        console.error('Demo mode error:', err);
        showToast('Demo mode failed: ' + err.message, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// User Authentication
// ═══════════════════════════════════════════════════════════════════════════════

async function loadUserInfo() {
    try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        
        if (data.authenticated) {
            const userNameEl = document.getElementById('userName');
            const userRoleEl = document.getElementById('userRole');
            
            if (userNameEl) userNameEl.textContent = data.user.username;
            if (userRoleEl) {
                userRoleEl.textContent = data.user.role;
                if (data.user.is_admin) {
                    userRoleEl.classList.add('admin');
                }
            }
        } else {
            // Not authenticated, redirect to login
            window.location.href = '/login';
        }
    } catch (err) {
        console.error('Failed to load user info:', err);
    }
}

function loadDemoEmails() {
    // Generate demo emails with classifications
    const demoEmails = [
        {
            uid: '1',
            subject: 'Congratulations! You won $1,000,000!',
            sender: 'lottery@win-big-now.xyz',
            date: new Date(Date.now() - 3600000).toISOString(),
            body: 'Dear winner, you have been selected for a grand prize! Click here to claim your reward immediately! Act now!',
            prediction: 'spam',
            confidence: 98.5,
            spam_probability: 98.5,
            ham_probability: 1.5,
            risk_score: 85,
            risk_level: 'High'
        },
        {
            uid: '2',
            subject: 'Team Meeting - Project Update',
            sender: 'sarah@company.com',
            date: new Date(Date.now() - 7200000).toISOString(),
            body: 'Hi team, Just a reminder about our weekly sync tomorrow at 2 PM. We will discuss the Q4 roadmap and review progress.',
            prediction: 'ham',
            confidence: 96.2,
            spam_probability: 3.8,
            ham_probability: 96.2,
            risk_score: 5,
            risk_level: 'Low'
        },
        {
            uid: '3',
            subject: 'URGENT: Your account will be suspended',
            sender: 'security@banking-verify-alert.com',
            date: new Date(Date.now() - 10800000).toISOString(),
            body: 'We detected unusual activity on your account. Please verify your identity immediately by clicking this link and entering your SSN.',
            prediction: 'spam',
            confidence: 99.1,
            spam_probability: 99.1,
            ham_probability: 0.9,
            risk_score: 95,
            risk_level: 'High'
        },
        {
            uid: '4',
            subject: 'Invoice #1234 - Payment Received',
            sender: 'billing@supplier.com',
            date: new Date(Date.now() - 86400000).toISOString(),
            body: 'Thank you for your payment. This email confirms we have received your payment for invoice #1234.',
            prediction: 'ham',
            confidence: 94.7,
            spam_probability: 5.3,
            ham_probability: 94.7,
            risk_score: 10,
            risk_level: 'Low'
        },
        {
            uid: '5',
            subject: 'Get Rich Quick! Work from home!',
            sender: 'opportunity@earn-money-fast.biz',
            date: new Date(Date.now() - 172800000).toISOString(),
            body: 'Make $5000 per week working from home! No experience needed! Limited spots available! Sign up now!',
            prediction: 'spam',
            confidence: 97.8,
            spam_probability: 97.8,
            ham_probability: 2.2,
            risk_score: 75,
            risk_level: 'High'
        }
    ];
    
    currentInboxEmails = demoEmails;
    document.getElementById('lastFetchTime').textContent = 'Just now';
    document.getElementById('inboxCount').textContent = demoEmails.length;
    document.getElementById('inboxCount').style.display = 'inline-flex';
    
    renderInboxEmails();
    showToast('Demo emails loaded!', 'success');
}
