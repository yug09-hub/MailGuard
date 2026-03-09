/**
 * SpamGuard AI — Email Security Platform
 * Frontend logic: analysis, XAI, phishing, URL scan, batch, analytics, history
 */

// ── State ──────────────────────────────────────────────────────
let selectedModel = 'nb';
let historyFilter = 'all';
let charts = {};

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
    // Hide all panels
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item[data-panel]').forEach(n => n.classList.remove('active'));

    // Show target
    const panel = document.getElementById(`panel-${name}`);
    if (panel) panel.classList.add('active');

    const navItem = document.querySelector(`.nav-item[data-panel="${name}"]`);
    if (navItem) navItem.classList.add('active');

    // Update title
    const titles = {
        analyze: 'Email Analysis',
        batch: 'Batch Processing',
        analytics: 'Analytics Dashboard',
        history: 'Analysis History',
        api: 'API Documentation'
    };
    document.getElementById('pageTitle').textContent = titles[name] || 'Dashboard';

    // Load data for panel
    if (name === 'analytics') loadAnalytics();
    if (name === 'history') loadHistory();

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

// ── Model Selection ────────────────────────────────────────────
function selectModel(key) {
    selectedModel = key;
    document.querySelectorAll('.model-chip').forEach(c => {
        c.classList.toggle('active', c.dataset.model === key);
    });
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

    try {
        const res = await fetch('/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_text: text, model: selectedModel })
        });
        const d = await res.json();

        if (d.error) {
            showToast(d.error, 'danger');
            return;
        }

        renderResult(d);
        renderXAI(d);
        renderPhishing(d.phishing);
        renderURLScan(d.url_scan);
        renderIntelligence(d.intelligence);
        renderHighlightedEmail(d.highlighted_text);

        loadHistory();
        loadStats();

        showToast(
            d.prediction === 'spam' ? 'Spam detected!' : 'Email looks safe.',
            d.prediction === 'spam' ? 'danger' : 'success'
        );
    } catch (err) {
        showToast('Network error. Is server running?', 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// ── Render Result Verdict ──────────────────────────────────────
function renderResult(d) {
    document.getElementById('resultPlaceholder').style.display = 'none';
    const box = document.getElementById('resultBox');
    box.style.display = 'block';

    const isSpam = d.prediction === 'spam';

    box.innerHTML = `
        <div class="result-verdict ${isSpam ? 'spam' : 'ham'}">
            <div class="verdict-icon">${isSpam ? '<i data-lucide="alert-triangle" style="width:48px;height:48px;stroke-width:1.5"></i>' : '<i data-lucide="shield-check" style="width:48px;height:48px;stroke-width:1.5"></i>'}</div>
            <div class="verdict-label ${isSpam ? 'spam' : 'ham'}">${isSpam ? 'SPAM DETECTED' : 'SAFE EMAIL'}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Model: ${d.model_name || 'Naive Bayes'}</div>
        </div>

        <div class="confidence-meter">
            <div class="meter-header">
                <span>Confidence</span>
                <span>${d.confidence}%</span>
            </div>
            <div class="meter-bar">
                <div class="meter-fill ${isSpam ? 'danger' : ''}" style="width: 0%;" id="confidenceFill"></div>
            </div>
        </div>

        <div class="prob-boxes">
            <div class="prob-box spam">
                <div class="prob-value">${d.spam_probability}%</div>
                <div class="prob-label">Spam Probability</div>
            </div>
            <div class="prob-box ham">
                <div class="prob-value">${d.ham_probability}%</div>
                <div class="prob-label">Ham Probability</div>
            </div>
        </div>
    `;

    // Animate confidence bar
    setTimeout(() => {
        const fill = document.getElementById('confidenceFill');
        if (fill) fill.style.width = d.confidence + '%';
    }, 100);
    if (window.lucide) lucide.createIcons();

    // Add PDF download button to the result card dynamically
    // Remove if it exists to avoid duplicates
    const existingPdfBtn = document.getElementById('dlPdfBtn');
    if (existingPdfBtn) existingPdfBtn.remove();

    const downloadBtnHtml = `
        <button id="dlPdfBtn" onclick="downloadPDFReport()" style="width: 100%; margin-top: 20px; padding: 10px; border-radius: 8px; font-weight: 500; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px; cursor: pointer; transition: background 0.2s;" class="btn btn-secondary">
            <i data-lucide="download" style="width: 16px; height: 16px;"></i> Download PDF Report
        </button>
    `;
    box.insertAdjacentHTML('beforeend', downloadBtnHtml);
    if (window.lucide) lucide.createIcons();
}

// ── Download PDF Report ────────────────────────────────────────
function downloadPDFReport() {
    const btn = document.getElementById('dlPdfBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner" style="width: 16px; height: 16px;"></span> Generating PDF...';
    btn.disabled = true;

    // We target the parent container of the results
    const element = document.querySelector('.result-panel');

    // Temporary styling changes to make the PDF look better
    const originalBackground = element.style.background;
    element.style.background = 'white'; // Force white background for PDF
    element.style.padding = '20px';
    element.style.borderRadius = '0';

    // Hide the download button itself in the PDF
    btn.style.display = 'none';

    const opt = {
        margin: 0.5,
        filename: 'SpamGuard_Analysis_Report.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, backgroundColor: '#ffffff' },
        jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
    };

    // New Promise-based usage:
    html2pdf().set(opt).from(element).save().then(() => {
        // Restore styling after generation
        element.style.background = originalBackground;
        element.style.padding = '';
        element.style.borderRadius = '';
        btn.style.display = 'flex';
        btn.innerHTML = originalText;
        btn.disabled = false;
        showToast('PDF downloaded successfully!', 'success');
    }).catch(err => {
        console.error('PDF Generation Error:', err);
        element.style.background = originalBackground;
        element.style.padding = '';
        element.style.borderRadius = '';
        btn.style.display = 'flex';
        btn.innerHTML = originalText;
        btn.disabled = false;
        showToast('Failed to generate PDF.', 'danger');
    });
}

// ── Render XAI ─────────────────────────────────────────────────
function renderXAI(d) {
    const card = document.getElementById('xaiCard');
    const kwDiv = document.getElementById('xaiKeywords');
    const contribDiv = document.getElementById('xaiContributions');

    if (!d.detected_keywords || d.detected_keywords.length === 0) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';

    // Keyword tags
    kwDiv.innerHTML = d.detected_keywords.map(kw =>
        `<span class="keyword-tag"><i data-lucide="key" class="inline-icon" style="width:12px;height:12px"></i> ${escapeHtml(kw)}</span>`
    ).join('');

    // Contribution bars
    if (d.keyword_contributions && d.keyword_contributions.length > 0) {
        const maxContrib = Math.max(...d.keyword_contributions.map(k => Math.abs(k.contribution)));
        contribDiv.innerHTML = d.keyword_contributions.slice(0, 8).map(k => {
            const pct = maxContrib > 0 ? (Math.abs(k.contribution) / maxContrib * 100) : 0;
            return `
                <div class="contribution-bar">
                    <span class="cb-word">${escapeHtml(k.word)}</span>
                    <div class="cb-bar-wrap">
                        <div class="cb-bar" style="width: ${pct}%;"></div>
                    </div>
                    <span class="cb-value">${k.contribution.toFixed(3)}</span>
                </div>
            `;
        }).join('');
    } else {
        contribDiv.innerHTML = '';
    }
    if (window.lucide) lucide.createIcons();
}

// ── Render Phishing ────────────────────────────────────────────
function renderPhishing(phishing) {
    const card = document.getElementById('phishingCard');
    const div = document.getElementById('phishingResult');

    if (!phishing) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';

    const level = phishing.risk_level.toLowerCase();

    let threatsHtml = '';
    if (phishing.threats && phishing.threats.length > 0) {
        threatsHtml = phishing.threats.map(t => `
            <div class="threat-item severity-${t.severity}">
                <span class="threat-icon"><i data-lucide="shield-alert"></i></span>
                <div class="threat-info">
                    <div class="threat-type">${escapeHtml(t.type)}</div>
                    <div class="threat-detail">${escapeHtml(t.details)}</div>
                    ${t.matches && t.matches.length > 0 ? `
                        <div class="threat-matches">
                            ${t.matches.slice(0, 4).map(m => `<span class="threat-match-tag">${escapeHtml(m)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');
    } else {
        threatsHtml = '<div class="empty-state" style="padding:20px;"><div class="empty-icon"><i data-lucide="check-circle" style="width:48px;height:48px"></i></div><div class="empty-text">No threats detected</div></div>';
    }

    div.innerHTML = `
        <div class="risk-gauge">
            <div class="risk-score-circle ${level}">
                <div class="risk-score-value">${phishing.risk_score}</div>
                <div class="risk-score-label">Risk Score</div>
            </div>
            <span class="risk-level-badge ${level}">${phishing.risk_level} Risk</span>
        </div>
        <div style="margin-top: 16px;">
            <h4 style="font-size:13px; font-weight:700; color:var(--text-heading); margin-bottom:12px;">
                Detected Threats (${phishing.threat_count})
            </h4>
            ${threatsHtml}
        </div>
    `;
    if (window.lucide) lucide.createIcons();
}

// ── Render URL Scan ────────────────────────────────────────────
function renderURLScan(urlScan) {
    const card = document.getElementById('urlCard');
    const div = document.getElementById('urlResult');

    if (!urlScan || urlScan.length === 0) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';

    div.innerHTML = `
        <table class="url-table">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>HTTPS</th>
                    <th>Domain Trust</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${urlScan.map(u => {
        const statusClass = u.status === 'Safe' ? 'safe' : u.status === 'Suspicious' ? 'suspicious' : 'high-risk';
        return `
                        <tr>
                            <td class="url-text" title="${escapeHtml(u.url)}">${escapeHtml(u.url)}</td>
                            <td>${u.is_https ? '<i data-lucide="lock" class="inline-icon" style="color:var(--accent-cyan)"></i>' : '<i data-lucide="unlock" class="inline-icon" style="color:#ef4444"></i>'}</td>
                            <td>${u.is_trusted ? '<i data-lucide="check-circle" class="inline-icon" style="color:var(--accent-cyan)"></i> Trusted' : u.is_shortener ? '<i data-lucide="link-2" class="inline-icon"></i> Shortener' : '<i data-lucide="help-circle" class="inline-icon"></i> Unknown'}</td>
                            <td><span class="status-badge ${statusClass}">${u.status}</span></td>
                        </tr>
                    `;
    }).join('')}
            </tbody>
        </table>
        ${urlScan.some(u => u.flags && u.flags.length > 0) ? `
            <div style="margin-top: 12px;">
                <p style="font-size:12px; color:var(--text-muted); font-weight:600; margin-bottom:6px;"><i data-lucide="flag" class="inline-icon" style="width:12px;height:12px"></i> Flags:</p>
                ${urlScan.filter(u => u.flags && u.flags.length > 0).map(u =>
        u.flags.map(f => `<span class="threat-match-tag" style="margin:2px;">${escapeHtml(f)}</span>`).join('')
    ).join('')}
            </div>
        ` : ''}
    `;
    if (window.lucide) lucide.createIcons();
}

// ── Render Email Intelligence ──────────────────────────────────
function renderIntelligence(intel) {
    const card = document.getElementById('intelCard');
    const div = document.getElementById('intelResult');

    if (!intel) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';

    const sentimentColor = intel.sentiment === 'Positive' ? 'var(--accent-cyan)' :
        intel.sentiment === 'Negative' ? '#ef4444' : 'var(--accent-orange)';

    div.innerHTML = `
        <div class="intel-grid">
            <div class="intel-item">
                <div class="intel-value"><i data-lucide="globe"></i></div>
                <div class="intel-label">${escapeHtml(intel.language)}</div>
            </div>
            <div class="intel-item">
                <div class="intel-value" style="color:${sentimentColor};">${intel.sentiment}</div>
                <div class="intel-label">Sentiment</div>
            </div>
            <div class="intel-item">
                <div class="intel-value">${intel.word_count}</div>
                <div class="intel-label">Words</div>
            </div>
            <div class="intel-item">
                <div class="intel-value">${intel.link_count}</div>
                <div class="intel-label">Links</div>
            </div>
            <div class="intel-item">
                <div class="intel-value" style="color: ${intel.suspicious_keyword_count > 3 ? '#ef4444' : 'var(--text-heading)'};">${intel.suspicious_keyword_count}</div>
                <div class="intel-label">Suspicious Keywords</div>
            </div>
            <div class="intel-item">
                <div class="intel-value">${intel.length_category}</div>
                <div class="intel-label">Email Length</div>
            </div>
        </div>
    `;
    if (window.lucide) lucide.createIcons();
}

// ── Render Highlighted Email ───────────────────────────────────
function renderHighlightedEmail(text) {
    const card = document.getElementById('highlightCard');
    const div = document.getElementById('highlightedEmail');

    if (!text) {
        card.style.display = 'none';
        return;
    }
    card.style.display = 'block';

    // Replace [[HIGHLIGHT]] markers with styled spans
    let html = escapeHtml(text);
    html = html.replace(/\[\[HIGHLIGHT\]\]/g, '<span class="highlight-word">');
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
            list.innerHTML = '<div class="empty-state"><div class="empty-icon"><i data-lucide="inbox" style="width:48px;height:48px"></i></div><div class="empty-text">No results found</div></div>';
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
    document.getElementById('emailInput').value = '';
    document.getElementById('emailFile').value = '';
    document.getElementById('charCount').textContent = '0 chars';
    document.getElementById('resultBox').style.display = 'none';
    document.getElementById('resultPlaceholder').style.display = 'block';

    // Hide analysis panels
    ['xaiCard', 'highlightCard', 'phishingCard', 'urlCard', 'intelCard'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
}

function escapeHtml(s) {
    if (!s) return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}
