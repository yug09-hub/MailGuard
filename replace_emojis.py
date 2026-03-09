import os

# 1. Update index.html
with open('templates/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Add Lucide script
html = html.replace('<!-- Chart.js -->', '<!-- Icons (Lucide) -->\n    <script src="https://unpkg.com/lucide@latest"></script>\n\n    <!-- Chart.js -->')

# Sidebar
html = html.replace('<div class="brand-icon">🛡️</div>', '<div class="brand-icon"><i data-lucide="shield-check"></i></div>')
html = html.replace('<span class="nav-icon">🔍</span>', '<span class="nav-icon"><i data-lucide="scan-search"></i></span>')
html = html.replace('<span class="nav-icon">📦</span>', '<span class="nav-icon"><i data-lucide="layers"></i></span>')
html = html.replace('<span class="nav-icon">📊</span>', '<span class="nav-icon"><i data-lucide="bar-chart-3"></i></span>')
html = html.replace('<span class="nav-icon">🕒</span>', '<span class="nav-icon"><i data-lucide="clock"></i></span>')
html = html.replace('<span class="nav-icon">⚡</span>', '<span class="nav-icon"><i data-lucide="code-2"></i></span>')
html = html.replace('<span class="nav-icon" id="themeIcon\">🌙</span>', '<span class="nav-icon" id="themeIcon"><i data-lucide="moon"></i></span>')

# Top bar
html = html.replace('<button class="mobile-menu-btn" onclick="toggleSidebar()">☰</button>', '<button class="mobile-menu-btn" onclick="toggleSidebar()"><i data-lucide="menu"></i></button>')
html = html.replace('<div class="theme-toggle" onclick="toggleTheme()" title="Toggle theme\"></div>', '<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">\n                        <span class="theme-toggle-icon" id="themeToggleIcon"></span>\n                    </button>')

# Stats
html = html.replace('<div class="stat-icon">🎯</div>', '<div class="stat-icon"><i data-lucide="crosshair"></i></div>')
html = html.replace('<div class="stat-icon">📌</div>', '<div class="stat-icon"><i data-lucide="locate"></i></div>')
html = html.replace('<div class="stat-icon">🔁</div>', '<div class="stat-icon"><i data-lucide="refresh-cw"></i></div>')
html = html.replace('<div class="stat-icon">⚖️</div>', '<div class="stat-icon"><i data-lucide="scale"></i></div>')
html = html.replace('<div class="stat-icon">📈</div>', '<div class="stat-icon"><i data-lucide="trending-up"></i></div>')

# Analyze Panel
html = html.replace('<span class="header-icon">✉️</span>', '<i data-lucide="mail" class="header-icon"></i>')
html = html.replace('<label for="emailFile" class="file-input-label">📎 Upload File</label>', '<label for="emailFile" class="file-input-label"><i data-lucide="paperclip" class="inline-icon"></i> Upload File</label>')
html = html.replace('>🚨 Spam\n                                                Sample<', '><i data-lucide="alert-triangle" class="inline-icon"></i> Spam Sample<')
html = html.replace('>✅ Legit\n                                                Sample<', '><i data-lucide="check-circle" class="inline-icon"></i> Legit Sample<')
html = html.replace('>🎣 Phishing\n                                                Sample<', '><i data-lucide="fish" class="inline-icon"></i> Phishing Sample<')
html = html.replace('🔍 Analyze Email', '<i data-lucide="search" class="inline-icon"></i> Analyze Email')
html = html.replace('title="Clear\">🗑️</button>', 'title="Clear"><i data-lucide="trash-2"></i></button>')

# XAI and highlight panels
html = html.replace('<span class="header-icon\">🧠</span>', '<i data-lucide="brain" class="header-icon"></i>')
html = html.replace('<span class="header-icon">📝</span>', '<i data-lucide="file-text" class="header-icon"></i>')

# Right panel
html = html.replace('<div class="placeholder-icon">🛡️</div>', '<div class="placeholder-icon"><i data-lucide="shield"></i></div>')
html = html.replace('<span class="header-icon\">🎣</span>', '<i data-lucide="fish" class="header-icon\"></i>')
html = html.replace('<span class="header-icon">🔗</span>', '<i data-lucide="link" class="header-icon"></i>')
html = html.replace('<span class="header-icon">🧬</span>', '<i data-lucide="cpu" class="header-icon"></i>')

# Batch Panel
html = html.replace('<span class="header-icon">📦</span>', '<i data-lucide="layers" class="header-icon"></i>')
html = html.replace('<div class="upload-icon">📄</div>', '<div class="upload-icon"><i data-lucide="upload-cloud"></i></div>')
html = html.replace('⚡ Classify Batch', '<i data-lucide="zap" class="inline-icon"></i> Classify Batch')

# Analytics Headers
html = html.replace('<h4>📊 Spam vs Ham Distribution</h4>', '<h4><i data-lucide="pie-chart" class="header-icon"></i> Spam vs Ham Distribution</h4>')
html = html.replace('<h4>⚠️ Risk Level Distribution</h4>', '<h4><i data-lucide="alert-circle" class="header-icon"></i> Risk Level Distribution</h4>')
html = html.replace('<h4>🏆 Model Performance Comparison</h4>', '<h4><i data-lucide="award" class="header-icon"></i> Model Performance Comparison</h4>')
html = html.replace('<h4>📈 Confidence Trend (Recent)</h4>', '<h4><i data-lucide="activity" class="header-icon"></i> Confidence Trend (Recent)</h4>')

# History Panel
html = html.replace('<span class="header-icon">🕒</span>', '<i data-lucide="clock" class="header-icon"></i>')
html = html.replace('placeholder="🔍 Search emails..."', 'placeholder="Search emails..."')
html = html.replace('data-filter="spam" onclick="setFilter(\'spam\')\">🚨\n                                    Spam</button>', 'data-filter="spam" onclick="setFilter(\'spam\')"><i data-lucide="alert-triangle" class="inline-icon"></i> Spam</button>')
html = html.replace('data-filter="ham" onclick="setFilter(\'ham\')\">✅ Ham</button>', 'data-filter="ham" onclick="setFilter(\'ham\')"><i data-lucide="check-circle" class="inline-icon"></i> Ham</button>')
html = html.replace('<div class="empty-icon\">📭</div>', '<div class="empty-icon"><i data-lucide="inbox"></i></div>')

# API Panel
html = html.replace('<span class="header-icon\">⚡</span>', '<i data-lucide="code-2" class="header-icon"></i>')

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html)
print('Updated index.html')


# 2. Update style.css
with open('static/style.css', 'r', encoding='utf-8') as f:
    css = f.read()

# Remove pseudo-element from theme toggle
css = css.replace('.theme-toggle::after {\n    content: \'🌙\';\n    position: absolute;\n    top: 3px;\n    left: 4px;\n    width: 20px;\n    height: 20px;\n    border-radius: 50%;\n    background: var(--accent-purple);\n    display: flex;\n    align-items: center;\n    justify-content: center;\n    font-size: 11px;\n    transition: all var(--transition-normal);\n}\n\n[data-theme="light"] .theme-toggle::after {\n    content: \'☀️\';\n    left: calc(100% - 24px);\n    background: var(--accent-orange);\n}', 
'.theme-toggle-icon {\n    position: absolute;\n    top: 3px;\n    left: 4px;\n    width: 20px;\n    height: 20px;\n    border-radius: 50%;\n    background: var(--accent-purple);\n    color: white;\n    display: flex;\n    align-items: center;\n    justify-content: center;\n    transition: all var(--transition-normal);\n}\n\n.theme-toggle-icon svg {\n    width: 12px;\n    height: 12px;\n}\n\n[data-theme="light"] .theme-toggle-icon {\n    left: calc(100% - 24px);\n    background: var(--accent-orange);\n}\n\n/* Lucide Icons Base */\ni[data-lucide] {\n    display: inline-flex;\n    align-items: center;\n    justify-content: center;\n}\n\n.inline-icon {\n    width: 16px;\n    height: 16px;\n    stroke-width: 2.5;\n}\n\n.header-icon {\n    width: 20px;\n    height: 20px;\n    margin-right: 8px;\n}\n\n.nav-icon svg {\n    width: 20px;\n    height: 20px;\n}\n\n.btn .inline-icon {\n    width: 18px;\n    height: 18px;\n    margin-right: 4px;\n}\n\n.stat-icon svg {\n    width: 32px;\n    height: 32px;\n    stroke-width: 1.5;\n}')

# Keep search icon via background image
css = css.replace('.history-search {\n    flex: 1;', '.history-search {\n    flex: 1;\n    background-image: url(\'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%2364748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>\');\n    background-repeat: no-repeat;\n    background-position: 12px center;\n    padding-left: 36px;')

# Make XAI icon styling robust
if '.highlight-word {' in css and not '.keyword-tag i {' in css:
    css = css.replace('.highlight-word {', '.keyword-tag i[data-lucide] {\n    margin-right: 4px;\n}\n\n.highlight-word {')

with open('static/style.css', 'w', encoding='utf-8') as f:
    f.write(css)
print('Updated style.css')


# 3. Update script.js
with open('static/script.js', 'r', encoding='utf-8') as f:
    js = f.read()

# Add lucide.createIcons() to appropriate places near window.onload
js = js.replace('// Load initial data\n    loadStats();\n    loadHistory();\n});', '// Load initial data\n    loadStats();\n    loadHistory();\n    if (window.lucide) lucide.createIcons();\n});')

js = js.replace('function updateThemeUI(theme) {\n    const icon = document.getElementById(\'themeIcon\');\n    const label = document.getElementById(\'themeLabel\');', 'function updateThemeUI(theme) {\n    const icon = document.getElementById(\'themeIcon\');\n    const toggleIcon = document.getElementById(\'themeToggleIcon\');\n    const label = document.getElementById(\'themeLabel\');')

js = js.replace('if (theme === \'dark\') {\n        icon.textContent = \'🌙\';\n        label.textContent = \'Dark Mode\';\n    } else {\n        icon.textContent = \'☀️\';\n        label.textContent = \'Light Mode\';\n    }', 'if (theme === \'dark\') {\n        if(icon) icon.innerHTML = \'<i data-lucide="moon"></i>\';\n        if(toggleIcon) toggleIcon.innerHTML = \'<i data-lucide="moon"></i>\';\n        if(label) label.textContent = \'Dark Mode\';\n    } else {\n        if(icon) icon.innerHTML = \'<i data-lucide="sun"></i>\';\n        if(toggleIcon) toggleIcon.innerHTML = \'<i data-lucide="sun"></i>\';\n        if(label) label.textContent = \'Light Mode\';\n    }\n    if (window.lucide) lucide.createIcons();')

js = js.replace('const icons = { success: \'✅\', danger: \'🚨\', warning: \'⚠️\', info: \'ℹ️\' };', 'const icons = { success: \'<i data-lucide="check-circle" class="inline-icon"></i>\', danger: \'<i data-lucide="alert-triangle" class="inline-icon"></i>\', warning: \'<i data-lucide="alert-circle" class="inline-icon"></i>\', info: \'<i data-lucide="info" class="inline-icon"></i>\' };')

js = js.replace('<div class="verdict-icon\">${isSpam ? \'🚨\' : \'✅\'}</div>', '<div class="verdict-icon">${isSpam ? \'<i data-lucide="alert-triangle" style="width:48px;height:48px;stroke-width:1.5"></i>\' : \'<i data-lucide="shield-check" style="width:48px;height:48px;stroke-width:1.5"></i>\'}</div>')
js = js.replace('if (fill) fill.style.width = d.confidence + \'%\';\n    }, 100);', 'if (fill) fill.style.width = d.confidence + \'%\';\n    }, 100);\n    if (window.lucide) lucide.createIcons();')

js = js.replace('<span class="keyword-tag\">🔑 ${escapeHtml(kw)}</span>', '<span class=\"keyword-tag\"><i data-lucide="key" class="inline-icon" style="width:12px;height:12px"></i> ${escapeHtml(kw)}</span>')
js = js.replace('} else {\n        contribDiv.innerHTML = \'\';\n    }\n}', '} else {\n        contribDiv.innerHTML = \'\';\n    }\n    if (window.lucide) lucide.createIcons();\n}')

js = js.replace('<span class="threat-icon\">${t.icon || \'⚠️\'}</span>', '<span class="threat-icon"><i data-lucide="shield-alert"></i></span>')
js = js.replace('<div class="empty-icon\">✅</div>', '<div class="empty-icon"><i data-lucide="check-circle" style="width:48px;height:48px"></i></div>')
js = js.replace('${threatsHtml}\n        </div>\n    `;\n}', '${threatsHtml}\n        </div>\n    `;\n    if (window.lucide) lucide.createIcons();\n}')

js = js.replace('<td>${u.is_https ? \'🔒\' : \'⚠️\'}</td>', '<td>${u.is_https ? \'<i data-lucide="lock" class="inline-icon" style="color:var(--accent-cyan)"></i>\' : \'<i data-lucide="unlock" class="inline-icon" style="color:#ef4444"></i>\'}</td>')
js = js.replace('<td>${u.is_trusted ? \'✅ Trusted\' : u.is_shortener ? \'📎 Shortener\' : \'❓ Unknown\'}</td>', '<td>${u.is_trusted ? \'<i data-lucide="check-circle" class="inline-icon" style="color:var(--accent-cyan)"></i> Trusted\' : u.is_shortener ? \'<i data-lucide="link-2" class="inline-icon"></i> Shortener\' : \'<i data-lucide="help-circle" class="inline-icon"></i> Unknown\'}</td>')
js = js.replace('<p style="font-size:12px; color:var(--text-muted); font-weight:600; margin-bottom:6px;\">⚠️ Flags:</p>', '<p style="font-size:12px; color:var(--text-muted); font-weight:600; margin-bottom:6px;"><i data-lucide="flag" class="inline-icon" style="width:12px;height:12px"></i> Flags:</p>')
js = js.replace('</div>\n        ` : \'\'}\n    `;\n}', '</div>\n        ` : \'\'}\n    `;\n    if (window.lucide) lucide.createIcons();\n}')

js = js.replace('<div class="intel-value\">🌐</div>', '<div class="intel-value"><i data-lucide="globe"></i></div>')
js = js.replace('</div>\n    `;\n}', '</div>\n    `;\n    if (window.lucide) lucide.createIcons();\n}')

js = js.replace('btn.innerHTML = \'⚡ Classify Batch\';', 'btn.innerHTML = \'<i data-lucide="zap" class="inline-icon"></i> Classify Batch\';\n        if (window.lucide) lucide.createIcons();')

js = js.replace('<div class="empty-icon\">📭</div>', '<div class="empty-icon"><i data-lucide="inbox" style="width:48px;height:48px"></i></div>')

js = js.replace('}).join(\'\');\n    } catch (err) {', '}).join(\'\');\n        if (window.lucide) lucide.createIcons();\n    } catch (err) {')
js = js.replace('list.innerHTML = \'<div class="empty-state\"><div class="empty-icon\">📭</div><div class="empty-text\">No results found</div></div>\';', 'list.innerHTML = \'<div class="empty-state\"><div class="empty-icon"><i data-lucide="inbox" style="width:48px;height:48px"></i></div><div class="empty-text">No results found</div></div>\';\n            if (window.lucide) lucide.createIcons();')

js = js.replace('renderCharts(d);\n    } catch (err) {', 'renderCharts(d);\n        if (window.lucide) lucide.createIcons();\n    } catch (err) {')


with open('static/script.js', 'w', encoding='utf-8') as f:
    f.write(js)
print('Updated script.js')
