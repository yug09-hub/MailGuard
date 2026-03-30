const { useState, useEffect, useRef } = React;

// --- API Configuration ---
const API_URL = 'http://127.0.0.1:5000';

// --- Utility Components ---
const Icon = ({ name, size = 20, className = "" }) => {
    return <i data-lucide={name} style={{ width: size, height: size }} className={className}></i>;
};

// Toast Component
const ToastContainer = ({ toasts, removeToast }) => (
    <div className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2">
        {toasts.map(toast => (
            <div key={toast.id} className={`flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg border border-slate-100 dark:border-slate-700 animate-in slide-in-from-right-8 fade-in duration-300 ${toast.type === 'error' ? 'bg-red-50 dark:bg-red-900 border-red-200 text-red-800 dark:text-red-200' : 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200'}`}>
                <Icon name={toast.type === 'error' ? 'alert-circle' : 'check-circle'} className={toast.type === 'error' ? 'text-red-500' : 'text-emerald-500'} />
                <span className="text-sm font-medium">{toast.message}</span>
                <button onClick={() => removeToast(toast.id)} className="ml-2 text-slate-400 hover:text-slate-600"><Icon name="x" size={16} /></button>
            </div>
        ))}
    </div>
);

// Gauge Component
const Gauge = ({ value, label, color }) => {
    const radius = 36;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (value / 100) * circumference;
    return (
        <div className="flex flex-col items-center">
            <svg className="transform -rotate-90 w-24 h-24">
                <circle cx="48" cy="48" r={radius} stroke="currentColor" strokeWidth="8" fill="transparent" className="text-slate-100 dark:text-slate-700" />
                <circle cx="48" cy="48" r={radius} stroke="currentColor" strokeWidth="8" fill="transparent" strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} className={`transition-all duration-1000 ease-out ${color}`} />
            </svg>
            <div className="absolute mt-8 text-center">
                <span className="block text-xl font-bold dark:text-white">{value.toFixed(1)}%</span>
            </div>
            <span className="text-xs font-medium text-slate-500 mt-2">{label}</span>
        </div>
    );
};

// Trend Chart Component
const TrendChart = ({ history }) => {
    const chartRef = useRef(null);
    const chartInstance = useRef(null);

    useEffect(() => {
        if (!chartRef.current || !history || history.length === 0) return;

        const ctx = chartRef.current.getContext('2d');
        const labels = history.slice(0, 10).reverse().map(h => new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        const dataSpam = history.slice(0, 10).reverse().map(h => h.spam_probability * 100);

        if (chartInstance.current) {
            chartInstance.current.destroy();
        }

        chartInstance.current = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Spam Probability',
                    data: dataSpam,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, max: 100 } }
            }
        });

        return () => { if (chartInstance.current) chartInstance.current.destroy(); }
    }, [history]);

    return (
        <div className="h-48 w-full mt-4">
            {history.length > 0 ? <canvas ref={chartRef}></canvas> : <div className="h-full flex items-center justify-center text-sm text-slate-400">Not enough data for chart</div>}
        </div>
    );
};

// --- Main Application ---
function App() {
    const [darkMode, setDarkMode] = useState(false);
    const [activeTab, setActiveTab] = useState('classify');
    const [emailText, setEmailText] = useState('');
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [result, setResult] = useState(null);
    const [history, setHistory] = useState([]);
    const [stats, setStats] = useState({ accuracy: 98.7, precision: 97.8, recall: 96.7, f1: 97.3, total: 0 });
    const [toasts, setToasts] = useState([]);

    // Batch variables
    const [batchFile, setBatchFile] = useState(null);
    const [batchResults, setBatchResults] = useState(null);
    const [isBatching, setIsBatching] = useState(false);

    useEffect(() => {
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            setDarkMode(true);
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        fetchStats();
        fetchHistory();
    }, []);

    const addToast = (message, type = 'success') => {
        const id = Date.now();
        setToasts(prev => [...prev, { id, message, type }]);
        setTimeout(() => removeToast(id), 5000);
    };

    const removeToast = (id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    };

    const toggleTheme = () => {
        setDarkMode(!darkMode);
        if (!darkMode) {
            document.documentElement.classList.add('dark');
            localStorage.theme = 'dark';
        } else {
            document.documentElement.classList.remove('dark');
            localStorage.theme = 'light';
        }
    };

    const fetchStats = async () => {
        try {
            const res = await fetch(`${API_URL}/stats`);
            const data = await res.json();
            if (data.predictions_made !== undefined) setStats(s => ({ ...s, total: data.predictions_made }));
        } catch (e) { console.error("Failed to fetch stats"); }
    };

    const fetchHistory = async () => {
        try {
            const res = await fetch(`${API_URL}/history`);
            const data = await res.json();
            setHistory(data);
        } catch (e) { }
    };

    const handleAnalyze = async () => {
        if (!emailText.trim()) return;
        setIsAnalyzing(true);
        setResult(null);

        try {
            const res = await fetch(`${API_URL}/predict`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email_text: emailText })
            });
            const data = await res.json();

            setTimeout(() => {
                setResult(data);
                setIsAnalyzing(false);
                fetchHistory();
                setStats(s => ({ ...s, total: s.total + 1 }));
                addToast('Analysis completed successfully!');
            }, 800);

        } catch (e) {
            setIsAnalyzing(false);
            addToast("Failed to connect to backend", "error");
        }
    };

    const handleBatchUpload = async () => {
        if (!batchFile) return;
        setIsBatching(true);
        const formData = new FormData();
        formData.append('file', batchFile);

        try {
            const res = await fetch(`${API_URL}/batch_predict`, { method: 'POST', body: formData });
            const data = await res.json();

            if (data.error) throw new Error(data.error);

            setBatchResults(data);
            fetchHistory();
            fetchStats();
            addToast(`Successfully processed ${data.total} emails`);
        } catch (e) {
            addToast(e.message || "Failed to process batch", "error");
        } finally {
            setIsBatching(false);
        }
    };

    const exportBatchCSV = () => {
        if (!batchResults) return;
        let csv = "Email Snippet,Prediction,Confidence,Spam Probability\n";
        batchResults.results.forEach(r => {
            csv += `"${r.snippet.replace(/"/g, '""')}",${r.prediction},${r.confidence},${r.spam_probability}\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = "mailguard_batch_results.csv";
        a.click();
    };

    const loadExample = (type) => {
        if (type === 'spam') {
            setEmailText("URGENT: You have won a $1000 Walmart Gift Card! Click here immediately to claim your prize before it expires. Congratulations winner!\n\nAct now!");
        } else {
            setEmailText("Hi team,\n\nJust a reminder that our weekly product sync is scheduled for tomorrow at 10 AM. Please make sure to update the project board before the meeting.\n\nThanks,\nSarah");
        }
    };

    return (
        <div className={`min-h-screen flex flex-col transition-colors duration-300 ${darkMode ? 'bg-slate-900 text-white' : 'bg-slate-50 text-slate-900'}`}>
            <ToastContainer toasts={toasts} removeToast={removeToast} />

            {/* Top Navigation */}
            <nav className="sticky top-0 z-50 glass-panel border-b px-6 py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary-500 rounded-lg shadow-lg shadow-primary-500/30">
                        <Icon name="shield-check" className="text-white" />
                    </div>
                    <span className="text-xl font-bold bg-gradient-to-r from-primary-600 to-blue-400 bg-clip-text text-transparent">
                        MailGuard
                    </span>
                </div>

                <div className="flex items-center gap-4">
                    <button className="flex items-center gap-2 px-4 py-2 rounded-full bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors text-sm font-medium">
                        <Icon name="bot" size={16} className="text-blue-500" />
                        <span className="hidden sm:inline">Ask AI Assistant</span>
                    </button>

                    <button onClick={toggleTheme} className="p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                        {darkMode ? <Icon name="sun" size={20} /> : <Icon name="moon" size={20} />}
                    </button>

                    <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-primary-500 to-purple-500 flex items-center justify-center text-white font-bold cursor-pointer ring-2 ring-white dark:ring-slate-800">YP</div>
                </div>
            </nav>

            <div className="flex flex-1 overflow-hidden">
                {/* Sidebar */}
                <aside className="w-64 border-r border-slate-200 dark:border-slate-800 hidden md:flex flex-col py-6 px-4 gap-2 bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 ml-2">App Features</div>
                    {[
                        { id: 'classify', icon: 'search', label: 'Classify Email' },
                        { id: 'batch', icon: 'file-spreadsheet', label: 'Batch Analysis' },
                        { id: 'report', icon: 'bar-chart-2', label: 'Detailed Report' },
                        { id: 'history', icon: 'history', label: 'History & Logs' }
                    ].map(item => (
                        <button key={item.id} onClick={() => setActiveTab(item.id)}
                            className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${activeTab === item.id ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-600 dark:text-primary-400 font-medium'
                                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400'
                                }`}
                        >
                            <Icon name={item.icon} size={18} /> {item.label}
                        </button>
                    ))}

                    <div className="mt-4 border-t border-slate-200 dark:border-slate-800 pt-4">
                        <button className="flex items-center gap-3 px-4 py-3 rounded-xl w-full text-left hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400">
                            <Icon name="refresh-cw" size={18} className="text-amber-500" /> Model Retraining
                        </button>
                    </div>
                </aside>

                {/* Main Content */}
                <main className="flex-1 overflow-y-auto p-4 lg:p-8">
                    {/* Metrics Dashboard */}
                    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
                        {[
                            { label: 'Accuracy', value: `${stats.accuracy}%`, icon: 'target', color: 'text-emerald-500', bg: 'bg-emerald-50 dark:bg-emerald-500/10' },
                            { label: 'Precision', value: `${stats.precision}%`, icon: 'crosshair', color: 'text-blue-500', bg: 'bg-blue-50 dark:bg-blue-500/10' },
                            { label: 'Recall', value: `${stats.recall}%`, icon: 'rotate-ccw', color: 'text-indigo-500', bg: 'bg-indigo-50 dark:bg-indigo-500/10' },
                            { label: 'F1 Score', value: `${stats.f1}%`, icon: 'activity', color: 'text-purple-500', bg: 'bg-purple-50 dark:bg-purple-500/10' },
                            { label: 'Total Scans', value: stats.total.toLocaleString(), icon: 'scan', color: 'text-primary-500', bg: 'bg-primary-50 dark:bg-primary-500/10' }
                        ].map((stat, i) => (
                            <div key={i} className="bg-white dark:bg-slate-800 rounded-2xl p-4 shadow-sm border border-slate-100 dark:border-slate-700/50">
                                <div className="flex items-center justify-between mb-3">
                                    <span className="text-sm font-medium text-slate-500">{stat.label}</span>
                                    <div className={`p-2 rounded-lg ${stat.bg} ${stat.color}`}><Icon name={stat.icon} size={16} /></div>
                                </div>
                                <div className="text-2xl font-bold dark:text-white">{stat.value}</div>
                            </div>
                        ))}
                    </div>

                    {activeTab === 'classify' && (
                        <div className="grid lg:grid-cols-3 gap-6">
                            {/* Editor */}
                            <div className="lg:col-span-2 space-y-6">
                                <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-sm border border-slate-100 dark:border-slate-700/50 overflow-hidden relative">
                                    <div className="border-b border-slate-100 dark:border-slate-700 p-4 flex justify-between bg-slate-50/50 dark:bg-slate-800/80">
                                        <h2 className="font-semibold text-lg flex items-center gap-2"><Icon name="mail" className="text-primary-500" /> Classify Email</h2>
                                        <div className="flex gap-2">
                                            <button onClick={() => loadExample('spam')} className="text-xs px-3 py-1 bg-red-50 dark:bg-red-500/10 text-red-600 rounded-full font-medium">Spam Sample</button>
                                            <button onClick={() => loadExample('ham')} className="text-xs px-3 py-1 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 rounded-full font-medium">Legit Sample</button>
                                            <label className="cursor-pointer text-slate-500 mx-2 hover:text-primary-500 mt-1">
                                                <Icon name="paperclip" size={16} />
                                                <input type="file" accept=".txt,.eml" className="hidden" onChange={(e) => { const r = new FileReader(); r.onload = (ev) => setEmailText(ev.target.result); r.readAsText(e.target.files[0]); }} />
                                            </label>
                                        </div>
                                    </div>
                                    <div className="p-4">
                                        <textarea className="w-full h-64 p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none focus:ring-2 focus:ring-primary-500 resize-none text-sm dark:text-slate-300 font-mono" placeholder="Paste email content..." value={emailText} onChange={(e) => setEmailText(e.target.value)}></textarea>
                                    </div>
                                    <div className="p-4 pt-0 flex justify-between">
                                        <span className="text-xs text-slate-400">{emailText.length} characters</span>
                                        <button onClick={handleAnalyze} disabled={isAnalyzing || !emailText} className={`flex items-center gap-2 px-6 py-2.5 rounded-xl font-medium text-white shadow-lg ${isAnalyzing ? 'bg-slate-600' : 'bg-primary-600 hover:bg-primary-500'}`}>
                                            {isAnalyzing ? <Icon name="loader-2" className="animate-spin" /> : <Icon name="zap" />} {isAnalyzing ? 'Analyzing...' : 'Analyze Email'}
                                        </button>
                                    </div>
                                    {isAnalyzing && <div className="absolute inset-0 bg-white/50 dark:bg-slate-900/50 backdrop-blur flex items-center justify-center rounded-2xl z-10"><Icon name="loader-2" className="animate-spin text-primary-500 w-10 h-10" /></div>}
                                </div>

                                <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-sm border border-slate-100 dark:border-slate-700/50 p-4">
                                    <h3 className="font-semibold text-sm mb-2 flex items-center gap-2"><Icon name="pie-chart" size={16} /> Spam Trend Analysis</h3>
                                    <TrendChart history={history} />
                                </div>
                            </div>

                            {/* Result */}
                            <div className="lg:col-span-1">
                                {result ? (
                                    <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-lg border border-slate-100 dark:border-slate-700 p-6 sticky top-24 animate-in fade-in slide-in-from-bottom-4">
                                        <div className="text-center mb-6">
                                            <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-4 shadow-xl ${result.prediction === 'spam' ? 'bg-gradient-to-br from-red-500 to-rose-600' : 'bg-gradient-to-br from-emerald-400 to-green-600'}`}>
                                                <Icon name={result.prediction === 'spam' ? 'shield-alert' : 'shield-check'} size={40} className="text-white" />
                                            </div>
                                            <h2 className={`text-3xl font-bold uppercase tracking-wide ${result.prediction === 'spam' ? 'text-red-500' : 'text-emerald-500'}`}>{result.prediction}</h2>
                                        </div>

                                        <div className="flex justify-around mb-6 py-4 border-y border-slate-100 dark:border-slate-700">
                                            <Gauge value={result.spam_probability * 100} label="Spam Prob" color="text-red-500" />
                                            <Gauge value={result.ham_probability * 100} label="Ham Prob" color="text-emerald-500" />
                                        </div>

                                        {result.prediction === 'spam' && (
                                            <div className="bg-red-50 dark:bg-red-500/5 rounded-xl p-4 border border-red-100 dark:border-red-500/20 mb-6">
                                                <h4 className="flex gap-2 text-sm font-semibold text-red-700 dark:text-red-400 mb-3"><Icon name="alert-triangle" size={16} /> Detected Issues</h4>
                                                <ul className="space-y-2 mb-4">
                                                    <li className="flex gap-2 text-sm text-red-600/80"><Icon name="x-circle" size={14} className="mt-0.5" /> High-risk keywords found</li>
                                                    {emailText.match(/urgent|win|free/i) && <li className="flex gap-2 text-sm text-red-600/80"><Icon name="x-circle" size={14} className="mt-0.5" /> Urgency/Sales language</li>}
                                                </ul>
                                                {result.detected_keywords?.length > 0 && (
                                                    <div>
                                                        <div className="text-xs font-semibold text-red-700/70 uppercase mb-2">Flagged Keywords</div>
                                                        <div className="flex flex-wrap gap-2">
                                                            {result.detected_keywords.map((kw, i) => <span key={i} className="px-2 py-1 bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 text-xs font-medium rounded-md">{kw}</span>)}
                                                        </div>
                                                    </div>
                                                )}
                                                <button className="mt-4 w-full text-xs font-medium bg-white dark:bg-red-900 border border-red-200 dark:border-red-700 rounded-lg py-2 text-red-600 dark:text-white flex justify-center items-center gap-2 hover:bg-red-50">
                                                    <Icon name="zap" size={14} /> Explain AI Decision
                                                </button>
                                            </div>
                                        )}
                                        <button className="w-full py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 font-medium text-sm hover:bg-slate-50 transition flex items-center justify-center gap-2">
                                            <Icon name="download" size={16} /> Download Report
                                        </button>
                                    </div>
                                ) : (
                                    <div className="h-full min-h-[400px] border-2 border-dashed border-slate-200 dark:border-slate-700 rounded-2xl flex flex-col items-center justify-center text-slate-400 p-6 text-center">
                                        <div className="w-16 h-16 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4"><Icon name="sparkles" size={24} /></div>
                                        <h3 className="text-lg font-medium text-slate-600 dark:text-slate-300 mb-2">Ready to Analyze</h3>
                                        <p className="text-sm">Paste your email content and click Analyze.</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'batch' && (
                        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-sm border border-slate-100 dark:border-slate-700 p-8">
                            <h2 className="text-2xl font-bold mb-6 flex items-center gap-2"><Icon name="file-spreadsheet" className="text-primary-500" /> Batch Analysis</h2>
                            <div className="flex flex-col items-center justify-center border-2 border-dashed border-slate-300 dark:border-slate-600 rounded-2xl p-12 bg-slate-50 dark:bg-slate-900/50">
                                <Icon name="upload-cloud" size={48} className="text-primary-400 mb-4" />
                                <h3 className="text-lg font-semibold mb-2">Upload CSV File</h3>
                                <p className="text-sm text-slate-500 mb-6">Upload a dataset of emails to classify them all at once.</p>
                                <input type="file" id="batch-upload" accept=".csv" className="hidden" onChange={(e) => setBatchFile(e.target.files[0])} />
                                <label htmlFor="batch-upload" className="cursor-pointer bg-primary-600 text-white px-6 py-2.5 rounded-xl font-medium hover:bg-primary-500 shadow-md">
                                    {batchFile ? batchFile.name : 'Select CSV File'}
                                </label>
                                {batchFile && (
                                    <button onClick={handleBatchUpload} disabled={isBatching} className="mt-4 flex items-center gap-2 bg-slate-800 text-white px-6 py-2.5 rounded-xl font-medium">
                                        {isBatching ? <Icon name="loader-2" className="animate-spin" /> : <Icon name="play" />} {isBatching ? 'Processing...' : 'Run Batch Analysis'}
                                    </button>
                                )}
                            </div>

                            {batchResults && (
                                <div className="mt-8">
                                    <div className="flex justify-between items-center mb-4">
                                        <h3 className="text-lg font-semibold">Results Overview</h3>
                                        <button onClick={exportBatchCSV} className="text-sm bg-emerald-50 border border-emerald-200 text-emerald-600 px-4 py-2 rounded-lg font-medium flex gap-2">
                                            <Icon name="download" size={16} /> Export CSV
                                        </button>
                                    </div>
                                    <div className="grid grid-cols-3 gap-4 mb-6">
                                        <div className="p-4 bg-slate-50 rounded-xl text-center"><div className="text-sm text-slate-500">Total</div><div className="text-xl font-bold">{batchResults.total}</div></div>
                                        <div className="p-4 bg-red-50 rounded-xl text-center"><div className="text-sm text-red-500">Spam</div><div className="text-xl font-bold text-red-600">{batchResults.spam_count}</div></div>
                                        <div className="p-4 bg-emerald-50 rounded-xl text-center"><div className="text-sm text-emerald-500">Ham</div><div className="text-xl font-bold text-emerald-600">{batchResults.ham_count}</div></div>
                                    </div>
                                    <div className="overflow-auto max-h-96">
                                        <table className="w-full text-sm text-left">
                                            <thead className="bg-slate-50 sticky top-0">
                                                <tr><th className="p-3">Prediction</th><th className="p-3">Snippet</th><th className="p-3">Confidence</th></tr>
                                            </thead>
                                            <tbody>
                                                {batchResults.results.slice(0, 100).map((r, i) => (
                                                    <tr key={i} className="border-b">
                                                        <td className="p-3"><span className={`px-2 py-1 rounded text-xs font-bold ${r.prediction === 'spam' ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'}`}>{r.prediction.toUpperCase()}</span></td>
                                                        <td className="p-3 max-w-md truncate">{r.snippet}</td>
                                                        <td className="p-3">{r.confidence}%</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'history' && (
                        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-sm border border-slate-100 dark:border-slate-700 p-8">
                            <h2 className="text-2xl font-bold mb-6 flex items-center gap-2"><Icon name="history" className="text-primary-500" /> Complete History</h2>
                            <table className="w-full text-sm text-left">
                                <thead className="bg-slate-50 dark:bg-slate-900/50 sticky top-0">
                                    <tr><th className="p-3">Status</th><th className="p-3">Time</th><th className="p-3">Snippet</th></tr>
                                </thead>
                                <tbody>
                                    {history.map((h, i) => (
                                        <tr key={i} className="border-b border-slate-100 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800">
                                            <td className="p-3">
                                                <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${h.prediction === 'spam' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'}`}>
                                                    {h.prediction.toUpperCase()}
                                                </span>
                                            </td>
                                            <td className="p-3 text-slate-500">{new Date(h.timestamp).toLocaleString()}</td>
                                            <td className="p-3 line-clamp-1 max-w-md">{h.snippet}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
}

// Render the App
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
