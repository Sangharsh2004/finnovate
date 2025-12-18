const BASE = "https://datapulse-backend-5898.onrender.com";
const ML = "https://datapulse-backend-5898.onrender.com";

let eventSource = null;

function openEventStream() {
  if (eventSource) {
    try { eventSource.close(); } catch (e) {}
    eventSource = null;
  }
  if (!session.token) return;

  const esUrl = `${BASE}/api/events?token=${encodeURIComponent(session.token)}`;
  eventSource = new EventSource(esUrl);

  eventSource.addEventListener("budget-update", (ev) => {
    try {
      const d = JSON.parse(ev.data);
      console.log("Budget updated:", d.remaining);
loadDashboard();

    } catch (e) { console.warn('budget-update parse error', e); }
  });

  eventSource.addEventListener("transaction-update", (ev) => {
    try {
      const d = JSON.parse(ev.data);
     console.log("Budget updated:", d.remaining);
loadDashboard();

    } catch (e) { console.warn('transaction-update parse error', e); }
  });

  eventSource.onerror = (err) => {
    console.warn('EventSource error', err);
    // it will auto-retry; keep minimal for now
  };
}

function closeEventStream() {
  if (eventSource) {
    try { eventSource.close(); } catch (e) { /* ignore */ }
    eventSource = null;
  }
}

// --- Session & Global State ---
let session = {
  id: localStorage.getItem('fp_userId') || '',
  token: localStorage.getItem('fp_token') || '',
  name: localStorage.getItem('fp_name') || ''
};

const loginContainer = document.getElementById('login-container');
const signupContainer = document.getElementById('signup-container');
const otpContainer = document.getElementById('otp-container');
const forgotContainer = document.getElementById('forgot-container');
const resetContainer = document.getElementById('reset-container');
const dashboardSection = document.getElementById('dashboard-section');

const navDashboardBtn = document.getElementById('nav-dashboard');
const navExpensesBtn = document.getElementById('nav-expenses');
const navIncomeBtn = document.getElementById('nav-income');
const navChartsBtn = document.getElementById('nav-charts');
const navSettingsBtn = document.getElementById('nav-settings');

const dashboardView = document.getElementById('dashboard-view');
const expensesView = document.getElementById('expenses-view');
const incomeView = document.getElementById('income-view');
const chartsView = document.getElementById('charts-view');
const settingsView = document.getElementById('settings-view');

let allTransactions = []; // full transaction cache for charts/lists
let monthlyChart = null;
let categoryPieChart = null;

// Currency formatter
const currencyFormatter = new Intl.NumberFormat('en-IN', {
  style: 'currency',
  currency: 'INR',
  minimumFractionDigits: 2,
});

// --- Small helpers ---
function el(id) { return document.getElementById(id); }

function safeJSONParse(text) {
  try { return JSON.parse(text); } catch (e) { return null; }
}

// Reusable API fetch with auth + JSON handling
async function apiFetch(endpoint, options = {}) {
  const url = `${BASE}${endpoint}`;
  const headers = Object.assign({}, options.headers || {}, { 'Content-Type': 'application/json' });
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  // If body is present and not a FormData, stringify
  if (options.body && typeof options.body !== 'string' && !(options.body instanceof FormData)) {
    options.body = JSON.stringify(options.body);
  }

  try {
    const res = await fetch(url, { ...options, headers });
    // Default assume JSON
    const text = await res.text();
    const data = safeJSONParse(text) || { success: res.ok, message: text || (res.ok ? 'OK' : 'Unknown error') };
    if (!res.ok && data && !data.success) {
      // return object with message
      return data;
    }
    return data;
  } catch (err) {
    console.error('API fetch failed', endpoint, err);
    return { success: false, message: 'Network or server error.' };
  }
}

// --- UI helpers ---
function showElement(elm) { if (elm) elm.classList.remove('hidden'); }
function hideElement(elm) { if (elm) elm.classList.add('hidden'); }

function clearAuthViews() {
  hideElement(loginContainer);
  hideElement(signupContainer);
  hideElement(otpContainer);
  hideElement(forgotContainer);
  hideElement(resetContainer);
}

// Show dashboard, load profile and dashboard data
function showDashboard(name) {
  session.name = name || session.name || 'User';
  if (el('dashboard-username')) el('dashboard-username').textContent = session.name;
  dashboardSection.classList.remove('hidden');
  hideElement(loginContainer);
  hideElement(signupContainer);
  hideElement(otpContainer);
  hideElement(forgotContainer);
  hideElement(resetContainer);
  switchView('dashboard'); // loads dashboard view and data
}

// Auto-login if token present (page load)
window.addEventListener('load', async () => {
  if (session.token && session.id) {
    // Try to fetch profile to validate token
    const profile = await apiFetch('/api/profile', { method: 'GET' });
    if (profile && profile.success) {
      session.name = profile.user.name || session.name;
      localStorage.setItem('fp_name', session.name);
      showDashboard(session.name);
      await loadDashboard();
      // OPEN SSE after successful auto-login
      openEventStream();
    } else {
      // invalid token -> clear and show login
      localStorage.removeItem('fp_token');
      localStorage.removeItem('fp_userId');
      localStorage.removeItem('fp_name');
      session = { id: '', token: '', name: '' };
      hideElement(dashboardSection);
      showElement(loginContainer);
    }
  } else {
    hideElement(dashboardSection);
    showElement(loginContainer);
  }
});

// --- AUTH NAV ---
document.getElementById('show-signup')?.addEventListener('click', () => {
  hideElement(loginContainer);
  showElement(signupContainer);
});
document.getElementById('show-login')?.addEventListener('click', () => {
  hideElement(signupContainer);
  showElement(loginContainer);
});

// --- SIGNUP (request OTP) ---
document.getElementById('signup-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = el('signup-name').value.trim();
  const email = el('signup-email').value.trim();
  const password = el('signup-password').value;
  if (!name || !email || !password) return alert('Please fill all fields.');

  const res = await apiFetch('/api/send-signup-otp', {
    method: 'POST',
    body: { name, email, password }
  });

  if (res && res.success) {
    // Store temporary signup data for OTP verification - do NOT store password insecurely in localStorage
    session._tempSignup = { name, email, password };
    // but also keep a non-sensitive copy in localStorage for resend convenience (no password)
    localStorage.setItem('fp_temp_signup', JSON.stringify({ name, email }));
    alert('OTP sent to your email. Enter OTP to verify and create account.');
    hideElement(signupContainer);
    showElement(otpContainer);
  } else {
    alert(res.message || 'Failed to send OTP.');
  }
});

// --- Resend OTP (signup) ---
document.getElementById('resend-otp')?.addEventListener('click', async () => {
  // Try to resend using temp signup stored in memory or localStorage
  let temp = session._tempSignup || safeJSONParse(localStorage.getItem('fp_temp_signup'));
  if (!temp || !temp.email) return alert('No signup in progress to resend OTP for. Please start signup again.');
  // For resend we need name & password as well in backend's current implementation; use memory copy if exists.
  if (!session._tempSignup || !session._tempSignup.password) {
    // we don't have password in localStorage for security reasons - ask user to re-enter
    const password = prompt('Please enter the password you used for signup (necessary to resend OTP):');
    if (!password) return alert('Resend cancelled — password required.');
    temp = { name: temp.name, email: temp.email, password };
    session._tempSignup = temp; // store in-memory temporarily
  }

  const res = await apiFetch('/api/send-signup-otp', {
    method: 'POST',
    body: { name: session._tempSignup.name, email: session._tempSignup.email, password: session._tempSignup.password }
  });

  if (res && res.success) {
    alert('OTP resent to your email.');
    hideElement(signupContainer);
    showElement(otpContainer);
  } else {
    alert(res.message || 'Failed to resend OTP.');
  }
});

// --- VERIFY SIGNUP OTP ---
document.getElementById('otp-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const otp = el('otp-code').value.trim();
  // Use temp signup stored in-memory first, fallback to localStorage (password not available there)
  const temp = session._tempSignup || safeJSONParse(localStorage.getItem('fp_temp_signup') || '{}');
  if (!temp || !temp.email || !temp.password) {
    // If password missing, we must ask user to re-enter (server requires password to create account)
    const pwd = prompt('Please enter the password you used while signing up (required to complete signup)');
    if (!pwd) return alert('Password required to verify OTP and create account.');
    temp.password = pwd;
    session._tempSignup = temp;
  }
  if (!otp) return alert('Please enter OTP.');

  const res = await apiFetch('/api/verify-signup-otp', {
    method: 'POST',
    body: { name: temp.name, email: temp.email, password: temp.password, otp }
  });

  if (res && res.success) {
    // Successful verification -> store token & user, show dashboard
    session.id = res.user.id;
    session.token = res.token;
    session.name = res.user.name;
    localStorage.setItem('fp_userId', session.id);
    localStorage.setItem('fp_token', session.token);
    localStorage.setItem('fp_name', session.name);
    // cleanup temp
    localStorage.removeItem('fp_temp_signup');
    session._tempSignup = null;

    // UI transitions (FIXED): hide auth views, display dashboard, load data
    hideElement(otpContainer);
    hideElement(signupContainer);
    hideElement(loginContainer);
    showDashboard(session.name);
    await loadDashboard();

    // OPEN SSE now that user is logged in
    openEventStream();

    // Clear OTP input
    el('otp-code').value = '';
    alert('Account verified and created. You are now logged in.');
  } else {
    alert(res && res.message ? res.message : 'OTP verification failed.');
  }
});

// Also support the "Verify OTP" button in case separate element exists
document.getElementById('verify-otp-btn')?.addEventListener('click', async () => {
  const form = document.getElementById('otp-form');
  if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
});

// --- LOGIN ---
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = el('login-email').value.trim();
  const password = el('login-password').value;
  if (!email || !password) return alert('Please enter email and password.');

  const res = await apiFetch('/api/login', {
    method: 'POST',
    body: { email, password }
  });

  if (res && res.success) {
    session.id = res.user.id;
    session.token = res.token;
    session.name = res.user.name;
    localStorage.setItem('fp_userId', session.id);
    localStorage.setItem('fp_token', session.token);
    localStorage.setItem('fp_name', session.name);
    showDashboard(session.name);
    await loadDashboard();
    // OPEN SSE after login
    openEventStream();
  } else {
    alert(res && res.message ? res.message : 'Login failed.');
  }
});

// --- LOGOUT ---
el('logout-btn')?.addEventListener('click', () => {
  localStorage.removeItem('fp_userId');
  localStorage.removeItem('fp_token');
  localStorage.removeItem('fp_name');
  session = { id: '', token: '', name: '' };
  // show login
  hideElement(dashboardSection);
  showElement(loginContainer);
  // clear transactions/charts
  allTransactions = [];
  if (monthlyChart) { monthlyChart.destroy(); monthlyChart = null; }
  if (categoryPieChart) { categoryPieChart.destroy(); categoryPieChart = null; }
  // close SSE connection
  closeEventStream();
});

// --- TRANSACTION SUBMIT ---
document.getElementById('add-transaction-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const description = el('transaction-description').value.trim();
  let category = el('transaction-category').value.trim();
  const amountRaw = el('transaction-amount').value;
  const amount = Number(amountRaw);
  const type = el('transaction-type').value;

  if (!description || !amountRaw) return alert('Please fill required fields.');

  const mlSuggestionEl = el('ml-suggestion');
  if (!category && description) {
    // try ML service for category suggestion but don't block on it
    try {
      const r = await fetch(`${ML}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: description })
      });
      if (r.ok) {
        const j = await r.json();
        if (j && j.success && j.category) {
          category = j.category;
          if (mlSuggestionEl) mlSuggestionEl.textContent = `ML suggestion: ${category}${j.confidence ? ` (${Math.round(j.confidence*100)}%)` : ''}`;
        }
      }
    } catch (err) {
      if (mlSuggestionEl) mlSuggestionEl.textContent = '';
      console.warn('ML service not available', err);
    }
  } else if (mlSuggestionEl) {
    mlSuggestionEl.textContent = '';
  }

  const res = await apiFetch('/api/transactions', {
    method: 'POST',
    body: { userId: session.id, type, category, amount, description }
  });

  if (res && res.success) {
    // reset form and reload dashboard
    el('add-transaction-form').reset();
    if (mlSuggestionEl) mlSuggestionEl.textContent = '';
    await loadDashboard();
    // If currently viewing transactions lists, re-render
    const currentView = document.querySelector('.content-view:not(.hidden)')?.id || 'dashboard-view';
    if (currentView.includes('expenses')) renderTransactionList('expense');
    if (currentView.includes('income')) renderTransactionList('income');
  } else {
    alert(res && res.message ? res.message : 'Error adding transaction.');
  }
});

// --- RENDER TRANSACTION LISTS ---
function renderTransactionList(type) {
  const isExpense = type === 'expense';
  const listElement = el(isExpense ? 'expense-transaction-list' : 'income-transaction-list');
  if (!listElement) return;

  const filtered = allTransactions
    .filter(t => t.type === type)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  listElement.innerHTML = '';
  if (!filtered.length) {
    listElement.innerHTML = `<li class="text-center loading-placeholder">No ${type} transactions recorded yet.</li>`;
    return;
  }

  filtered.forEach(t => {
    const li = document.createElement('li');
    li.classList.add('transaction-item');
    const when = t.created_at ? new Date(t.created_at).toLocaleString() : 'N/A';
    const amountClass = isExpense ? 'expense-amount' : 'income-amount';
    li.innerHTML = `
      <div class="transaction-detail-wrapper">
        <div class="transaction-info">
          <strong>${t.description || 'No Description'}</strong>
          <small class="meta-text">Category: ${t.category || 'Uncategorized'}</small>
        </div>
        <div class="transaction-amount-info">
          <span class="${amountClass} amount-display">${isExpense ? '-' : '+'}${currencyFormatter.format(Number(t.amount))}</span>
          <small class="meta-text">${when}</small>
        </div>
      </div>
    `;
    listElement.appendChild(li);
  });
}
// --- CHARTS ---
function renderCharts() {
  // derive monthly aggregates
  const monthlyMap = {};
  allTransactions.forEach(t => {
    const d = new Date(t.created_at);
    if (isNaN(d)) return;
    const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2, '0')}`;
    const label = d.toLocaleString('default', { month: 'short', year: 'numeric' });
    if (!monthlyMap[key]) monthlyMap[key] = { label, income: 0, expense: 0 };
    if (t.type === 'income') monthlyMap[key].income += Number(t.amount);
    else monthlyMap[key].expense += Number(t.amount);
  });

  const keys = Object.keys(monthlyMap).sort();
  const labels = keys.map(k => monthlyMap[k].label);
  const incomes = keys.map(k => monthlyMap[k].income);
  const expenses = keys.map(k => monthlyMap[k].expense);

  const monthlyCtx = document.getElementById('monthlyChart')?.getContext('2d');

  if (monthlyCtx) {
    if (monthlyChart) monthlyChart.destroy();

    // 🔥 Create gradient colors
    const incomeGradient = monthlyCtx.createLinearGradient(0, 0, 0, 300);
    incomeGradient.addColorStop(0, "rgba(46, 204, 113, 0.9)");
    incomeGradient.addColorStop(1, "rgba(46, 204, 113, 0.3)");

    const expenseGradient = monthlyCtx.createLinearGradient(0, 0, 0, 300);
    expenseGradient.addColorStop(0, "rgba(231, 76, 60, 0.9)");
    expenseGradient.addColorStop(1, "rgba(231, 76, 60, 0.3)");

    monthlyChart = new Chart(monthlyCtx, {
      type: 'bar',
      data: {
        labels: labels.length ? labels : ['No data'],
        datasets: [
          {
            label: 'Income',
            data: incomes.length ? incomes : [0],
            backgroundColor: incomeGradient,
            borderColor: "#27ae60",
            borderWidth: 2,
            borderRadius: 10,
            hoverBackgroundColor: "rgba(39, 174, 96, 1)",
            barThickness: 35
          },
          {
            label: 'Expense',
            data: expenses.length ? expenses : [0],
            backgroundColor: expenseGradient,
            borderColor: "#c0392b",
            borderWidth: 2,
            borderRadius: 10,
            hoverBackgroundColor: "rgba(192, 57, 43, 1)",
            barThickness: 35
          }
        ]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'top',
            labels: {
              font: { size: 14, weight: 'bold' },
              color: '#2c3e50'
            }
          }
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  // PIE CHART
  const expenseData = allTransactions.filter(t => t.type === 'expense');
  const catMap = {};
  expenseData.forEach(t => {
    const c = t.category || 'Uncategorized';
    catMap[c] = (catMap[c] || 0) + Number(t.amount);
  });

  const pieLabels = Object.keys(catMap);
  const pieAmounts = Object.values(catMap);
  const pieCtx = document.getElementById('categoryPieChart')?.getContext('2d');

  if (pieCtx) {
    if (categoryPieChart) categoryPieChart.destroy();

    // 🔥 Attractive Pie Colors
    const pieColors = [
      "#3498db", "#9b59b6", "#e74c3c", "#f1c40f",
      "#1abc9c", "#e67e22", "#2ecc71", "#7f8c8d"
    ];

    categoryPieChart = new Chart(pieCtx, {
      type: 'pie',
      data: {
        labels: pieLabels.length ? pieLabels : ['No expenses'],
        datasets: [
          {
            data: pieAmounts.length ? pieAmounts : [1],
            backgroundColor: pieColors,
            borderWidth: 2,
            borderColor: "#fff",
            hoverOffset: 15
          }
        ]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              font: { size: 13, weight: 'bold' },
              color: '#2c3e50'
            }
          }
        }
      }
    });
  }
}

// --- NAV & VIEW SWITCHING ---
function switchView(viewName) {
  [dashboardView, expensesView, incomeView, chartsView, settingsView].forEach(v => v?.classList.add('hidden'));
  [navDashboardBtn, navExpensesBtn, navIncomeBtn, navChartsBtn, navSettingsBtn].forEach(b => {
    b?.classList.remove('btn-primary-alt');
    b?.classList.add('btn-secondary');
  });

  if (viewName === 'dashboard') {
    dashboardView?.classList.remove('hidden');
    navDashboardBtn?.classList.add('btn-primary-alt');
    navDashboardBtn?.classList.remove('btn-secondary');
    loadDashboard();
  } else if (viewName === 'expenses') {
    expensesView?.classList.remove('hidden');
    navExpensesBtn?.classList.add('btn-primary-alt');
    navExpensesBtn?.classList.remove('btn-secondary');
    renderTransactionList('expense');
  } else if (viewName === 'income') {
    incomeView?.classList.remove('hidden');
    navIncomeBtn?.classList.add('btn-primary-alt');
    navIncomeBtn?.classList.remove('btn-secondary');
    renderTransactionList('income');
  } else if (viewName === 'charts') {
    chartsView?.classList.remove('hidden');
    navChartsBtn?.classList.add('btn-primary-alt');
    navChartsBtn?.classList.remove('btn-secondary');
    renderCharts();
  } else if (viewName === 'settings') {
    settingsView?.classList.remove('hidden');
    navSettingsBtn?.classList.add('btn-primary-alt');
    navSettingsBtn?.classList.remove('btn-secondary');
  }
}

navDashboardBtn?.addEventListener('click', () => switchView('dashboard'));
navExpensesBtn?.addEventListener('click', () => switchView('expenses'));
navIncomeBtn?.addEventListener('click', () => switchView('income'));
navChartsBtn?.addEventListener('click', () => switchView('charts'));
navSettingsBtn?.addEventListener('click', () => switchView('settings'));

// --- LOAD DASHBOARD ---
async function loadDashboard() {
  const data = await apiFetch('/api/dashboard/summary', { method: 'GET' });
  if (!data || !data.success) {
    console.error('Failed to load dashboard:', data && data.message);
    return;
  }

  const s = data.summary || { totalIncome: 0, totalExpense: 0, netSavings: 0 };
  if (el('total-income')) el('total-income').textContent = currencyFormatter.format(s.totalIncome);
  if (el('total-expense')) el('total-expense').textContent = currencyFormatter.format(s.totalExpense);
  if (el('net-savings')) el('net-savings').textContent = currencyFormatter.format(s.netSavings);
  if (el('ai-recommendation')) el('ai-recommendation').textContent = data.recommendation || 'No recommendation';

  allTransactions = Array.isArray(data.transactions) ? data.transactions : [];

  // dashboard recent list
  const list = el('transaction-list');
  if (!list) return;
  list.innerHTML = '';
  const recent = allTransactions.slice(0, 5);
  if (!recent.length) {
    list.innerHTML = '<li class="loading-placeholder">No transactions yet</li>';
  } else {
    recent.forEach(t => {
      const li = document.createElement('li');
      const when = t.created_at ? new Date(t.created_at).toLocaleString() : '';
      li.textContent = `[${t.type}] ${currencyFormatter.format(Number(t.amount))} — ${t.category || '-'} — ${t.description || ''} (${when})`;
      list.appendChild(li);
    });
  }
}

// --- ALERTS ---
el('check-alerts')?.addEventListener('click', async () => {
  const data = await apiFetch('/api/alerts', { method: 'GET' });
  const list = el('alerts-list');
  if (!list) return;
  list.innerHTML = '';
  if (data && data.success && data.alerts && data.alerts.length) {
    data.alerts.forEach(a => { const li = document.createElement('li'); li.textContent = a; list.appendChild(li); });
  } else {
    list.innerHTML = '<li class="loading-placeholder">No alerts</li>';
  }
});

// --- BUDGET SAVE ---
el('budget-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const mb = Number(el('monthly-budget').value || 0);
  const res = await apiFetch('/api/budget', { method: 'POST', body: { userId: session.id, monthlyBudget: mb } });
  if (res && res.success) alert('Budget saved.');
  else alert(res && res.message ? res.message : 'Error saving budget.');
});

// --- EXPORT CSV (download) ---
el('export-csv')?.addEventListener('click', async () => {
  try {
    const r = await fetch(`${BASE}/api/transactions/export`, { headers: { Authorization: `Bearer ${session.token}` }});
    if (!r.ok) {
      const text = await r.text();
      if (r.status === 401 || text.includes('Unauthorized')) {
        alert('Authentication failed during export. Please login again.');
        return;
      }
      throw new Error('Export failed');
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    // filename derived from content-disposition if provided, fallback:
    a.download = 'transactions.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('Export download failed', err);
    alert('Export failed. Please try again.');
  }
});

// --- EMAIL CSV + SUMMARY ---
el('email-csv-summary')?.addEventListener('click', async () => {
  const res = await apiFetch('/api/transactions/export-summary-email', { method: 'POST', body: {} });
  if (res && res.success) alert('CSV & summary emailed to your registered address.');
  else alert(res && res.message ? res.message : 'Failed to email summary.');
});

// --- REFRESH BUTTON ---
// --- REFRESH BUTTON ---
document.addEventListener('DOMContentLoaded', () => {
  el('refresh-btn')?.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    await loadDashboard();

    const current =
      document.querySelector('.content-view:not(.hidden)')?.id || 'dashboard-view';

    if (current.includes('charts')) renderCharts();
    else if (current.includes('expenses')) renderTransactionList('expense');
    else if (current.includes('income')) renderTransactionList('income');
  });
});
// ================= DIRECT VOICE ASSISTANT (FINAL + FEATURES) =================

// Browser Speech API
const SpeechRecognition =
  window.SpeechRecognition || window.webkitSpeechRecognition;
const synth = window.speechSynthesis;

// Speak helper
function speak(text, lang = "en-IN") {
  synth.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = lang;
  synth.speak(u);
}

if (!SpeechRecognition) {
  alert("Speech Recognition not supported in this browser");
}

// Recognition setup
const recognition = new SpeechRecognition();
recognition.lang = "en-IN";
recognition.continuous = false;
recognition.interimResults = false;

// 🎤 MIC BUTTON
el("voice-btn")?.addEventListener("click", () => {
  speak("Listening");
  recognition.start();
});

// 🎧 RESULT
recognition.onresult = async (event) => {
  let text = event.results[0][0].transcript.toLowerCase();
  text = text.replace(/^(and|so|please|okay)\s+/g, "").trim();

  console.log("🎤 Command:", text);

  // ====================================================
  // 1️⃣ ADD INCOME / EXPENSE
  // ====================================================
  if (
    (text.includes("expense") || text.includes("खर्च") ||
     text.includes("income") || text.includes("उत्पन्न")) &&
    text.match(/\d+/)
  ) {
    const data = extractTransaction(text);
    if (!data) {
      speak("Amount samajla nahi", "mr-IN");
      return;
    }

    const type =
      text.includes("income") || text.includes("उत्पन्न")
        ? "income"
        : "expense";

    await apiFetch("/api/transactions", {
      method: "POST",
      body: {
        userId: session.id,
        type,
        amount: data.amount,
        category: data.category,
        description: "Voice entry"
      }
    });

    speak(`${type === "income" ? "Income" : "Expense"} ${data.amount} added`);
    return;
  }

  // ====================================================
  // 2️⃣ SAVE / SET BUDGET
  // ====================================================
  if (text.includes("budget") && text.match(/\d+/)) {
    const amount = Number(text.match(/\d+/)[0]);

    await apiFetch("/api/budget", {
      method: "POST",
      body: {
        userId: session.id,
        monthlyBudget: amount
      }
    });

    speak(`Monthly budget set to ${amount}`);
    return;
  }
// ====================================================
// 3️⃣ DOWNLOAD CSV (FIXED)
// ====================================================
if (
  text.includes("download csv") ||
  text.includes("export csv") ||
  text.includes("download transactions")
) {
  speak("Downloading CSV file");

  try {
    const res = await fetch(`${BASE}/api/transactions/export`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${session.token}`
      }
    });

    if (!res.ok) {
      console.error("CSV download failed:", res.status);
      speak("Failed to download CSV");
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "transactions.csv";
    document.body.appendChild(a);
    a.click();

    a.remove();
    window.URL.revokeObjectURL(url);

    speak("CSV downloaded successfully");
  } catch (err) {
    console.error("CSV error:", err);
    speak("Error downloading CSV file");
  }

  return;
}

  // ====================================================
  // 4️⃣ EMAIL CSV
  // ====================================================
  if (
    text.includes("email csv") ||
    text.includes("send csv") ||
    text.includes("mail transactions")
  ) {
    await apiFetch("/api/transactions/export-email", {
      method: "POST",
      body: { userId: session.id }
    });

    speak("CSV file sent to your email");
    return;
  }

  // ====================================================
  // 5️⃣ CHECK ALERTS
  // ====================================================
  if (
    text.includes("check alert") ||
    text.includes("show alert") ||
    text.includes("budget alert")
  ) {
    const res = await apiFetch("/api/alerts");
    if (res.alerts && res.alerts.length) {
      speak(res.alerts.join(". "));
    } else {
      speak("No alerts at the moment");
    }
    return;
  }

  // ====================================================
  // 6️⃣ NAVIGATION
  // ====================================================
  if (text.includes("dashboard")) {
    speak("Opening dashboard");
    switchView("dashboard");
    return;
  }

  if (text.includes("income")) {
    speak("Opening income");
    switchView("income");
    return;
  }

  if (text.includes("expense")) {
    speak("Opening expenses");
    switchView("expenses");
    return;
  }

  if (text.includes("profile")) {
    speak("Opening profile");
    el("profile-btn")?.click();
    return;
  }

  if (text.includes("refresh")) {
    el("refresh-btn")?.click();
    speak("Data refreshed");
    return;
  }

  // ====================================================
  // FALLBACK
  // ====================================================
  speak("Sorry, command not recognized");
};

recognition.onerror = (e) => {
  console.error("Voice error:", e.error);
  speak("Voice recognition error");
};

// ====================================================
// NLP Helper
// ====================================================
function extractTransaction(text) {
  const amountMatch = text.match(/\d+/);
  if (!amountMatch) return null;

  const amount = Number(amountMatch[0]);

  const category = text
    .replace(/add|expense|income|budget|खर्च|उत्पन्न|₹|\d+/g, "")
    .trim();

  return {
    amount,
    category: category || "General"
  };
}

// --- FORGOT PASSWORD FLOW ---
el('show-forgot')?.addEventListener('click', () => {
  hideElement(loginContainer);
  showElement(forgotContainer);
});
el('back-to-login')?.addEventListener('click', () => {
  hideElement(forgotContainer);
  showElement(loginContainer);
});
el('back-to-login2')?.addEventListener('click', () => {
  hideElement(resetContainer);
  showElement(loginContainer);
});

// Step 1: request reset OTP
el('forgot-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = el('forgot-email').value.trim();
  if (!email) return alert('Please enter your registered email.');
  const res = await apiFetch('/api/forgot-password', { method: 'POST', body: { email }});
  if (res && res.success) {
    alert('OTP sent to your registered email.');
    hideElement(forgotContainer);
    showElement(resetContainer);
    el('reset-email').value = email;
  } else {
    alert(res && res.message ? res.message : 'Failed to send OTP.');
  }
});

// Step 2: reset password using OTP
el('reset-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = el('reset-email').value.trim();
  const otp = el('reset-otp').value.trim();
  const newPassword = el('reset-password').value.trim();
  if (!email || !otp || !newPassword) return alert('Please fill all fields.');
  const res = await apiFetch('/api/reset-password', { method: 'POST', body: { email, otp, password: newPassword }});
  if (res && res.success) {
    alert('Password reset successful. Please log in with your new password.');
    hideElement(resetContainer);
    showElement(loginContainer);
  } else {
    alert(res && res.message ? res.message : 'Password reset failed.');
  }
});

// --- PROFILE MODAL ---
el('profile-btn')?.addEventListener('click', async () => {
  const data = await apiFetch('/api/profile', { method: 'GET' });
  if (data && data.success) {
    el('profile-info').innerHTML = `<p><strong>${data.user.name}</strong><br>${data.user.email}</p>`;
    showElement(el('profile-modal'));
  } else {
    alert(data && data.message ? data.message : 'Cannot load profile.');
  }
});
el('close-profile')?.addEventListener('click', () => hideElement(el('profile-modal')));

// --- Utility: small UX niceties ---
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    // Prevent accidental submits triggering when inputs not in forms
  }
});

// ================= PROFILE DROPDOWN + CHANGE PHOTO =================
const profileBtn = document.getElementById('profile-btn');
const profileMenu = document.getElementById('profile-menu');
const menuPhoto = document.getElementById('menu-photo');
const menuName = document.getElementById('menu-name');
const menuEmail = document.getElementById('menu-email');
const profileIcon = document.getElementById('profile-icon');
const myProfileBtn = document.getElementById('my-profile-btn');
const changePhotoBtn = document.getElementById('change-photo-btn');
const logoutMenuBtn = document.getElementById('logout-menu-btn');

// Load saved profile photo at startup
window.addEventListener('load', () => {
  const savedPhoto = localStorage.getItem('profilePhoto');
  if (savedPhoto) {
    profileIcon.src = savedPhoto;
    menuPhoto.src = savedPhoto;
  }
});

// Toggle dropdown
profileBtn?.addEventListener('click', async (e) => {
  e?.stopPropagation();
  profileMenu.classList.toggle('hidden');
  if (!profileMenu.classList.contains('hidden')) {
    // Load user data dynamically
    const data = await fetch(`${BASE}/api/profile`, {
      headers: { Authorization: `Bearer ${session.token}` },
    }).then(r => r.json()).catch(() => null);
    if (data && data.success) {
      menuName.textContent = data.user.name;
      menuEmail.textContent = data.user.email;
    }
  }
});

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  if (profileMenu && !profileMenu.contains(e.target) && e.target !== profileBtn) {
    profileMenu.classList.add('hidden');
  }
});

// My Profile (shows modal info)
myProfileBtn?.addEventListener('click', () => {
  profileMenu?.classList.add('hidden');
  document.getElementById('profile-modal')?.classList.remove('hidden');
});

// Change Profile (direct file explorer)
changePhotoBtn?.addEventListener('click', () => {
  profileMenu?.classList.add('hidden');
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = 'image/*';
  fileInput.onchange = (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result;
      // Save locally
      localStorage.setItem('profilePhoto', base64);
      // Update both UI photos
      profileIcon.src = base64;
      menuPhoto.src = base64;
    };
    reader.readAsDataURL(file);
  };
  fileInput.click();
});

// Logout
logoutMenuBtn?.addEventListener('click', () => {
  localStorage.removeItem('fp_token');
  localStorage.removeItem('fp_userId');
  localStorage.removeItem('fp_name');
  localStorage.removeItem('profilePhoto');
  // close SSE if open
  closeEventStream();
  window.location.reload();
});

// End of script.js
