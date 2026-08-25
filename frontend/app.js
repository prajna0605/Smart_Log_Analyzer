/* ==========================================================================
   SMART LOG ANALYZER & ANOMALY DETECTOR - FRONTEND LOGIC
   Vanilla JavaScript Application Engine
   ========================================================================== */

const API_BASE = window.location.origin;

// State Store
let state = {
  logs: [],
  flaggedMap: {},
  summaries: [],
  activeFilter: 'ALL',
  searchQuery: ''
};

// DOM References
const metricTotalLogs = document.getElementById('metricTotalLogs');
const metricValidLogs = document.getElementById('metricValidLogs');
const metricInvalidLogs = document.getElementById('metricInvalidLogs');
const metricFlaggedAnomalies = document.getElementById('metricFlaggedAnomalies');

const summaryBanner = document.getElementById('summaryBanner');
const summaryBannerText = document.getElementById('summaryBannerText');

const logsTableBody = document.getElementById('logsTableBody');
const tableCountIndicator = document.getElementById('tableCountIndicator');
const searchInput = document.getElementById('searchInput');

const csvFileInput = document.getElementById('csvFileInput');
const btnLoadDefault = document.getElementById('btnLoadDefault');
const btnAnalyzeAll = document.getElementById('btnAnalyzeAll');
const btnClearDb = document.getElementById('btnClearDb');

const inspectionModal = document.getElementById('inspectionModal');
const btnModalClose = document.getElementById('btnModalClose');

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadData();
});

function setupEventListeners() {
  // Action Buttons
  btnLoadDefault.addEventListener('click', handleLoadDefault);
  btnAnalyzeAll.addEventListener('click', handleAnalyzeAll);
  btnClearDb.addEventListener('click', handleClearDb);
  csvFileInput.addEventListener('change', handleFileUpload);

  // Search & Filter
  searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase();
    renderTable();
  });

  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      state.activeFilter = e.target.dataset.status;
      renderTable();
    });
  });

  // Modal Close
  btnModalClose.addEventListener('click', closeModal);
  inspectionModal.addEventListener('click', (e) => {
    if (e.target === inspectionModal) closeModal();
  });
}

// Fetch Application State
async function loadData() {
  try {
    const [logsRes, flaggedRes, summariesRes] = await Promise.all([
      fetch(`${API_BASE}/logs`).then(r => r.json()),
      fetch(`${API_BASE}/flagged`).then(r => r.json()),
      fetch(`${API_BASE}/summaries`).then(r => r.json())
    ]);

    state.logs = logsRes || [];
    state.summaries = summariesRes || [];
    
    state.flaggedMap = {};
    if (Array.isArray(flaggedRes)) {
      flaggedRes.forEach(item => {
        state.flaggedMap[item.log_entry_id] = item;
      });
    }

    renderMetrics();
    renderSummaryBanner();
    renderTable();
  } catch (err) {
    showToast(`🔌 Failed to connect to server: ${err.message}`, 'error');
  }
}

// Render Metrics Cards
function renderMetrics() {
  const total = state.logs.length;
  const valid = state.logs.filter(l => l.is_valid).length;
  const invalid = total - valid;
  const flaggedCount = Object.keys(state.flaggedMap).length;

  metricTotalLogs.textContent = total;
  metricValidLogs.textContent = valid;
  metricInvalidLogs.textContent = invalid;
  metricFlaggedAnomalies.textContent = flaggedCount;
}

// Render Ingestion Summary Banner
function renderSummaryBanner() {
  if (state.summaries.length > 0) {
    const latest = state.summaries[0];
    const createdTime = latest.created_at ? latest.created_at.substring(0, 19).replace('T', ' ') : 'N/A';
    summaryBannerText.innerHTML = `
      📊 Latest File: <strong>${latest.filename}</strong> (${createdTime}) | 
      Total Rows: <strong>${latest.total_rows}</strong> | 
      Loaded: <strong>${latest.loaded_rows}</strong> | 
      Rejected: <strong>${latest.rejected_rows}</strong>
    `;
    summaryBanner.style.display = 'flex';
  } else {
    summaryBanner.style.display = 'none';
  }
}

// Render Main Logs Data Table
function renderTable() {
  logsTableBody.innerHTML = '';

  const filtered = state.logs.filter(entry => {
    const isAnomaly = !!state.flaggedMap[entry.id];
    const status = isAnomaly ? '🚨 ANOMALY' : (entry.is_valid ? '✅ NORMAL' : '❌ INVALID');
    
    // Status Filter Check
    if (state.activeFilter !== 'ALL' && status !== state.activeFilter) {
      return false;
    }

    // Search Query Check
    if (state.searchQuery) {
      const q = state.searchQuery;
      const msg = (entry.raw_message || '').toLowerCase();
      const src = (entry.source || '').toLowerCase();
      const evt = (entry.event_type || '').toLowerCase();
      const sev = (entry.severity || '').toLowerCase();
      return msg.includes(q) || src.includes(q) || evt.includes(q) || sev.includes(q);
    }

    return true;
  });

  tableCountIndicator.textContent = `Showing ${filtered.length} of ${state.logs.length} entries`;

  if (filtered.length === 0) {
    logsTableBody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px;">
          No matching log entries found.
        </td>
      </tr>
    `;
    return;
  }

  filtered.forEach(entry => {
    const isAnomaly = !!state.flaggedMap[entry.id];
    const flagInfo = state.flaggedMap[entry.id];
    const tr = document.createElement('tr');
    
    if (isAnomaly) {
      tr.classList.add('anomaly-row');
    }

    const statusBadge = isAnomaly 
      ? `<span class="badge badge-anomaly">🚨 ANOMALY</span>`
      : (entry.is_valid 
          ? `<span class="badge badge-normal">✅ NORMAL</span>`
          : `<span class="badge badge-invalid">❌ INVALID</span>`);

    const ruleText = isAnomaly ? flagInfo.detector_rule : 'NORMAL';
    const reasonText = isAnomaly ? flagInfo.reason : (entry.validation_error || 'N/A');

    const formattedTime = entry.timestamp ? entry.timestamp.substring(0, 19).replace('T', ' ') : 'N/A';

    tr.innerHTML = `
      <td class="mono">#${entry.id}</td>
      <td class="mono" style="white-space: nowrap;">${formattedTime}</td>
      <td class="mono">${escapeHtml(entry.source || 'UNKNOWN')}</td>
      <td>${escapeHtml(entry.event_type || 'N/A')}</td>
      <td><strong>${escapeHtml(entry.severity || 'N/A')}</strong></td>
      <td>${statusBadge}</td>
      <td class="mono" style="font-size: 12px; color: ${isAnomaly ? '#fca5a5' : 'var(--text-muted)'}">${ruleText}</td>
      <td style="max-width: 280px; font-size: 13px;">${escapeHtml(reasonText)}</td>
      <td>
        ${isAnomaly 
          ? `<button class="btn-inspect" onclick="openModal(${flagInfo.id})">Inspect AI</button>`
          : `<span style="color: var(--text-dim); font-size: 12px;">-</span>`}
      </td>
    `;

    logsTableBody.appendChild(tr);
  });
}

// Modal Inspector Logic
window.openModal = async function(flaggedId) {
  inspectionModal.classList.add('active');
  
  // Set Loading State
  document.getElementById('modalLogId').textContent = '...';
  document.getElementById('modalTimestamp').textContent = '...';
  document.getElementById('modalSource').textContent = '...';
  document.getElementById('modalEventType').textContent = '...';
  document.getElementById('modalSeverity').textContent = '...';
  document.getElementById('modalRule').textContent = '...';
  document.getElementById('modalScore').textContent = '...';
  document.getElementById('modalReason').textContent = '...';
  document.getElementById('modalAiExplanation').textContent = 'Retrieving Gemini AI analysis...';
  document.getElementById('modalAiRootCause').textContent = 'Retrieving Gemini AI root cause...';

  try {
    const res = await fetch(`${API_BASE}/flagged/${flaggedId}`);
    if (!res.ok) throw new Error('Failed to fetch detail');
    const flag = await res.json();
    const log = flag.log_entry || {};

    document.getElementById('modalLogId').textContent = `#${log.id || 'N/A'}`;
    document.getElementById('modalTimestamp').textContent = log.timestamp ? log.timestamp.substring(0, 19).replace('T', ' ') : 'N/A';
    document.getElementById('modalSource').textContent = log.source || 'N/A';
    document.getElementById('modalEventType').textContent = log.event_type || 'N/A';
    document.getElementById('modalSeverity').textContent = log.severity || 'N/A';
    document.getElementById('modalRule').textContent = flag.detector_rule;
    document.getElementById('modalScore').textContent = flag.score;
    document.getElementById('modalReason').textContent = flag.reason;

    document.getElementById('modalAiExplanation').textContent = flag.ai_explanation || 'No explanation generated yet. Click "Batch AI Analyze Anomalies" to generate.';
    document.getElementById('modalAiRootCause').textContent = flag.ai_root_cause || 'No root cause generated yet.';
  } catch (err) {
    showToast(`Error loading inspection detail: ${err.message}`, 'error');
  }
};

function closeModal() {
  inspectionModal.classList.remove('active');
}

// Actions Handlers
async function handleLoadDefault() {
  try {
    showToast('⚙️ Ingesting default logs.csv dataset...', 'info');
    const res = await fetch(`${API_BASE}/ingest-default`, { method: 'POST' });
    if (res.ok) {
      showToast('✅ Default dataset loaded & analyzed successfully!', 'success');
      await loadData();
    } else {
      const err = await res.json();
      showToast(`❌ Load failed: ${err.detail}`, 'error');
    }
  } catch (err) {
    showToast(`❌ Connection error: ${err.message}`, 'error');
  }
}

async function handleFileUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    showToast(`🚀 Processing ${file.name}...`, 'info');
    const res = await fetch(`${API_BASE}/ingest`, {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      showToast('✅ File uploaded and anomalies flagged successfully!', 'success');
      csvFileInput.value = '';
      await loadData();
    } else {
      const err = await res.json();
      showToast(`❌ Ingestion failed: ${err.detail}`, 'error');
    }
  } catch (err) {
    showToast(`❌ Error uploading file: ${err.message}`, 'error');
  }
}

async function handleAnalyzeAll() {
  try {
    showToast('🤖 Generating batch Gemini AI explanations for all anomalies...', 'info');
    const res = await fetch(`${API_BASE}/analyze-all-anomalies`, { method: 'POST' });
    if (res.ok) {
      showToast('✨ Gemini AI insights generated for all flagged entries!', 'success');
      await loadData();
    } else {
      const err = await res.json();
      showToast(`❌ AI Analysis failed: ${err.detail}`, 'error');
    }
  } catch (err) {
    showToast(`❌ Error triggering AI analysis: ${err.message}`, 'error');
  }
}

async function handleClearDb() {
  if (!confirm('Are you sure you want to clear all ingested logs from the database?')) return;

  try {
    const res = await fetch(`${API_BASE}/clear`, { method: 'POST' });
    if (res.ok) {
      showToast('🗑️ Database wiped clean.', 'info');
      await loadData();
    } else {
      showToast('❌ Clear database failed.', 'error');
    }
  } catch (err) {
    showToast(`❌ Error: ${err.message}`, 'error');
  }
}

// Helpers & Utilities
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type = 'info') {
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'error') toast.style.borderColor = 'var(--accent-rose)';
  if (type === 'success') toast.style.borderColor = 'var(--accent-emerald)';
  toast.textContent = msg;

  const container = document.getElementById('toastContainer');
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
