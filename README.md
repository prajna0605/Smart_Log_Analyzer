# 🛡️ Smart Log Analyzer & Anomaly Detector MVP

> **Automated, Adaptive Log Parsing, Rule-Based Anomaly Detection, and AI-Powered Root-Cause Insights with Google Gemini 3.6 Flash & Glassmorphic HTML5/CSS3/JS Web Interface.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![HTML5/CSS3](https://img.shields.io/badge/Frontend-HTML5_--_CSS3_--_JS-E34F26?logo=html5&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Gemini_AI-3.6_Flash-8E44AD?logo=google-gemini&logoColor=white)
![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen)

---

## 📑 Table of Contents
- [🌟 Key Features](#-key-features)
- [📐 System Architecture](#-system-architecture)
- [📥 Adaptive CSV Ingestion Engine](#-adaptive-csv-ingestion-engine)
- [🎯 Anomaly Detector Rules & Logic](#-anomaly-detector-rules--logic)
- [🤖 Gemini AI Root-Cause Explainer](#-gemini-ai-root-cause-explainer)
- [🔌 REST API Endpoint Reference](#-rest-api-endpoint-reference)
- [🖥️ Glassmorphic Web Dashboard](#-glassmorphic-web-dashboard)
- [🚀 Quick Start & Step-by-Step Setup Guide](#-quick-start--step-by-step-setup-guide)
- [🧪 Automated Unit Testing](#-automated-unit-testing)
- [📁 Project Folder Structure](#-project-folder-structure)
- [💡 Design Rationale & Trade-offs](#-design-rationale--trade-offs)

---

## 🌟 Key Features

- 🔄 **Adaptive CSV Column Normalization**: Ingests custom web access logs, firewall logs, or system logs without fixed header names (`IP_Address`, `Status_Code`, `Request_Type`, `User_Agent`, `Session_ID`, `Location`, etc.).
- 🎯 **Deterministic Anomaly Detection (Zero AI Bias)**: Evaluates $100\%$ reproducible rule-based algorithms (`SEVERITY_SPIKE`, `REQUEST_BURST` via two-pointer sliding window $O(N \log N)$, `OFF_HOURS_SENSITIVE_ACCESS`, `RARE_EVENT_TYPE`).
- 🤖 **Gemini 3.6 Flash Explainability**: Translates raw detection signals into plain-English root causes and actionable remediation steps.
- ⚡ **Single-Request Batching & Rate-Limit Backoff**: Packs multiple anomalies into a single API request, eliminating HTTP `429 RESOURCE_EXHAUSTED` rate limit errors.
- 🎨 **Glassmorphic Single-Page Web Dashboard**: Built with Vanilla HTML5, CSS3, and JavaScript featuring deep dark aesthetics (`#0b0f19`), real-time search & status filtering, status badges, metrics cards, and modal inspection drawers.
- ⚡ **Unified FastAPI Server**: FastAPI serves both REST API endpoints and the static HTML/CSS/JS frontend on a single unified port.
- 💾 **SQLite DB Caching**: Caches generated AI explanations persistently so reloading details requires zero API calls.
- 🛡️ **Graceful Degradation**: Retains system stability and displays friendly user warnings if the Gemini API key is missing or rate limited.

---

## 📐 System Architecture

```mermaid
flowchart TD
    subgraph Ingestion Layer
        A[Custom Log CSV File\nlogs.csv / user_upload.csv] --> B[Adaptive Header Resolver\nbackend/ingester.py]
    end

    subgraph Data & Validation Layer
        B -->|Valid & Rejected Logs| C[(SQLite Database\nsmart_logs.db)]
        B -->|Summary Log| H[IngestionSummary Table]
    end

    subgraph Detection & AI Core
        C --> D[Sliding Window Anomaly Detector\nbackend/detector.py]
        D -->|Write Flagged Entries| C
        C --> E[Gemini 3.6 Flash Explainer\nbackend/explainer.py]
        E -->|Cache AI Explanations & Root Causes| C
    end

    subgraph Unified Application Server
        F[FastAPI Server\nbackend/main.py] <-->|JSON REST API| C
        F -->|Static Files Mount| G[Glassmorphic HTML5/CSS3/JS Web App\nfrontend/index.html]
    end
```

---

## 📥 Adaptive CSV Ingestion Engine

The ingestion module (`backend/ingester.py`) normalizes diverse column names and converts HTTP status codes to system severities automatically.

### Header Synonym Mapping Matrix

| Domain Field | Supported Column Header Synonyms |
| :--- | :--- |
| **Timestamp** | `timestamp`, `datetime`, `time`, `date`, `created_at`, `log_time`, `ts` |
| **Source IP / Host** | `source`, `ip_address`, `ip`, `host`, `client_ip`, `source_ip`, `src`, `hostname`, `user_ip`, `origin` |
| **Event Type / Action**| `event_type`, `request_type`, `action`, `event`, `method`, `path`, `uri`, `command`, `operation`, `type` |
| **Severity / Status** | `severity`, `status_code`, `status`, `level`, `log_level`, `error_level`, `priority` |
| **Raw Message** | `raw_message`, `message`, `user_agent`, `details`, `description`, `log`, `msg` |

### HTTP Status Code Transformation Logic
- `500`, `502`, `503`, `504`, `FATAL`, `CRITICAL` $\rightarrow$ **`CRITICAL`**
- `400`, `401`, `403`, `404`, `ERROR`, `WARNING` $\rightarrow$ **`WARNING` / `ERROR`**
- `200`, `201`, `204`, `301`, `302`, `INFO`, `DEBUG` $\rightarrow$ **`INFO`**

---

## 🎯 Anomaly Detector Rules & Logic

Rule execution (`backend/detector.py`) is decoupled from AI generation to ensure strict determinism.

| Detector Rule | Score | Condition & Mathematical Rule | Operational Significance |
| :--- | :---: | :--- | :--- |
| **`SEVERITY_SPIKE`** | `1.0` | Log severity is in `{"CRITICAL", "FATAL", "ERROR"}` (including HTTP `500`). | Identifies server crashes, memory exhaustion, database connection pool depletion, and critical hardware failures. |
| **`REQUEST_BURST`** | `0.9` | Single source IP/Host issues $\ge 10$ requests within a rolling **60-second window** ($O(N \log N)$ two-pointer algorithm). | Detects denial-of-service (DoS) attempts, web scrapers, infinite application loops, and high-frequency script bugs. |
| **`OFF_HOURS_SENSITIVE_ACCESS`**| `0.85` | Sensitive actions (`SENSITIVE_DATA_EXPORT`, `CONFIGURATION_WRITE`, `SYSTEM_OVERRIDE`, `ENCRYPTION_KEY_DESTROYED`, `DELETE`, `DROP`) performed between **10 PM and 5 AM**. | Flags credential abuse, data exfiltration, or out-of-schedule administrative destructions. |
| **`RARE_EVENT_TYPE`** | `0.75` | Event type occurrence frequency is $< 2\%$ of the total valid records loaded. | Highlights rarely executed system commands or obscure endpoints requiring manual security auditing. |

---

## 🤖 Gemini AI Root-Cause Explainer

The explainability engine (`backend/explainer.py`) utilizes the official **Google GenAI SDK** (`google-genai`) with **`gemini-3.6-flash`**.

- **Single-Request Batching**: `/analyze-all-anomalies` packs multiple flagged entries into a single structured JSON prompt, requesting AI analysis for the entire batch in **1 single API call**.
- **Exponential Backoff**: Single-entry requests include automated retry loops (`time.sleep(2.0 * attempt)`) to handle rate limit spikes cleanly.
- **Persistent DB Caching**: AI explanations (`ai_explanation`) and remediation steps (`ai_root_cause`) are saved directly in `FlaggedEntry` records in SQLite.
- **Dynamic `.env` Reloading**: Calls `load_dotenv(override=True)` before making API requests so changes to `GEMINI_API_KEY` take effect instantly without restarting the server.

---

## 🔌 REST API Endpoint Reference

FastAPI runs on `http://localhost:8000` (`backend/main.py`).

| Method | Endpoint | Request Payload / Params | Description |
| :---: | :--- | :--- | :--- |
| `GET` | `/` | None | Serves the HTML5/CSS3/JS Web Application Dashboard. |
| `POST` | `/ingest` | `file`: CSV file multipart/form-data | Ingests a custom CSV, runs validation, and triggers rule detection. |
| `POST` | `/ingest-default` | None | Loads pre-synthesized `data/logs.csv` directly from storage. |
| `GET` | `/logs` | None | Retrieves all log entries (valid and invalid) sorted by timestamp. |
| `GET` | `/flagged` | None | Retrieves all flagged anomalies sorted by anomaly score. |
| `GET` | `/flagged/{id}` | `id`: Integer (Flagged Entry ID) | Retrieves anomaly details and triggers Gemini AI explanation if un-cached. |
| `POST` | `/analyze-all-anomalies`| None | Runs single-request batch Gemini AI analysis on all unanalyzed anomalies. |
| `GET` | `/summaries` | None | Returns ingestion summary logs (loaded vs rejected counts). |
| `POST` | `/clear` | None | Wipes all database tables for a clean restart test case. |

---

## 🖥️ Glassmorphic Web Dashboard

Built with HTML5, CSS3, and Vanilla JavaScript (`frontend/`).

1. **Header & Status Badge**: Displays real-time "System Operational" status indicator and application title.
2. **Action Toolbar**: Custom file drag-and-drop CSV upload, "Load Default logs.csv", "Batch AI Analyze Anomalies", and "Clear Database" buttons.
3. **Metrics Grid**: 4 glowing cards displaying Total Logs Processed, Valid Log Entries, Malformed/Rejected Rows, and Flagged Anomalies.
4. **Search & Filter Controls**: Real-time text search (searches log messages, IP sources, and event types) combined with interactive status filter chips (`All Logs`, `🚨 Anomalies Only`, `✅ Normal Logs`, `❌ Malformed Logs`).
5. **Timeline Data Table**: Glassmorphic table displaying log records with status badges (`🚨 ANOMALY`, `✅ NORMAL`, `❌ INVALID`), detector rules, inline reasons, and "Inspect AI" triggers.
6. **Modal Inspection Drawer**: Click any anomaly's "Inspect AI" button to reveal Event Metadata, Triggered Rules, Anomaly Scores, Gemini AI Plain-English Explanations, and Root Cause & Action Steps.

---

## 🚀 Quick Start & Step-by-Step Setup Guide

Follow these steps to run the website locally:

### Step 1: Clone Repository & Install Dependencies

```bash
# Clone repository
git clone https://github.com/prajna0605/Smart_Log_Analyzer.git
cd Smart_Log_Analyzer

# Install required Python dependencies
pip install -r requirements.txt
```

### Step 2: Configure Gemini API Key

Set your Gemini API Key in your terminal or `.env` file:

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="your-gemini-api-key-here"
```

**Linux / macOS:**
```bash
export GEMINI_API_KEY="your-gemini-api-key-here"
```

Or create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your-gemini-api-key-here
```

### Step 3: Generate Initial Synthetic Log Dataset (Optional)

Generate `data/logs.csv` (contains 200 normal logs, 20 deliberate anomalies, and 3 malformed validation test rows):
```bash
python backend/synthesizer.py
```

### Step 4: Run the Web Server

Start the unified FastAPI server:

```bash
python -m uvicorn backend.main:app --port 8000 --reload
```

*Or run via startup script:*
```bash
# Linux / macOS / Bash:
bash start.sh
```

### Step 5: Open in Browser

Open your web browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🧪 Automated Unit Testing

Run the automated backend test suite using `pytest`:

```bash
python -m pytest backend/tests/
```

**Expected Test Output:**
```text
backend\tests\test_backend.py ....                                       [100%]
============================== 4 passed in 1.39s ==============================
```

---

## 📁 Project Folder Structure

```text
HACKATHON/
├── backend/
│   ├── database.py       # SQLAlchemy engine & SQLite session configuration
│   ├── detector.py       # Rule-based anomaly detection engine (O(N log N) sliding window)
│   ├── explainer.py      # Gemini 3.6 Flash AI integration & single-request batching
│   ├── ingester.py       # Adaptive CSV parser & synonym column normalizer
│   ├── main.py           # FastAPI REST API routes & static frontend mount
│   ├── models.py         # SQLAlchemy ORM database models
│   ├── schemas.py        # Pydantic v2 schemas for API requests/responses
│   ├── synthesizer.py    # Synthetic dataset generator script
│   └── tests/
│       └── test_backend.py # Automated pytest test suite
├── data/
│   └── logs.csv          # Pre-generated synthetic log dataset
├── frontend/
│   ├── index.html        # Single-page web dashboard HTML markup
│   ├── style.css         # Glassmorphic dark mode CSS design system
│   └── app.js            # Client-side JavaScript REST API integration & UI engine
├── .env                  # Environment configuration file (GEMINI_API_KEY)
├── start.sh              # Production / cloud startup script
├── CHECKLIST.MD          # Grading checklist & verification benchmarks
├── README.md             # Project documentation & GitHub guide
└── smart_logs.db         # Persistent SQLite database file
```

---

## 💡 Design Rationale & Trade-offs

- **Why Unified HTML/CSS/JS Served by FastAPI?**
  Replacing dual-server frameworks (Streamlit + FastAPI) with a single FastAPI server hosting static HTML/CSS/JS eliminates multi-process port overhead, reduces container build footprint, speeds up page loading, and allows custom glassmorphic UI design.
- **Why Rule-Based Detection Over Pure AI Detection?**
  Using LLMs directly for anomaly classification introduces non-deterministic outputs, API latency, high costs, and hallucination risks. Decoupling detection (rule engine) from explanation (LLM) guarantees $100\%$ deterministic flagging while leveraging Gemini's strengths in plain-English translation and root-cause reasoning.
- **Why Single-Request Batching for AI Analysis?**
  Free-tier Gemini API keys enforce a limit of **15 Requests Per Minute (RPM)**. Generating explanations sequentially for 20 anomalies triggers HTTP `429 RESOURCE_EXHAUSTED` rate limits. Sending 1 single JSON batch prompt achieves full AI analysis in a single request (~2 seconds total).
