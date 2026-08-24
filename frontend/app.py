
import json

import pandas as pd
import requests
import streamlit as st

# Streamlit Config
st.set_page_config(
    page_title="Smart Log Analyzer & Anomaly Detector",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium styling via CSS
st.markdown("""
<style>
    /* Main body background and modern typography */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@300;500;700&display=swap');
    
    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Outfit', sans-serif;
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Headers styling */
    h1, h2, h3 {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        background: linear-gradient(135deg, #6366f1 0%, #a855f7 50%, #ec4899 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Metrics blocks */
    div[data-testid="metric-container"] {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 15px 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    div[data-testid="metric-container"]:hover {
        transform: translateY(-2px);
        border-color: #6366f1;
    }
    
    /* Subtitle or text fields colors */
    label[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-weight: 600;
    }
    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-weight: 800;
    }

    /* Highlight table anomalies */
    .anomaly-row {
        background-color: rgba(239, 68, 68, 0.15);
        border-left: 5px solid #ef4444 !important;
    }
    
    /* Custom buttons */
    .stButton>button {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 14px 0 rgba(79, 70, 229, 0.4);
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        transform: scale(1.02);
        box-shadow: 0 6px 20px 0 rgba(99, 102, 241, 0.6);
    }
</style>
""", unsafe_allow_html=True)

# Configuration backend URL
API_URL = "http://127.0.0.1:8000"

st.title("🛡️ Smart Log Analyzer & Anomaly Detector")
st.markdown("Automated log parsing, rule-based anomaly detection, and intelligent Gemini root-cause insights.")

# Sidebar - Controls & Ingestion
st.sidebar.header("📥 Ingestion & Controls")

uploaded_file = st.sidebar.file_uploader("Upload log CSV file", type=["csv"])

if st.sidebar.button("⚙️ Load Default logs.csv"):
    try:
        res = requests.post(f"{API_URL}/ingest-default")
        if res.status_code == 200:
            st.sidebar.success("Successfully loaded and processed default logs!")
            st.rerun()
        else:
            st.sidebar.error(f"Failed to load: {res.json().get('detail')}")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Backend Server offline: {e}")

if uploaded_file is not None and st.sidebar.button("🚀 Process Uploaded File"):
    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/csv")}
    try:
        res = requests.post(f"{API_URL}/ingest", files=files)
        if res.status_code == 200:
            st.sidebar.success("File processed and anomalies flagged successfully!")
            st.rerun()
        else:
            st.sidebar.error(f"Processing failed: {res.json().get('detail')}")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Error connecting to backend: {e}")

if st.sidebar.button("🤖 Batch AI Analyze Anomalies"):
    try:
        res = requests.post(f"{API_URL}/analyze-all-anomalies")
        if res.status_code == 200:
            st.sidebar.success("Generated Gemini AI analysis for all anomalies!")
            st.rerun()
        else:
            st.sidebar.error(f"Analysis failed: {res.json().get('detail')}")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Error connecting to backend: {e}")

if st.sidebar.button("🗑️ Clear Database"):
    try:
        res = requests.post(f"{API_URL}/clear")
        if res.status_code == 200:
            st.sidebar.warning("Database cleared!")
            st.rerun()
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Error clearing: {e}")

# Fetch Current State
try:
    logs_res = requests.get(f"{API_URL}/logs")
    flagged_res = requests.get(f"{API_URL}/flagged")
    summaries_res = requests.get(f"{API_URL}/summaries")
    
    logs = logs_res.json() if logs_res.status_code == 200 else []
    flagged = flagged_res.json() if flagged_res.status_code == 200 else []
    summaries = summaries_res.json() if summaries_res.status_code == 200 else []
except requests.exceptions.RequestException:
    st.error("🔌 Unable to connect to the backend server. Please make sure the FastAPI server is running on localhost:8000.")
    st.stop()

# Helper logic to map flagged entry states
flagged_log_ids = {f["log_entry_id"]: f for f in flagged}

# Main metrics
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Logs Processed", len(logs))
with col2:
    valid_count = sum(1 for l in logs if l["is_valid"])
    st.metric("Valid Log Entries", valid_count)
with col3:
    invalid_count = sum(1 for l in logs if not l["is_valid"])
    st.metric("Malformed / Rejected", invalid_count)
with col4:
    st.metric("Flagged Anomalies", len(flagged))

# Display Ingestion Validation Summary details if any exist
if summaries:
    st.subheader("📊 Ingestion & Validation Summary")
    latest_summary = summaries[0]
    st.info(
        f"Latest Ingestion File: **{latest_summary['filename']}** at {str(latest_summary['created_at'])[:19]} | "
        f"Total: **{latest_summary['total_rows']}** rows, "
        f"Loaded: **{latest_summary['loaded_rows']}**, "
        f"Rejected: **{latest_summary['rejected_rows']}**."
    )
    if latest_summary['rejected_rows'] > 0:
        with st.expander("🔍 View Ingestion Error/Rejection Log"):
            try:
                rej_data = json.loads(latest_summary['rejected_details'])
                st.dataframe(pd.DataFrame(rej_data))
            except (json.JSONDecodeError, TypeError, ValueError):
                st.code(latest_summary['rejected_details'])

if not logs:
    st.warning("⚠️ No logs ingested yet. Please upload a CSV file or load the default logs.csv via the sidebar controls.")
    st.stop()

# Build timeline/list data frame
logs_data = []
for entry in logs:
    log_id = entry["id"]
    is_anomaly = log_id in flagged_log_ids
    rule = flagged_log_ids[log_id]["detector_rule"] if is_anomaly else "NORMAL"
    score = flagged_log_ids[log_id]["score"] if is_anomaly else 0.0
    reason = flagged_log_ids[log_id]["reason"] if is_anomaly else "N/A"
    ai_exp = (flagged_log_ids[log_id].get("ai_explanation") or "Pending AI Analysis") if is_anomaly else "N/A"
    
    logs_data.append({
        "ID": log_id,
        "Timestamp": entry["timestamp"],
        "Source": entry["source"],
        "Event Type": entry["event_type"] or "N/A",
        "Severity": entry["severity"] or "N/A",
        "Status": "🚨 ANOMALY" if is_anomaly else "✅ NORMAL" if entry["is_valid"] else "❌ INVALID",
        "Detector Rule": rule,
        "Anomaly Reason": reason,
        "AI Explanation": ai_exp,
        "Score": score,
        "Message": entry["raw_message"] or "N/A",
        "Is Valid": entry["is_valid"],
        "Validation Error": entry["validation_error"] or ""
    })

df = pd.DataFrame(logs_data)

# Sidebar Filter Options
st.sidebar.header("🔍 Filters")
filter_status = st.sidebar.multiselect(
    "Status Filter",
    options=["🚨 ANOMALY", "✅ NORMAL", "❌ INVALID"],
    default=["🚨 ANOMALY", "✅ NORMAL", "❌ INVALID"]
)

# Apply filters
df_filtered = df[df["Status"].isin(filter_status)]

# Main Dataset View (Full Width)
st.subheader("📋 Logs Dataset Timeline & AI Anomaly Detection")
st.markdown("*Filter logs using the sidebar or select any flagged anomaly below to inspect AI explanations and root causes.*")

st.dataframe(
    df_filtered[["ID", "Timestamp", "Source", "Event Type", "Severity", "Status", "Detector Rule", "Anomaly Reason", "AI Explanation", "Score"]],
    use_container_width=True,
    hide_index=True
)

st.markdown("---")

# Dedicated AI Analyzer Section for All Anomalies
st.subheader("🤖 AI Analyzer Summary for All Anomalies")

anomaly_options = df[df["Status"] == "🚨 ANOMALY"]
if not anomaly_options.empty:
    with st.expander("📊 View AI Analysis & Root Causes Table (All Flagged Anomalies)", expanded=True):
        st.markdown("Below is the AI-generated diagnosis and root-cause analysis for all flagged anomalies in the dataset:")
        
        # Build summary table of all flagged entries with AI explanation & root cause
        analyzer_rows = []
        for f in flagged:
            l_entry = next((item for item in logs if item["id"] == f["log_entry_id"]), {})
            analyzer_rows.append({
                "Log ID": f["log_entry_id"],
                "Rule": f["detector_rule"],
                "Score": f["score"],
                "Source": l_entry.get("source", "N/A"),
                "Event Type": l_entry.get("event_type", "N/A"),
                "Severity": l_entry.get("severity", "N/A"),
                "Detector Reason": f["reason"],
                "AI Explanation": f.get("ai_explanation") or "Click '🤖 Batch AI Analyze Anomalies' in sidebar to generate",
                "Root Cause & Next Steps": f.get("ai_root_cause") or "Click '🤖 Batch AI Analyze Anomalies' in sidebar to generate"
            })
            
        analyzer_df = pd.DataFrame(analyzer_rows)
        st.dataframe(analyzer_df, use_container_width=True, hide_index=True)

anomaly_options = df[df["Status"] == "🚨 ANOMALY"]
if not anomaly_options.empty:
    selected_id = st.selectbox(
        "Select a flagged anomaly from the dropdown to reveal detailed AI insights:",
        options=[None] + anomaly_options["ID"].tolist(),
        format_func=lambda x: "Choose an anomaly to inspect..." if x is None else f"🚨 Anomaly Log ID: {x} | Rule: {anomaly_options[anomaly_options['ID'] == x]['Detector Rule'].values[0]}"
    )
    
    if selected_id:
        flagged_meta = flagged_log_ids[selected_id]
        
        with st.spinner("Retrieving Gemini AI root-cause analysis..."):
            try:
                detail_res = requests.get(f"{API_URL}/flagged/{flagged_meta['id']}")
                if detail_res.status_code == 200:
                    flag_detail = detail_res.json()
                else:
                    flag_detail = flagged_meta
            except requests.exceptions.RequestException:
                flag_detail = flagged_meta

        log_row = df[df["ID"] == selected_id].iloc[0]
        
        with st.expander(f"📌 Detailed Inspection for Anomaly Log ID #{selected_id} ({log_row['Detector Rule']})", expanded=True):
            det_col1, det_col2 = st.columns([1, 1])
            
            with det_col1:
                st.markdown("#### 📝 Event Metadata")
                meta_df = pd.DataFrame([
                    {"Field": "Timestamp", "Value": log_row["Timestamp"]},
                    {"Field": "Source", "Value": log_row["Source"]},
                    {"Field": "Event Type", "Value": log_row["Event Type"]},
                    {"Field": "Severity", "Value": log_row["Severity"]},
                    {"Field": "Raw Message", "Value": log_row["Message"]},
                    {"Field": "Triggered Rule", "Value": f"🔴 {log_row['Detector Rule']}"},
                    {"Field": "Confidence/Weight Score", "Value": log_row["Score"]},
                    {"Field": "Detector Reason", "Value": flag_detail["reason"]}
                ])
                st.table(meta_df)
                
            with det_col2:
                st.markdown("#### 🤖 Gemini AI Plain-English Explanation")
                explanation = flag_detail.get("ai_explanation") or "No explanation generated."
                st.info(explanation)
                
                st.markdown("#### 💡 Root Cause & Next Action Steps")
                root_cause = flag_detail.get("ai_root_cause") or "Root cause not generated."
                st.success(root_cause)
else:
    st.info("No flagged anomalies to display. Select '🚨 ANOMALY' in filters or load data with anomalies.")

# Malformed Log Ingestion Errors Section
invalid_options = df[df["Status"] == "❌ INVALID"]
if not invalid_options.empty:
    with st.expander("❌ Malformed Log Ingestion Errors (Validation Failures)", expanded=False):
        selected_invalid_id = st.selectbox(
            "Select malformed entry to view error details:",
            options=invalid_options["ID"].tolist()
        )
        if selected_invalid_id:
            invalid_row = df[df["ID"] == selected_invalid_id].iloc[0]
            st.error(f"Row validation failed: **{invalid_row['Validation Error']}**")
            st.code(f"Source: {invalid_row['Source']}\nMessage: {invalid_row['Message']}\nTimestamp: {invalid_row['Timestamp']}")
