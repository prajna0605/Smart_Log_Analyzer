# ruff: noqa: B008, BLE001
import os
import shutil

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .detector import run_anomaly_detector
from .explainer import explain_all_flagged_entries, explain_flagged_entry
from .ingester import ingest_csv_logs
from .models import FlaggedEntry, IngestionSummary, LogEntry
from .schemas import FlaggedEntryResponse, IngestionSummaryResponse, LogEntryResponse

from fastapi.staticfiles import StaticFiles

# Load environment variables from .env file
load_dotenv()

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Smart Log Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/ingest", response_model=IngestionSummaryResponse)
def ingest_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Uploads and ingests a log CSV file, triggering validation and rule-based anomaly detection."""
    # Ensure temporary directory exists and sanitize filename
    temp_dir = "temp"
    os.makedirs(temp_dir, exist_ok=True)
    safe_filename = os.path.basename(file.filename or "uploaded.csv")
    temp_file_path = os.path.join(temp_dir, safe_filename)
    
    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # Ingest records
        summary = ingest_csv_logs(temp_file_path, safe_filename, db)
        # Run anomaly detection on newly ingested records
        run_anomaly_detector(db)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@app.post("/ingest-default", response_model=IngestionSummaryResponse)
def ingest_default(db: Session = Depends(get_db)):
    """Loads the pre-synthesized data/logs.csv directly from server storage."""
    default_csv = "data/logs.csv"
    if not os.path.exists(default_csv):
        raise HTTPException(status_code=404, detail="Default logs.csv not found. Run synthesizer first.")
    
    try:
        summary = ingest_csv_logs(default_csv, "logs.csv", db)
        run_anomaly_detector(db)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs", response_model=list[LogEntryResponse])
def get_logs(db: Session = Depends(get_db)):
    """Retrieves all log entries (valid and invalid) sorted by ID/Timestamp."""
    return db.query(LogEntry).order_by(LogEntry.timestamp.asc()).all()

@app.get("/flagged", response_model=list[FlaggedEntryResponse])
def get_flagged(db: Session = Depends(get_db)):
    """Retrieves all flagged anomalies."""
    return db.query(FlaggedEntry).order_by(FlaggedEntry.score.desc()).all()

@app.post("/analyze-all-anomalies", response_model=list[FlaggedEntryResponse])
def analyze_all_anomalies(db: Session = Depends(get_db)):
    """Triggers batch Gemini AI explanation for all unanalyzed flagged anomalies in 1 single API call."""
    return explain_all_flagged_entries(db)

@app.get("/flagged/{flagged_id}", response_model=FlaggedEntryResponse)
def get_flagged_detail(flagged_id: int, db: Session = Depends(get_db)):
    """Retrieves the details of a specific flagged anomaly, including triggering rule and Gemini explanation."""
    flagged = db.query(FlaggedEntry).filter(FlaggedEntry.id == flagged_id).first()
    if not flagged:
        raise HTTPException(status_code=404, detail="Flagged entry not found")
    
    # Generate/fetch Gemini explanations
    explain_flagged_entry(flagged_id, db)
    
    # Reload from DB to return complete model with explanations
    return db.query(FlaggedEntry).filter(FlaggedEntry.id == flagged_id).first()

@app.get("/summaries", response_model=list[IngestionSummaryResponse])
def get_summaries(db: Session = Depends(get_db)):
    """Retrieves standard ingestion summaries showing validated vs rejected lines."""
    return db.query(IngestionSummary).order_by(IngestionSummary.created_at.desc()).all()

@app.post("/clear")
def clear_database(db: Session = Depends(get_db)):
    """Utility endpoint to wipe tables for a clean restart test case."""
    db.query(FlaggedEntry).delete()
    db.query(LogEntry).delete()
    db.query(IngestionSummary).delete()
    db.commit()
    return {"message": "Database wiped successfully"}

# Mount frontend static files (HTML/CSS/JS) at root
if os.path.exists("frontend"):
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

