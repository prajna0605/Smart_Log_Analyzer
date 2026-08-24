import json
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types
from sqlalchemy.orm import Session

from .models import FlaggedEntry


def explain_flagged_entry(flagged_id: int, db: Session) -> FlaggedEntry:
    """
    Calls Gemini API to explain a single flagged log entry.
    Retries up to 3 times with backoff if rate limits are hit.
    Caches the results directly in the database.
    """
    flagged = db.query(FlaggedEntry).filter(FlaggedEntry.id == flagged_id).first()
    if not flagged:
        return None

    # If already cached with a valid explanation, return immediately
    if (
        flagged.ai_explanation
        and flagged.ai_root_cause
        and not flagged.ai_explanation.startswith("explanation unavailable")
    ):
        return flagged

    log_entry = flagged.log_entry
    if not log_entry:
        flagged.ai_explanation = "explanation unavailable"
        flagged.ai_root_cause = "explanation unavailable"
        db.commit()
        return flagged

    # Dynamically reload environment variables from .env
    load_dotenv(override=True)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        flagged.ai_explanation = "explanation unavailable (Gemini API key missing)"
        flagged.ai_root_cause = "explanation unavailable"
        db.commit()
        return flagged

    prompt = f"""
    You are an expert security and systems operational analyst assistant.
    Analyze this flagged anomaly and explain it in plain, simple English.

    Log Entry Details:
    - Timestamp: {log_entry.timestamp}
    - Source: {log_entry.source}
    - Event Type: {log_entry.event_type}
    - Severity: {log_entry.severity}
    - Raw Message: {log_entry.raw_message}

    Anomaly Flag Details:
    - Detector Rule triggered: {flagged.detector_rule}
    - Score/Weight: {flagged.score}
    - Detection Reason: {flagged.reason}

    Provide your response in JSON format matching the following schema structure:
    {{
        "explanation": "A 2-3 sentence plain-English explanation of what this log entry means and why it represents an anomaly.",
        "root_cause_and_next_steps": "A brief explanation of the likely root cause and concrete next steps or troubleshooting actions to resolve it."
    }}
    Do not include any formatting markdown like ```json. Return ONLY raw JSON.
    """

    client = genai.Client(api_key=api_key)

    # Retry up to 3 times for rate limits
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json"),
            )

            raw_text = response.text.strip()
            if raw_text.startswith("```"):
                lines = raw_text.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw_text = "\n".join(lines).strip()

            data = json.loads(raw_text)
            flagged.ai_explanation = data.get("explanation", "explanation unavailable").strip()
            flagged.ai_root_cause = data.get("root_cause_and_next_steps", "explanation unavailable").strip()
            db.commit()
            db.refresh(flagged)
            return flagged
        except Exception as e:  # noqa: BLE001
            err_str = str(e)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "quota" in err_str:
                if attempt < 2:
                    time.sleep(2.0 * (attempt + 1))  # Exponential backoff
                    continue
                flagged.ai_explanation = "explanation unavailable (Gemini API rate limit exceeded - please retry shortly)"
                flagged.ai_root_cause = "explanation unavailable (Rate limit reached)"
            else:
                flagged.ai_explanation = "explanation unavailable"
                flagged.ai_root_cause = f"explanation unavailable (Error details: {err_str[:100]})"
            break

    db.commit()
    db.refresh(flagged)
    return flagged


def explain_all_flagged_entries(db: Session) -> list[FlaggedEntry]:
    """
    Executes a SINGLE BATCH Gemini API request for all unanalyzed flagged entries.
    Prevents 429 Rate Limit errors by using 1 single API call instead of N calls.
    """
    all_flagged = db.query(FlaggedEntry).all()
    unanalyzed = [
        f for f in all_flagged
        if not f.ai_explanation or f.ai_explanation.startswith("explanation unavailable")
    ]

    if not unanalyzed:
        return db.query(FlaggedEntry).order_by(FlaggedEntry.score.desc()).all()

    # Dynamically reload environment variables from .env
    load_dotenv(override=True)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        for f in unanalyzed:
            f.ai_explanation = "explanation unavailable (Gemini API key missing)"
            f.ai_root_cause = "explanation unavailable"
        db.commit()
        return db.query(FlaggedEntry).order_by(FlaggedEntry.score.desc()).all()

    # Process in batches of 15 to stay within token context comfortably
    batch_size = 15
    client = genai.Client(api_key=api_key)

    for i in range(0, len(unanalyzed), batch_size):
        batch = unanalyzed[i : i + batch_size]
        items_payload = []
        for entry in batch:
            log = entry.log_entry
            items_payload.append({
                "id": entry.id,
                "timestamp": str(log.timestamp) if log else "N/A",
                "source": log.source if log else "N/A",
                "event_type": log.event_type if log else "N/A",
                "severity": log.severity if log else "N/A",
                "raw_message": log.raw_message if log else "N/A",
                "detector_rule": entry.detector_rule,
                "detection_reason": entry.reason,
            })

        prompt = f"""
        You are an expert security and systems operational analyst assistant.
        Analyze the following batch of flagged log anomalies and provide plain-English explanations and root causes for each.

        Flagged Anomalies JSON list:
        {json.dumps(items_payload, indent=2)}

        Return a JSON array where each object has:
        - "id": integer matching the entry ID
        - "explanation": "2-3 sentence plain-English explanation of why this log is an anomaly."
        - "root_cause_and_next_steps": "Likely root cause and concrete next steps/actions to resolve."

        Return ONLY the raw JSON array.
        """

        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model="gemini-3.6-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(response_mime_type="application/json"),
                )

                raw_text = response.text.strip()
                if raw_text.startswith("```"):
                    lines = raw_text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    raw_text = "\n".join(lines).strip()

                results = json.loads(raw_text)
                if isinstance(results, list):
                    res_map = {r.get("id"): r for r in results if isinstance(r, dict)}
                    for entry in batch:
                        if entry.id in res_map:
                            entry.ai_explanation = res_map[entry.id].get("explanation", "explanation unavailable").strip()
                            entry.ai_root_cause = res_map[entry.id].get("root_cause_and_next_steps", "explanation unavailable").strip()
                    db.commit()
                break
            except Exception as e:  # noqa: BLE001
                err_str = str(e)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "quota" in err_str:
                    if attempt < 2:
                        time.sleep(3.0 * (attempt + 1))
                        continue
                    for entry in batch:
                        entry.ai_explanation = "explanation unavailable (Gemini API rate limit exceeded - please retry shortly)"
                        entry.ai_root_cause = "explanation unavailable (Rate limit reached)"
                    db.commit()
                else:
                    for entry in batch:
                        entry.ai_explanation = "explanation unavailable"
                        entry.ai_root_cause = f"explanation unavailable (Error details: {err_str[:100]})"
                    db.commit()
                break

    return db.query(FlaggedEntry).order_by(FlaggedEntry.score.desc()).all()

