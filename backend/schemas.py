from datetime import datetime

from pydantic import BaseModel


class LogEntryBase(BaseModel):
    timestamp: datetime
    source: str
    event_type: str | None = None
    severity: str | None = None
    raw_message: str | None = None

class LogEntryCreate(LogEntryBase):
    pass

class LogEntryResponse(LogEntryBase):
    id: int
    is_valid: bool
    validation_error: str | None = None

    class Config:
        from_attributes = True

class FlaggedEntryBase(BaseModel):
    score: float
    reason: str
    detector_rule: str
    ai_explanation: str | None = None
    ai_root_cause: str | None = None

class FlaggedEntryResponse(FlaggedEntryBase):
    id: int
    log_entry_id: int
    created_at: datetime
    log_entry: LogEntryResponse | None = None

    class Config:
        from_attributes = True

class IngestionSummaryResponse(BaseModel):
    id: int
    filename: str
    total_rows: int
    loaded_rows: int
    rejected_rows: int
    rejected_details: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True
