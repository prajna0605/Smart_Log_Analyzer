import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    raw_message = Column(Text, nullable=True)
    is_valid = Column(Boolean, default=True)
    validation_error = Column(String, nullable=True)

    flagged_entries = relationship("FlaggedEntry", back_populates="log_entry", cascade="all, delete-orphan")


class FlaggedEntry(Base):
    __tablename__ = "flagged_entries"

    id = Column(Integer, primary_key=True, index=True)
    log_entry_id = Column(Integer, ForeignKey("log_entries.id", ondelete="CASCADE"), nullable=False)
    score = Column(Float, nullable=False)
    reason = Column(String, nullable=False)
    detector_rule = Column(String, nullable=False)
    ai_explanation = Column(Text, nullable=True)
    ai_root_cause = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))

    log_entry = relationship("LogEntry", back_populates="flagged_entries")


class IngestionSummary(Base):
    __tablename__ = "ingestion_summaries"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    total_rows = Column(Integer, default=0)
    loaded_rows = Column(Integer, default=0)
    rejected_rows = Column(Integer, default=0)
    rejected_details = Column(Text, nullable=True)  # JSON or newline-separated error details
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))

