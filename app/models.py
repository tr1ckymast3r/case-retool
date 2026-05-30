from sqlalchemy import Column, String, Integer, DateTime, Text
from .database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String, primary_key=True)
    filename = Column(String)
    filepath = Column(String)
    file_size = Column(Integer)
    file_type = Column(String, default="Unknown")
    platform = Column(String, default="Unknown")
    md5 = Column(String)
    sha1 = Column(String)
    sha256 = Column(String)
    status = Column(String, default="queued")
    analysis_profile = Column(String, default="quick_scan")
    tech_stack = Column(Text, default="{}")
    architecture = Column(Text, default="{}")
    features = Column(Text, default="{}")
    api_endpoints = Column(Text, default="{}")
    dependencies = Column(Text, default="[]")
    data_models = Column(Text, default="{}")
    network_activity = Column(Text, default="{}")
    decompiled_code = Column(Text, default="{}")
    ai_summary = Column(Text, default="")
    config_values = Column(Text, default="{}")
    worker_results = Column(Text, default="{}")
    created_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
