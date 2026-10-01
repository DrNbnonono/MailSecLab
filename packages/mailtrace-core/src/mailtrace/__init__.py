"""MailTrace: offline email header analysis."""
from .engine import analyze
from .models.report import AnalysisOptions, MailReport

__all__ = ["analyze", "AnalysisOptions", "MailReport"]
