"""All rules. Importing the cloud modules registers their rules."""

from . import aws, azure  # noqa: F401
from .base import RULES, SEVERITIES, Rule

__all__ = ["RULES", "SEVERITIES", "Rule"]
