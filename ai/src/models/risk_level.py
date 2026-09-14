"""
risk_level.py

Defines the available AI risk levels.
"""

from enum import Enum


class RiskLevel(Enum):
    """
    Represents the overall login risk.
    """

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

    def __str__(self) -> str:
        return self.value