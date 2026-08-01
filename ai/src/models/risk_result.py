"""
risk_result.py

Represents the final risk assessment returned
by the AI engine.
"""

from dataclasses import dataclass, asdict
import json

from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction


@dataclass(slots=True)
class RiskResult:
    """
    Stores the final AI risk assessment.
    """

    risk_score: int
    risk_level: RiskLevel
    recommended_action: RecommendedAction
    reason: str

    def to_dict(self) -> dict:
        """
        Convert the object to a dictionary.
        """
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "recommended_action": self.recommended_action.value,
            "reason": self.reason,
        }

    def to_json(self) -> str:
        """
        Convert the object to JSON.
        """
        return json.dumps(self.to_dict(), indent=4)

    def __str__(self) -> str:
        """
        Display a readable risk assessment.
        """
        return (
            "\n"
            "========== Risk Assessment ==========\n"
            f"Risk Score         : {self.risk_score}\n"
            f"Risk Level         : {self.risk_level.value}\n"
            f"Recommended Action : {self.recommended_action.value}\n"
            f"Reason             : {self.reason}\n"
        )