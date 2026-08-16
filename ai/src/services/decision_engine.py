"""
decision_engine.py

Combines the outputs of the Rule-Based Risk Calculator
and the Machine Learning Predictor to produce a final
authentication decision.
"""

from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction
from models.risk_result import RiskResult


class DecisionEngine:
    """
    Combines multiple security assessments into one final decision.
    """

    def evaluate(
        self,
        rule_result: RiskResult,
        ai_result: RiskResult,
    ) -> RiskResult:
        """
        Determine the final authentication decision.

        Strategy:
        - Use the higher risk score.
        - Use the highest risk level.
        - Use the strongest recommended action.
        - Combine both reasons.
        """

        # --------------------------------------------------
        # Final Risk Score
        # --------------------------------------------------

        final_score = max(
            rule_result.risk_score,
            ai_result.risk_score,
        )

        # --------------------------------------------------
        # Final Risk Level
        # --------------------------------------------------

        risk_priority = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
        }

        if (
            risk_priority[rule_result.risk_level]
            >= risk_priority[ai_result.risk_level]
        ):
            final_level = rule_result.risk_level
        else:
            final_level = ai_result.risk_level

        # --------------------------------------------------
        # Final Recommended Action
        # --------------------------------------------------

        action_priority = {
            RecommendedAction.ALLOW_LOGIN: 1,
            RecommendedAction.REQUIRE_EMAIL_OTP: 2,
            RecommendedAction.REQUIRE_ADDITIONAL_VERIFICATION: 3,
            RecommendedAction.BLOCK_LOGIN: 4,
        }

        if (
            action_priority[rule_result.recommended_action]
            >= action_priority[ai_result.recommended_action]
        ):
            final_action = rule_result.recommended_action
        else:
            final_action = ai_result.recommended_action

        # --------------------------------------------------
        # Combine Reasons
        # --------------------------------------------------

        reason = (
            "Rule-Based Assessment: "
            f"{rule_result.reason} | "
            "Machine Learning Assessment: "
            f"{ai_result.reason}"
        )

        # --------------------------------------------------
        # Return Final Decision
        # --------------------------------------------------

        return RiskResult(
            risk_score=final_score,
            risk_level=final_level,
            recommended_action=final_action,
            reason=reason,
        )