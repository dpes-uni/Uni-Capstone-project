"""
decision_engine.py

Combines rule-based login risk, Login ML risk,
and Session ML risk to produce one final
authentication decision.
"""

from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction
from models.risk_result import RiskResult


class DecisionEngine:
    """
    Combines multiple security assessments into
    one final authentication decision.
    """

    def evaluate(
        self,
        rule_result: RiskResult,
        login_ai_result: RiskResult,
        session_ai_result: RiskResult,
    ) -> RiskResult:
        """
        Determine the final authentication decision.

        The final decision considers:

        1. Rule-based login risk
        2. Login Machine Learning risk
        3. Session Machine Learning risk

        The highest risk level and risk score are retained.

        The strongest recommended security action is retained.

        No individual assessment can reduce a higher-risk
        assessment produced by another component.
        """

        # --------------------------------------------------
        # Risk Level Priority
        # --------------------------------------------------

        risk_priority = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
        }

        assessments = [
            rule_result,
            login_ai_result,
            session_ai_result,
        ]

        # --------------------------------------------------
        # Final Risk Score
        # --------------------------------------------------

        final_score = max(
            result.risk_score
            for result in assessments
        )

        # --------------------------------------------------
        # Final Risk Level
        # --------------------------------------------------

        final_result = max(
            assessments,
            key=lambda result: risk_priority[
                result.risk_level
            ],
        )

        final_level = final_result.risk_level

        # --------------------------------------------------
        # Recommended Action Priority
        # --------------------------------------------------

        action_priority = {
            RecommendedAction.ALLOW_LOGIN: 1,
            RecommendedAction.REQUIRE_EMAIL_OTP: 2,
            RecommendedAction.REQUIRE_ADDITIONAL_VERIFICATION: 3,
            RecommendedAction.BLOCK_LOGIN: 4,
        }

        final_action_result = max(
            assessments,
            key=lambda result: action_priority[
                result.recommended_action
            ],
        )

        final_action = (
            final_action_result.recommended_action
        )

        # --------------------------------------------------
        # Combine Reasons
        # --------------------------------------------------

        reason = (
            "Rule-Based Assessment: "
            f"{rule_result.reason} | "
            "Login ML Assessment: "
            f"{login_ai_result.reason} | "
            "Session ML Assessment: "
            f"{session_ai_result.reason}"
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