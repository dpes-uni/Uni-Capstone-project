"""
decision_engine.py

Combines risk assessments into authentication decisions.

Login decisions combine:
    - Rule-based login risk
    - Login ML risk

Session decisions evaluate:
    - Session ML risk

The DecisionEngine returns a RiskResult.
"""

from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction
from models.risk_result import RiskResult


class DecisionEngine:
    """
    Produces final authentication decisions from
    the available risk assessments.
    """

    # ------------------------------------------------------
    # Login Decision
    # ------------------------------------------------------

    def evaluate_login(
        self,
        rule_result: RiskResult,
        login_ai_result: RiskResult,
    ) -> RiskResult:
        """
        Combine rule-based login risk and Login ML risk.

        The higher-risk assessment wins.

        Session risk is intentionally NOT included here because
        an authenticated session does not exist yet.
        """

        assessments = [
            rule_result,
            login_ai_result,
        ]

        risk_priority = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
        }

        action_priority = {
            RecommendedAction.ALLOW_LOGIN: 1,
            RecommendedAction.REQUIRE_EMAIL_OTP: 2,
            RecommendedAction.REQUIRE_ADDITIONAL_VERIFICATION: 3,
            RecommendedAction.BLOCK_LOGIN: 4,
        }

        # Highest numerical risk score wins.
        final_score = max(
            result.risk_score
            for result in assessments
        )

        # Highest risk level wins.
        final_level_result = max(
            assessments,
            key=lambda result: risk_priority[result.risk_level],
        )

        final_level = final_level_result.risk_level

        # Strongest recommended security action wins.
        final_action_result = max(
            assessments,
            key=lambda result: action_priority[
                result.recommended_action
            ],
        )

        final_action = final_action_result.recommended_action

        reason = (
            "Rule-Based Assessment: "
            f"{rule_result.reason} | "
            "Login ML Assessment: "
            f"{login_ai_result.reason}"
        )

        return RiskResult(
            risk_score=final_score,
            risk_level=final_level,
            recommended_action=final_action,
            reason=reason,
        )

    # ------------------------------------------------------
    # Session Decision
    # ------------------------------------------------------

    def evaluate_session(
        self,
        session_ai_result: RiskResult,
    ) -> RiskResult:
        """
        Evaluate an authenticated session.

        SessionPredictor already produces a RiskResult,
        so the session decision currently preserves that
        result rather than inventing another risk calculation.

        This provides a clear integration boundary for the
        future Node.js session-monitoring flow.
        """

        return session_ai_result

    # ------------------------------------------------------
    # Backwards Compatibility
    # ------------------------------------------------------

    def evaluate(
        self,
        rule_result: RiskResult,
        login_ai_result: RiskResult,
        session_ai_result: RiskResult = None,
    ) -> RiskResult:
        """
        Compatibility wrapper.

        New code should use:
            evaluate_login()
            evaluate_session()

        If a session result is supplied, the three-assessment
        behaviour is retained for existing standalone tests.
        """

        if session_ai_result is None:
            return self.evaluate_login(
                rule_result,
                login_ai_result,
            )

        assessments = [
            rule_result,
            login_ai_result,
            session_ai_result,
        ]

        risk_priority = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
        }

        action_priority = {
            RecommendedAction.ALLOW_LOGIN: 1,
            RecommendedAction.REQUIRE_EMAIL_OTP: 2,
            RecommendedAction.REQUIRE_ADDITIONAL_VERIFICATION: 3,
            RecommendedAction.BLOCK_LOGIN: 4,
        }

        final_score = max(
            result.risk_score
            for result in assessments
        )

        final_level_result = max(
            assessments,
            key=lambda result: risk_priority[result.risk_level],
        )

        final_action_result = max(
            assessments,
            key=lambda result: action_priority[
                result.recommended_action
            ],
        )

        reason = (
            "Rule-Based Assessment: "
            f"{rule_result.reason} | "
            "Login ML Assessment: "
            f"{login_ai_result.reason} | "
            "Session ML Assessment: "
            f"{session_ai_result.reason}"
        )

        return RiskResult(
            risk_score=final_score,
            risk_level=final_level_result.risk_level,
            recommended_action=(
                final_action_result.recommended_action
            ),
            reason=reason,
        )