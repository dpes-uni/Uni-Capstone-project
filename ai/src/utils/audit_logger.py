"""
logger.py

Audit logger for the AI-Assisted Anomaly Detection
and Adaptive MFA System.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from models.login_attempt import LoginAttempt
from models.risk_result import RiskResult
from config import settings


class AuditLogger:
    """
    Records authentication events for auditing
    and future forensic analysis.
    """

    def __init__(self):

        self.log_file = Path(settings.LOG_FILE)

        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def log(
        self,
        login: LoginAttempt,
        rule_result: RiskResult,
        ai_result: RiskResult,
        final_result: RiskResult,
    ) -> None:
        """
        Record one authentication event.
        """

        event = {

            "timestamp": datetime.now().isoformat(),

            "login": login.to_dict(),

            "rule_engine": rule_result.to_dict(),

            "machine_learning": ai_result.to_dict(),

            "final_decision": final_result.to_dict(),

        }

        with open(
            self.log_file,
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(event)
            )

            file.write("\n")