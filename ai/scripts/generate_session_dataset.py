"""
generate_session_dataset.py

Generates synthetic authenticated session behaviour
for training the Session Monitoring AI.

The dataset contains normal and unusual sessions
for Students, Agents and Institutions.

The unusual_activity field is the target label.
It is NOT used as an input feature by the model.
"""

import random
import sys
from pathlib import Path

import pandas as pd


# ----------------------------------------------------------
# Project Paths
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

USERS_FILE = (
    PROJECT_ROOT
    / "data"
    / "source"
    / "platform_users.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "session_events.csv"
)


# ----------------------------------------------------------
# Dataset Configuration
# ----------------------------------------------------------

SESSIONS_PER_USER = 50
ANOMALY_RATE = 0.20

random.seed(42)


class SessionDatasetGenerator:
    """
    Generates synthetic session behaviour data.
    """

    def __init__(self):
        self.users = pd.read_csv(USERS_FILE)
        self.records = []

    # ------------------------------------------------------
    # Generate normal session
    # ------------------------------------------------------

    def generate_normal_session(self, user_role):
        """
        Generate realistic normal behaviour based
        on the user's platform role.
        """

        if user_role == "Student":

            session_duration = random.randint(5, 45)

            documents_viewed = random.randint(1, 5)

            documents_downloaded = random.randint(0, 2)

            documents_uploaded = random.randint(0, 3)

            verification_actions = random.randint(0, 3)

            failed_actions = random.randint(0, 1)

        elif user_role == "Agent":

            session_duration = random.randint(15, 120)

            documents_viewed = random.randint(5, 30)

            documents_downloaded = random.randint(0, 10)

            documents_uploaded = random.randint(2, 15)

            verification_actions = random.randint(2, 20)

            failed_actions = random.randint(0, 2)

        else:  # Institution

            session_duration = random.randint(20, 150)

            documents_viewed = random.randint(10, 50)

            documents_downloaded = random.randint(1, 15)

            documents_uploaded = random.randint(0, 5)

            verification_actions = random.randint(5, 30)

            failed_actions = random.randint(0, 2)

        # Normal users can occasionally perform rapid actions.
        rapid_actions = random.random() < 0.10

        return {
            "session_duration_minutes": session_duration,
            "documents_viewed": documents_viewed,
            "documents_downloaded": documents_downloaded,
            "documents_uploaded": documents_uploaded,
            "verification_actions": verification_actions,
            "failed_actions": failed_actions,
            "rapid_actions": rapid_actions,
        }

    # ------------------------------------------------------
    # Generate unusual session
    # ------------------------------------------------------

    def generate_unusual_session(self, user_role):
        """
        Generate unusual behaviour.

        Different anomaly patterns are used so the model
        cannot rely on a single feature.
        """

        session = self.generate_normal_session(user_role)

        anomaly_type = random.choice([
            "high_activity",
            "long_session",
            "failed_actions",
            "rapid_activity",
            "mixed_behaviour",
        ])

        # --------------------------------------------------
        # High activity anomaly
        # --------------------------------------------------

        if anomaly_type == "high_activity":

            session["documents_viewed"] += random.randint(
                15, 35
            )

            session["documents_downloaded"] += random.randint(
                5, 15
            )

            session["verification_actions"] += random.randint(
                8, 20
            )

            # Rapid actions are NOT always present.
            session["rapid_actions"] = (
                random.random() < 0.50
            )

        # --------------------------------------------------
        # Long session anomaly
        # --------------------------------------------------

        elif anomaly_type == "long_session":

            session["session_duration_minutes"] += random.randint(
                90, 180
            )

            # Activity can still look relatively normal.
            session["rapid_actions"] = (
                random.random() < 0.30
            )

        # --------------------------------------------------
        # Failed action anomaly
        # --------------------------------------------------

        elif anomaly_type == "failed_actions":

            session["failed_actions"] += random.randint(
                3, 7
            )

            # Other activity remains mostly normal.
            session["rapid_actions"] = (
                random.random() < 0.40
            )

        # --------------------------------------------------
        # Rapid activity anomaly
        # --------------------------------------------------

        elif anomaly_type == "rapid_activity":

            session["rapid_actions"] = True

            session["documents_viewed"] += random.randint(
                5, 15
            )

            session["verification_actions"] += random.randint(
                3, 10
            )

        # --------------------------------------------------
        # Mixed behaviour anomaly
        # --------------------------------------------------

        elif anomaly_type == "mixed_behaviour":

            session["session_duration_minutes"] += random.randint(
                45, 100
            )

            session["documents_viewed"] += random.randint(
                5, 20
            )

            session["failed_actions"] += random.randint(
                1, 4
            )

            session["rapid_actions"] = (
                random.random() < 0.70
            )

        return session

    # ------------------------------------------------------
    # Generate one complete session
    # ------------------------------------------------------

    def generate_session(self, user):

        user_role = user.user_role

        # Decide whether this session is unusual.
        is_unusual = (
            random.random() < ANOMALY_RATE
        )

        if is_unusual:

            session = self.generate_unusual_session(
                user_role
            )

        else:

            session = self.generate_normal_session(
                user_role
            )

        # Add identifying information and target label.
        session["username"] = user.username
        session["user_role"] = user_role
        session["unusual_activity"] = is_unusual

        return session

    # ------------------------------------------------------
    # Generate complete dataset
    # ------------------------------------------------------

    def generate_dataset(self):

        for _, user in self.users.iterrows():

            for _ in range(SESSIONS_PER_USER):

                session = self.generate_session(user)

                self.records.append(session)

    # ------------------------------------------------------
    # Save dataset
    # ------------------------------------------------------

    def save(self):

        dataframe = pd.DataFrame(self.records)

        OUTPUT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        dataframe.to_csv(
            OUTPUT_FILE,
            index=False,
        )

        print("\nSession dataset generated successfully!")

        print(
            f"Total Records : {len(dataframe)}"
        )

        print(
            f"Saved To      : {OUTPUT_FILE}"
        )


def main():

    generator = SessionDatasetGenerator()

    generator.generate_dataset()

    generator.save()


if __name__ == "__main__":
    main()