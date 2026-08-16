"""
generate_login_dataset.py

Generates realistic login attempts for training the
AI Login Risk Model.
"""
import sys
from pathlib import Path

# ----------------------------------------------------------
# Add the src folder to Python's search path
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))


import random
from pathlib import Path

import pandas as pd

from models.login_attempt import LoginAttempt
from services.risk_calculator import RiskCalculator


# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------

USERS_FILE = Path("data/source/platform_users.csv")
OUTPUT_FILE = Path("data/raw/login_attempts.csv")

LOGIN_ATTEMPTS_PER_USER = 50
ANOMALY_RATE = 0.20

random.seed(42)


class LoginDatasetGenerator:

    def __init__(self):

        self.users = pd.read_csv(USERS_FILE)

        self.calculator = RiskCalculator()

        self.records = []

    # ------------------------------------------------------

    def generate_ip(self, prefix: str) -> str:

        return (
            prefix
            + str(random.randint(0, 255))
            + "."
            + str(random.randint(1, 254))
        )

    # ------------------------------------------------------

    def random_ip(self):

        return (
            f"{random.randint(1,223)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}"
        )

    # ------------------------------------------------------

    def generate_login(self, user):

        anomaly = random.random() < ANOMALY_RATE

        # ----------------------------
        # Login Hour
        # ----------------------------

        if anomaly:

            login_hour = random.choice(
                [0, 1, 2, 3, 4, 22, 23]
            )

        else:

            login_hour = random.randint(
                int(user.usual_login_start_hour),
                int(user.usual_login_end_hour)
            )

        # ----------------------------
        # Device
        # ----------------------------

        if anomaly:

            devices = [
                "Windows Laptop",
                "MacBook",
                "Linux Laptop"
            ]

            device = random.choice(devices)

            new_device = (
                device != user.normal_device
            )

        else:

            device = user.normal_device

            new_device = False

        # ----------------------------
        # Browser
        # ----------------------------

        if anomaly:

            browser = random.choice(
                [
                    "Microsoft Edge",
                    "Google Chrome",
                    "Firefox",
                    "Safari"
                ]
            )

        else:

            browser = user.normal_browser

        # ----------------------------
        # Operating System
        # ----------------------------

        if anomaly:

            operating_system = random.choice(
                [
                    "Windows 11",
                    "macOS",
                    "Ubuntu 24.04"
                ]
            )

        else:

            operating_system = (
                user.normal_operating_system
            )

        # ----------------------------
        # Location
        # ----------------------------

        if anomaly:

            countries = [
                "Germany",
                "Singapore",
                "Canada",
                "United Kingdom"
            ]

            cities = [
                "Berlin",
                "Singapore",
                "Toronto",
                "London"
            ]

            index = random.randint(0, 3)

            country = countries[index]

            city = cities[index]

            trusted_location = False

        else:

            country = user.country

            city = user.city

            trusted_location = True

        # ----------------------------
        # VPN
        # ----------------------------

        if anomaly:

            vpn = random.choice([True, False])

        else:

            vpn = bool(user.trusted_vpn_user)

        # ----------------------------
        # Failed Attempts
        # ----------------------------

        if anomaly:

            failed = random.randint(3, 6)

        else:

            failed = random.randint(0, 2)

        # ----------------------------
        # IP Address
        # ----------------------------

        if trusted_location:

            ip = self.generate_ip(
                user.trusted_ip_prefix
            )

        else:

            ip = self.random_ip()

        trusted_device = not new_device

        login = LoginAttempt(

            username=user.username,

            device=device,

            browser=browser,

            operating_system=operating_system,

            ip_address=ip,

            country=country,

            city=city,

            login_hour=login_hour,

            failed_login_attempts=failed,

            new_device=new_device,

            vpn_detected=vpn,

            trusted_device=trusted_device,

            trusted_location=trusted_location,
        )

        result = self.calculator.calculate(login)

        return {

            **login.to_dict(),

            "user_role": user.user_role,

            "organisation": user.organisation,

            "risk_score": result.risk_score,

            "risk_level": result.risk_level.value,

            "recommended_action":
                result.recommended_action.value,

            "reason": result.reason,
        }

    # ------------------------------------------------------

    def generate_dataset(self):

        for _, user in self.users.iterrows():

            for _ in range(
                LOGIN_ATTEMPTS_PER_USER
            ):

                self.records.append(

                    self.generate_login(user)

                )

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

        print(
            f"\nDataset generated successfully!"
        )

        print(
            f"Total Records : {len(dataframe)}"
        )

        print(
            f"Saved To      : {OUTPUT_FILE}"
        )


def main():

    generator = LoginDatasetGenerator()

    generator.generate_dataset()

    generator.save()


if __name__ == "__main__":
    main()