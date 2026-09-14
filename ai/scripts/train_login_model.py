"""
train_login_model.py

Trains the Login Risk Machine Learning model.
"""

import sys
from pathlib import Path

# ----------------------------------------------------------
# Make src importable
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

# ----------------------------------------------------------

from services.model_trainer import ModelTrainer


def main():
    print("=" * 60)
    print(" AI Login Risk Model Trainer")
    print("=" * 60)

    trainer = ModelTrainer()

    accuracy = trainer.train()

    print("\nTraining completed successfully.")
    print(f"Model Accuracy: {accuracy:.2%}")


if __name__ == "__main__":
    main()