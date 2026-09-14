"""
csv_loader.py

Utility class for loading and saving CSV datasets.

Used by:
- Feature Engineering
- Model Trainer
- Testing
- Future reporting modules
"""

from pathlib import Path

import pandas as pd


class CSVLoader:
    """
    Utility class for reading and writing CSV files.
    """

    @staticmethod
    def load(file_path: str) -> pd.DataFrame:
        """
        Load a CSV file into a Pandas DataFrame.

        Args:
            file_path: Path to the CSV file.

        Returns:
            pd.DataFrame

        Raises:
            FileNotFoundError
            ValueError
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"CSV file not found: {path}"
            )

        try:
            dataframe = pd.read_csv(path)

        except Exception as error:
            raise ValueError(
                f"Unable to read CSV file: {error}"
            ) from error

        return dataframe

    @staticmethod
    def save(dataframe: pd.DataFrame, file_path: str) -> None:
        """
        Save a DataFrame to CSV.

        Args:
            dataframe: Pandas DataFrame
            file_path: Destination path
        """

        path = Path(file_path)

        path.parent.mkdir(parents=True, exist_ok=True)

        dataframe.to_csv(path, index=False)

    @staticmethod
    def exists(file_path: str) -> bool:
        """
        Check whether a CSV file exists.
        """

        return Path(file_path).exists()

    @staticmethod
    def row_count(dataframe: pd.DataFrame) -> int:
        """
        Return number of rows.
        """

        return len(dataframe)

    @staticmethod
    def column_count(dataframe: pd.DataFrame) -> int:
        """
        Return number of columns.
        """

        return len(dataframe.columns)
    