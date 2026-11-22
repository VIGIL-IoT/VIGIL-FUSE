"""Manual controlled UART smoke test, excluded from automatic model execution in CI."""

from pathlib import Path
from runpy import run_path


if __name__ == "__main__":
    run_path(str(Path(__file__).with_name("benchmark_reasoning_model.py")), run_name="__main__")
