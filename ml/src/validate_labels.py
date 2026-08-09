"""Command-line entry point for ML replay label validation."""

try:
    from replay_labels import cli
except ModuleNotFoundError:  # pragma: no cover - supports package-style pytest imports
    from ml.src.replay_labels import cli


if __name__ == "__main__":
    raise SystemExit(cli())
