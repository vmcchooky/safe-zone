"""
Unit tests for artifact validation suite (Phase 2).
"""

import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.validate_artifacts import ArtifactValidator


def test_artifact_validator_initialization():
    validator = ArtifactValidator()
    assert validator.derived_dir is not None
    assert validator.matrices_dir is not None
    assert validator.partitions_dir is not None
