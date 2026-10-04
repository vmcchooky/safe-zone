"""
Unit tests for group-disjoint split partitioning (Phase 1).
"""

import os
import sys
import pytest
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.make_splits import assign_group_partition, make_splits


def test_assign_group_partition_determinism():
    p1 = assign_group_partition("example.com", seed=42)
    p2 = assign_group_partition("example.com", seed=42)
    assert p1 == p2
    assert p1 in {"train", "validation", "calibration", "test"}


def test_group_disjoint_property():
    groups = [f"domain{i}.com" for i in range(100)]
    partitions = [assign_group_partition(g, seed=42) for g in groups]

    # Map groups to partitions
    group_map = dict(zip(groups, partitions))

    train_groups = {g for g, p in group_map.items() if p == "train"}
    val_groups = {g for g, p in group_map.items() if p == "validation"}
    cal_groups = {g for g, p in group_map.items() if p == "calibration"}
    test_groups = {g for g, p in group_map.items() if p == "test"}

    assert len(train_groups & val_groups) == 0
    assert len(train_groups & cal_groups) == 0
    assert len(train_groups & test_groups) == 0
    assert len(val_groups & cal_groups) == 0
    assert len(val_groups & test_groups) == 0
    assert len(cal_groups & test_groups) == 0
