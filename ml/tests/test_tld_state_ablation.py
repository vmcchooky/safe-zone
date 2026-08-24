import pandas as pd

from src.build_tld_state_ablation import ternary_tld_values


def test_ternary_tld_ablation_values_match_contract():
    policy = {
        "tld_state_encoding": {
            "unknown": 0.0,
            "known_neutral": 0.5,
            "risky": 1.0,
        }
    }
    values = ternary_tld_values(
        pd.Series(["ordinary.example.com", "risk.example.xyz", "x.invalidtld"]),
        policy,
    )
    assert values.tolist() == [0.5, 1.0, 0.0]
