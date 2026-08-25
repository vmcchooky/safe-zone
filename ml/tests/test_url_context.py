from __future__ import annotations

import numpy as np
import pytest

from src.url_context import (
    HANDCRAFTED_FEATURES,
    URLContextError,
    build_url_features,
    parse_url,
    redact_value_shape,
)


CONTRACT = {
    "allowed_schemes": ["http", "https"],
    "maximum_url_bytes": 128,
    "maximum_redirects": 2,
    "reject_credentials": True,
    "executable_extensions": [".exe", ".apk"],
}


def test_query_values_are_redacted_and_host_is_excluded():
    secret = "TopSecret12345"
    text, values, parsed = build_url_features(
        f"https://Example.COM/login?token={secret}&empty=",
        expected_host="example.com",
        contract=CONTRACT,
        suspicious_tokens=["login"],
        brand_tokens=["example"],
    )

    assert parsed.host == "example.com"
    assert parsed.registrable_domain == "example.com"
    assert secret not in text
    assert "example.com" not in text
    assert "token=" in text
    assert text.startswith("/login?")
    assert values.shape == (len(HANDCRAFTED_FEATURES),)
    assert np.isfinite(values).all()
    assert values[HANDCRAFTED_FEATURES.index("suspicious_token_count")] == 1
    assert values[HANDCRAFTED_FEATURES.index("brand_token_count")] == 0


def test_value_shape_has_no_original_characters():
    assert redact_value_shape("Abcd1234-xyz") == "a4-d4-s1-a2"
    assert redact_value_shape("") == "empty"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "https://user:password@example.com/",
        "https:///missing-host",
        "https://example.com/" + "a" * 128,
    ],
)
def test_invalid_context_is_rejected(url: str):
    with pytest.raises(URLContextError):
        parse_url(url, maximum_url_bytes=128, reject_credentials=True)


def test_expected_host_redirect_limits_and_redirect_features():
    with pytest.raises(URLContextError, match="does not equal"):
        build_url_features(
            "https://evil.example/path",
            expected_host="safe.example",
            contract=CONTRACT,
            suspicious_tokens=[],
            brand_tokens=[],
        )

    _, values, _ = build_url_features(
        "https://safe.example/start",
        expected_host="safe.example",
        redirect_chain=["http://other.example/final"],
        contract=CONTRACT,
        suspicious_tokens=[],
        brand_tokens=[],
    )
    assert values[HANDCRAFTED_FEATURES.index("redirect_count")] == 1
    assert values[HANDCRAFTED_FEATURES.index("redirect_cross_host_count")] == 1
    assert values[HANDCRAFTED_FEATURES.index("redirect_https_downgrade_count")] == 1

    with pytest.raises(URLContextError, match="exceeds"):
        build_url_features(
            "https://safe.example/start",
            expected_host="safe.example",
            redirect_chain=[
                "https://safe.example/a",
                "https://safe.example/b",
                "https://safe.example/c",
            ],
            contract=CONTRACT,
            suspicious_tokens=[],
            brand_tokens=[],
        )
