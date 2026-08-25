"""Privacy-preserving features for caller-supplied URL context.

This module never performs network I/O.  It validates and transforms URLs that
the caller already observed, and deliberately excludes hostname and raw query
values from the learned representation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

import numpy as np

from src.canonicalize import canonicalize_domain


HANDCRAFTED_FEATURES = (
    "path_length",
    "path_depth",
    "query_length",
    "query_parameter_count",
    "percent_escape_count",
    "digit_count",
    "digit_ratio",
    "special_character_count",
    "path_entropy",
    "suspicious_token_count",
    "brand_token_count",
    "has_ip_literal_in_path",
    "has_double_slash_in_path",
    "has_at_sign",
    "has_executable_extension",
    "redirect_count",
    "redirect_cross_host_count",
    "redirect_https_downgrade_count",
)


class URLContextError(ValueError):
    """The supplied URL context violates the bounded product contract."""


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    query_pairs: tuple[tuple[str, str], ...]
    normalized_url: str
    url_sha256: str


def _base2_length_bucket(length: int) -> int:
    if length <= 0:
        return 0
    return min(64, 1 << int(math.floor(math.log2(length))))


def redact_value_shape(value: str) -> str:
    """Return run-type and coarse run-length tokens without retaining value text."""

    if not value:
        return "empty"
    runs: list[str] = []
    run_type = ""
    run_length = 0
    for char in value:
        char_type = "a" if char.isalpha() else "d" if char.isdigit() else "s"
        if char_type == run_type:
            run_length += 1
            continue
        if run_type:
            runs.append(f"{run_type}{_base2_length_bucket(run_length)}")
        run_type = char_type
        run_length = 1
    runs.append(f"{run_type}{_base2_length_bucket(run_length)}")
    return "-".join(runs)


def parse_url(
    value: str,
    *,
    allowed_schemes: Iterable[str] = ("http", "https"),
    maximum_url_bytes: int = 4096,
    reject_credentials: bool = True,
) -> ParsedURL:
    raw = str(value).strip()
    if not raw:
        raise URLContextError("URL is empty")
    if len(raw.encode("utf-8")) > maximum_url_bytes:
        raise URLContextError("URL exceeds maximum byte length")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {item.lower() for item in allowed_schemes}:
            raise URLContextError("URL scheme is not allowed")
        if reject_credentials and (parsed.username is not None or parsed.password is not None):
            raise URLContextError("URL credentials are not allowed")
        if not parsed.hostname:
            raise URLContextError("URL host is missing")
        canonical = canonicalize_domain(parsed.hostname)
        if not canonical.is_valid or not canonical.domain_ascii:
            raise URLContextError("URL host is invalid")
        port = parsed.port
    except URLContextError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise URLContextError("URL cannot be parsed") from exc

    path = parsed.path or "/"
    query_pairs = tuple(parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False))
    sorted_pairs = tuple(sorted(query_pairs, key=lambda item: (item[0].lower(), item[1])))
    normalized_query = "&".join(
        f"{quote(key, safe='-._~')}={quote(value, safe='-._~')}"
        for key, value in sorted_pairs
    )
    host = canonical.domain_ascii
    netloc = host if port is None else f"{host}:{port}"
    normalized_url = urlunsplit((scheme, netloc, path, normalized_query, ""))
    return ParsedURL(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=parsed.query,
        query_pairs=sorted_pairs,
        normalized_url=normalized_url,
        url_sha256=hashlib.sha256(normalized_url.encode("utf-8")).hexdigest(),
    )


def _feature_text(parsed: ParsedURL) -> str:
    query_tokens = [
        f"{key.lower()}={redact_value_shape(value)}"
        for key, value in parsed.query_pairs
    ]
    path = parsed.path.lower()
    return path if not query_tokens else f"{path}?{'&'.join(query_tokens)}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _token_count(value: str, tokens: Sequence[str]) -> int:
    lowered = value.lower()
    return sum(lowered.count(token.lower()) for token in tokens if token)


def _has_ip_literal(value: str) -> int:
    candidates = re.findall(r"(?<![0-9a-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])", value)
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return 1
        except ValueError:
            continue
    return 0


def build_url_features(
    requested_url: str,
    *,
    expected_host: str | None,
    redirect_chain: Sequence[str] = (),
    contract: Mapping[str, Any],
    suspicious_tokens: Sequence[str],
    brand_tokens: Sequence[str],
) -> tuple[str, np.ndarray, ParsedURL]:
    parsed = parse_url(
        requested_url,
        allowed_schemes=contract["allowed_schemes"],
        maximum_url_bytes=int(contract["maximum_url_bytes"]),
        reject_credentials=bool(contract["reject_credentials"]),
    )
    if expected_host is not None:
        canonical_expected = canonicalize_domain(expected_host)
        if not canonical_expected.is_valid or canonical_expected.domain_ascii != parsed.host:
            raise URLContextError("requested URL host does not equal canonical domain")
    maximum_redirects = int(contract["maximum_redirects"])
    if len(redirect_chain) > maximum_redirects:
        raise URLContextError("redirect chain exceeds maximum length")

    redirects = [
        parse_url(
            item,
            allowed_schemes=contract["allowed_schemes"],
            maximum_url_bytes=int(contract["maximum_url_bytes"]),
            reject_credentials=bool(contract["reject_credentials"]),
        )
        for item in redirect_chain
    ]
    chain = [parsed, *redirects]
    cross_host = sum(left.host != right.host for left, right in zip(chain, chain[1:]))
    downgrade = sum(
        left.scheme == "https" and right.scheme == "http"
        for left, right in zip(chain, chain[1:])
    )

    feature_text = _feature_text(parsed)
    raw_component = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    digit_count = sum(char.isdigit() for char in raw_component)
    visible_length = max(1, len(raw_component))
    special_count = sum(not char.isalnum() for char in raw_component)
    path_lower = parsed.path.lower()
    executable_extensions = tuple(
        str(value).lower() for value in contract["executable_extensions"]
    )
    values = np.asarray(
        [
            len(parsed.path),
            len([part for part in parsed.path.split("/") if part]),
            len(parsed.query),
            len(parsed.query_pairs),
            len(re.findall(r"%[0-9a-fA-F]{2}", raw_component)),
            digit_count,
            digit_count / visible_length,
            special_count,
            _entropy(parsed.path),
            _token_count(feature_text, suspicious_tokens),
            _token_count(feature_text, brand_tokens),
            _has_ip_literal(parsed.path),
            int("//" in parsed.path),
            int("@" in raw_component),
            int(path_lower.endswith(executable_extensions)),
            len(redirects),
            cross_host,
            downgrade,
        ],
        dtype=np.float64,
    )
    if len(values) != len(HANDCRAFTED_FEATURES):
        raise AssertionError("URL handcrafted feature contract drift")
    return feature_text, values, parsed
