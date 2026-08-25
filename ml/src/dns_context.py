"""Bounded DNS-over-HTTPS collection and v8 DNS context features."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

import httpx
import numpy as np
import pandas as pd


DNS_TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}


def stable_bucket(seed: int, evaluation_group: str, modulo: int = 10) -> int:
    digest = hashlib.sha256(f"{seed}|{evaluation_group}".encode("utf-8")).digest()
    return int.from_bytes(digest, "big", signed=False) % modulo


def _parsed_response(value: Any) -> Dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("Status"), int):
        return None
    return value


def _answers(response: Dict[str, Any] | None) -> list[Dict[str, Any]]:
    if response is None or not isinstance(response.get("Answer"), list):
        return []
    return [answer for answer in response["Answer"] if isinstance(answer, dict)]


def _minimum_ttl(answers: Sequence[Dict[str, Any]]) -> float:
    values = [
        int(answer["TTL"])
        for answer in answers
        if isinstance(answer.get("TTL"), (int, float)) and answer["TTL"] >= 0
    ]
    return float(math.log1p(min(values))) if values else 0.0


def extract_dns_features(responses: Dict[str, Any]) -> Dict[str, float]:
    parsed = {name: _parsed_response(responses.get(name)) for name in ("A", "AAAA", "NS", "MX")}
    answers = {name: _answers(value) for name, value in parsed.items()}
    a_addresses = sum(answer.get("type") == DNS_TYPE_CODES["A"] for answer in answers["A"])
    aaaa_addresses = sum(
        answer.get("type") == DNS_TYPE_CODES["AAAA"] for answer in answers["AAAA"]
    )
    return {
        "a_noerror": float(parsed["A"] is not None and parsed["A"]["Status"] == 0),
        "a_nxdomain": float(parsed["A"] is not None and parsed["A"]["Status"] == 3),
        "a_answer_count": float(len(answers["A"])),
        "a_address_count": float(a_addresses),
        "a_cname_count": float(
            sum(answer.get("type") == DNS_TYPE_CODES["CNAME"] for answer in answers["A"])
        ),
        "log1p_a_min_ttl": _minimum_ttl(answers["A"]),
        "aaaa_noerror": float(
            parsed["AAAA"] is not None and parsed["AAAA"]["Status"] == 0
        ),
        "aaaa_answer_count": float(len(answers["AAAA"])),
        "aaaa_address_count": float(aaaa_addresses),
        "log1p_aaaa_min_ttl": _minimum_ttl(answers["AAAA"]),
        "ns_noerror": float(parsed["NS"] is not None and parsed["NS"]["Status"] == 0),
        "ns_answer_count": float(len(answers["NS"])),
        "log1p_ns_min_ttl": _minimum_ttl(answers["NS"]),
        "mx_noerror": float(parsed["MX"] is not None and parsed["MX"]["Status"] == 0),
        "mx_answer_count": float(len(answers["MX"])),
        "log1p_mx_min_ttl": _minimum_ttl(answers["MX"]),
        "resolved_any": float(a_addresses + aaaa_addresses > 0),
        "dns_error_count": float(sum(value is None for value in parsed.values())),
    }


def has_parsed_response(responses: Dict[str, Any]) -> bool:
    return any(_parsed_response(responses.get(name)) is not None for name in ("A", "AAAA", "NS", "MX"))


async def _query(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    endpoint: str,
    domain: str,
    record_type: str,
    maximum_attempts: int,
    retry_statuses: set[int],
) -> Dict[str, Any]:
    last_error = "unattempted"
    for attempt in range(maximum_attempts):
        try:
            async with semaphore:
                response = await client.get(
                    endpoint,
                    params={"name": domain, "type": record_type},
                    headers={"Accept": "application/dns-json"},
                )
            if response.status_code in retry_statuses and attempt + 1 < maximum_attempts:
                await asyncio.sleep(0.15 * (attempt + 1))
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("Status"), int):
                raise ValueError("DoH response lacks integer Status")
            return payload
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            last_error = type(exc).__name__
            if attempt + 1 < maximum_attempts:
                await asyncio.sleep(0.15 * (attempt + 1))
    return {"error": last_error}


async def _collect_domain(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    config: Dict[str, Any],
    domain: str,
) -> Dict[str, Any]:
    record_types = list(config["record_types"])
    values = await asyncio.gather(
        *[
            _query(
                client,
                semaphore,
                str(config["endpoint"]),
                domain,
                record_type,
                int(config["maximum_attempts"]),
                set(int(value) for value in config["retry_statuses"]),
            )
            for record_type in record_types
        ]
    )
    return {"domain_ascii": domain, "responses": dict(zip(record_types, values))}


async def _collect(config: Dict[str, Any], domains: Sequence[str]) -> list[Dict[str, Any]]:
    timeout = httpx.Timeout(float(config["timeout_seconds"]))
    limits = httpx.Limits(
        max_connections=int(config["maximum_concurrency"]),
        max_keepalive_connections=int(config["maximum_concurrency"]),
    )
    semaphore = asyncio.Semaphore(int(config["maximum_concurrency"]))
    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False) as client:
        return await asyncio.gather(
            *[_collect_domain(client, semaphore, config, domain) for domain in domains]
        )


def collect_dns_features(
    frame: pd.DataFrame,
    config: Dict[str, Any],
    feature_names: Sequence[str],
    raw_output: Path,
) -> pd.DataFrame:
    """Collect DNS in domain-only order and join fixed features back to the cohort."""
    ordered = sorted(
        frame["domain_ascii"].astype(str).unique(),
        key=lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest(),
    )
    records = asyncio.run(_collect(config, ordered))
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    with open(raw_output, "w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    by_domain = {}
    for record in records:
        features = extract_dns_features(record["responses"])
        missing = sorted(set(feature_names) - set(features))
        extra = sorted(set(features) - set(feature_names))
        if missing or extra:
            raise ValueError(f"DNS feature contract mismatch: missing={missing}, extra={extra}")
        by_domain[record["domain_ascii"]] = {
            **features,
            "dns_parsed_response": has_parsed_response(record["responses"]),
        }
    result = frame.copy()
    for name in feature_names:
        result[name] = [by_domain[str(domain)][name] for domain in result["domain_ascii"]]
    result["dns_parsed_response"] = [
        by_domain[str(domain)]["dns_parsed_response"] for domain in result["domain_ascii"]
    ]
    return result


def select_zero_benign_threshold(
    probabilities: np.ndarray, labels: np.ndarray
) -> tuple[float, Dict[str, Any]]:
    probability = np.asarray(probabilities, dtype=float)
    label = np.asarray(labels, dtype=int)
    benign = probability[label == 0]
    malicious = probability[label == 1]
    if len(benign) == 0 or len(malicious) == 0:
        raise ValueError("threshold split requires both benign and malicious rows")
    threshold = float(np.nextafter(np.max(benign), 1.0))
    return threshold, {
        "rows": int(len(label)),
        "benign_rows": int(len(benign)),
        "malicious_rows": int(len(malicious)),
        "accepted_benign": int(np.sum(benign >= threshold)),
        "accepted_malicious": int(np.sum(malicious >= threshold)),
        "threshold": threshold,
    }


def combined_decisions(
    primary_probability: np.ndarray,
    context_probability: np.ndarray,
    primary_threshold: float,
    context_threshold: float,
) -> np.ndarray:
    primary = np.asarray(primary_probability) >= primary_threshold
    context = np.asarray(context_probability) >= context_threshold
    return primary | (~primary & context)


def coverage_metrics(frame: pd.DataFrame) -> Dict[str, Any]:
    result: Dict[str, Any] = {"rows": int(len(frame)), "by_label": {}}
    fractions = []
    for label in (0, 1):
        mask = frame["label"].to_numpy(int) == label
        fraction = float(frame.loc[mask, "dns_parsed_response"].mean())
        result["by_label"][str(label)] = {
            "rows": int(np.sum(mask)),
            "parsed_response_fraction": fraction,
        }
        fractions.append(fraction)
    result["label_coverage_gap"] = float(abs(fractions[1] - fractions[0]))
    result["minimum_label_coverage"] = float(min(fractions))
    return result
