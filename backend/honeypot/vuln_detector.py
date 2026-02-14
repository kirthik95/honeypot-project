"""
Pattern-based vulnerability detector with dynamic CVSS scoring.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Tuple

try:
    from .dynamic_cvss_calculator import DynamicCVSSCalculator
except Exception:
    DynamicCVSSCalculator = None  # type: ignore[assignment]


@dataclass(frozen=True)
class _Rule:
    id: str
    attack_type: str
    name: str
    owasp: str
    keyword: str
    remediation: str
    patterns: Tuple[Pattern[str], ...]


def _rx(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_RULES: Tuple[_Rule, ...] = (
    _Rule(
        id="SQLI",
        attack_type="sql_injection",
        name="SQL Injection",
        owasp="A03:2021 Injection",
        keyword="SQL Injection",
        remediation="Use parameterized queries (prepared statements) and validate inputs server-side.",
        patterns=(
            _rx(r"\bunion\b\s+\bselect\b"),
            _rx(r"\bor\b\s+1\s*=\s*1\b"),
            _rx(r"--\s*$"),
            _rx(r"/\*.*\*/"),
            _rx(r"\bdrop\b\s+\btable\b"),
            _rx(r"(xp_cmdshell|exec\s+master|sp_executesql)"),
            _rx(r"(load_file|into\s+outfile|into\s+dumpfile)"),
        ),
    ),
    _Rule(
        id="XSS",
        attack_type="xss",
        name="Cross-Site Scripting (XSS)",
        owasp="A03:2021 Injection",
        keyword="XSS",
        remediation="Escape/encode output, apply a strict CSP, and sanitize untrusted HTML inputs.",
        patterns=(
            _rx(r"<\s*script\b"),
            _rx(r"onerror\s*="),
            _rx(r"onload\s*="),
            _rx(r"javascript\s*:"),
            _rx(r"<\s*img\b[^>]*\bon\w+\s*="),
            _rx(r"<\s*svg\b[^>]*\bon\w+\s*="),
            _rx(r"(document\.cookie|localStorage|sessionStorage)"),
        ),
    ),
    _Rule(
        id="CMDI",
        attack_type="command_injection",
        name="Command Injection",
        owasp="A03:2021 Injection",
        keyword="Command Injection",
        remediation="Never pass user input to shell commands. Use allowlists and safe APIs (no shell=True).",
        patterns=(
            _rx(r"(;|\|\||&&|\|)\s*(ls|cat|whoami|id|pwd|curl|wget|nc|bash|sh)\b"),
            _rx(r"`[^`]{1,200}`"),
            _rx(r"\$\([^)]{1,200}\)"),
            _rx(r"(/bin/(bash|sh)|nc\s+-e|mkfifo)"),
        ),
    ),
    _Rule(
        id="TRAVERSAL",
        attack_type="path_traversal",
        name="Path Traversal",
        owasp="A01:2021 Broken Access Control",
        keyword="Path Traversal",
        remediation="Normalize paths, enforce allowlisted directories, and reject traversal sequences like ../ and ..\\.",
        patterns=(
            _rx(r"\.\./"),
            _rx(r"\.\.\\"),
            _rx(r"%2e%2e%2f"),
            _rx(r"%2e%2e%5c"),
            _rx(r"\.\.%2f"),
            _rx(r"\.\.%5c"),
        ),
    ),
    _Rule(
        id="SSRF",
        attack_type="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        owasp="A10:2021 Server-Side Request Forgery (SSRF)",
        keyword="SSRF",
        remediation="Block internal IP ranges, use allowlists for outbound requests, and disable metadata access.",
        patterns=(
            _rx(r"https?://(localhost|127\.0\.0\.1)"),
            _rx(r"https?://169\.254\.169\.254"),
            _rx(r"https?://(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)"),
        ),
    ),
)


class EnhancedVulnerabilityDetector:
    """
    Pattern-based vulnerability detector with optional dynamic CVSS scoring.
    """

    def __init__(self):
        self.rules = _RULES
        self.cvss_calculator = None
        if DynamicCVSSCalculator is not None:
            try:
                self.cvss_calculator = DynamicCVSSCalculator()
            except Exception:
                self.cvss_calculator = None

    def detect(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str, str]] = set()

        candidates = self._candidate_fields(data)
        if not candidates:
            return findings

        for rule in self.rules:
            evidence = self._match_rule(rule, candidates)
            if evidence is None:
                continue

            dedupe_key = (
                rule.attack_type,
                str(evidence.get("field", "")),
                str(evidence.get("match", "")).lower(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            matched_payload = str(evidence.get("match", ""))
            matched_field = str(evidence.get("field", ""))

            context = {
                "field": matched_field,
                "stored": self._is_stored_field(matched_field),
                "full_payload": str(evidence.get("value", "")),
            }

            cvss_result = self._calculate_cvss(rule.attack_type, matched_payload, context)

            findings.append(
                {
                    "id": rule.id,
                    "attack_type": rule.attack_type,
                    "name": rule.name,
                    "owasp": rule.owasp,
                    "cvss_score": cvss_result["cvss_score"],
                    "cvss_vector": cvss_result["cvss_vector"],
                    "severity": cvss_result["severity"],
                    "keyword": rule.keyword,
                    "remediation": rule.remediation,
                    "evidence": evidence,
                    "cvss_metrics": cvss_result.get("metrics", {}),
                    "payload_analysis": cvss_result.get("analysis", {}),
                }
            )

        findings.sort(key=lambda x: float(x.get("cvss_score", 0.0)), reverse=True)
        return findings

    def _calculate_cvss(self, attack_type: str, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if self.cvss_calculator is not None:
            try:
                return self.cvss_calculator.calculate_cvss(
                    attack_type=attack_type,
                    payload=payload,
                    context=context,
                )
            except Exception:
                pass

        fallback_scores = {
            "sql_injection": 7.1,
            "xss": 6.1,
            "command_injection": 9.8,
            "path_traversal": 6.5,
            "ssrf": 8.2,
        }
        score = fallback_scores.get(attack_type, 5.0)
        return {
            "cvss_score": score,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "severity": self._severity_from_cvss(score),
            "metrics": {},
            "analysis": {
                "payload_length": len(payload),
                "attack_type": attack_type,
                "context": context,
                "fallback": True,
            },
        }

    @staticmethod
    def _severity_from_cvss(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"

    @staticmethod
    def _candidate_fields(data: Dict[str, Any]) -> List[Dict[str, str]]:
        fields: List[Dict[str, str]] = []
        for key in (
            "email",
            "password",
            "username",
            "payload",
            "query",
            "input",
            "comment",
            "filename",
            "path",
            "body",
            "url",
            "endpoint",
        ):
            if key in data and data[key] is not None:
                fields.append({"field": key, "value": str(data[key])})
        return fields

    @staticmethod
    def _match_rule(rule: _Rule, fields: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        for item in fields:
            value = item["value"]
            for pattern in rule.patterns:
                match = pattern.search(value)
                if not match:
                    continue
                snippet = value[match.start() : match.end()][:200]
                return {
                    "field": item["field"],
                    "match": snippet,
                    "value": value,
                }
        return None

    @staticmethod
    def _is_stored_field(field_name: str) -> bool:
        return field_name.lower() in {"comment", "bio", "description", "message", "post", "review"}


class VulnerabilityDetector(EnhancedVulnerabilityDetector):
    """Backwards-compatible class alias."""

    pass

