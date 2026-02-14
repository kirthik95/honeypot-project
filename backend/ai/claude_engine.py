import importlib
import os
import requests
from typing import Any

from dotenv import load_dotenv

load_dotenv()

OPENAI_CLIENT_CLASS = None
OPENAI_AVAILABLE = False
try:
    openai_module = importlib.import_module("openai")
    OPENAI_CLIENT_CLASS = getattr(openai_module, "OpenAI", None)
    OPENAI_AVAILABLE = OPENAI_CLIENT_CLASS is not None
except Exception:
    OPENAI_AVAILABLE = False


class AIEngine:
    """
    Multi-tier AI threat analyzer with fallback support:
    1. OpenAI GPT-4 (cloud)
    2. Local LLM (Ollama/Mistral)
    3. Rule-based analysis (always available)
    """

    def __init__(self):
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.local_llm_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
        self.client = None

        # Initialize OpenAI client if available
        if OPENAI_AVAILABLE and self.openai_key and OPENAI_CLIENT_CLASS is not None:
            self.client = OPENAI_CLIENT_CLASS(api_key=self.openai_key)
            print("[OK] OpenAI client initialized")
        else:
            print("[WARN] OpenAI not available - using fallback methods")

    def analyze(self, detection: Any) -> str:
        """
        Analyze threat using multi-tier approach.
        
        Args:
            detection: Threat data (dict, string, or any object)
            
        Returns:
            Analysis string with severity, impact, and remediation
        """

        # 1️⃣ Try OpenAI first (most capable)
        if self.client:
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",  # Cost-effective model
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity threat analyst. Provide concise analysis with severity, impact, and mitigation."},
                        {"role": "user", "content": str(detection)}
                    ],
                    max_tokens=400,
                    temperature=0  # Deterministic for security analysis
                )
                return response.choices[0].message.content
            except Exception as e:
                print(f"[WARN] OpenAI failed: {e}")

        # 2️⃣ Try Local LLM (Ollama/Mistral)
        try:
            response = requests.post(
                self.local_llm_url,
                json={
                    "model": "mistral",
                    "prompt": f"Analyze this cyber threat and provide severity, impact, and mitigation: {detection}",
                    "stream": False  # Get complete response
                },
                timeout=10
            )
            if response.status_code == 200:
                result = response.json().get("response", "")
                if result:
                    return result
                print("[WARN] Local LLM returned empty response")
        except requests.exceptions.Timeout:
            print("[WARN] Local LLM timeout")
        except requests.exceptions.ConnectionError:
            print("[WARN] Local LLM not reachable")
        except Exception as e:
            print(f"[WARN] Local LLM failed: {e}")

        # 3️⃣ Fallback to rule-based explanation (always works)
        return self.rule_based_explanation(detection)

    def rule_based_explanation(self, detection: Any) -> str:
        """
        Fallback analysis when AI services are unavailable.
        
        Args:
            detection: Threat data
            
        Returns:
            Rule-based threat analysis
        """
        # Convert detection to dict if it's a string
        if isinstance(detection, str):
            detection_dict = {"raw": detection}
        elif isinstance(detection, dict):
            detection_dict = detection
        else:
            detection_dict = {"data": str(detection)}

        # Extract key information
        attack_type = detection_dict.get("attack_type", "unknown")
        severity = detection_dict.get("severity", "MEDIUM")
        cvss_score = detection_dict.get("cvss_score", 0.0)
        
        # Build analysis based on attack type
        analysis_templates = {
            "sql_injection": {
                "severity": "HIGH to CRITICAL",
                "impact": "Potential database compromise, data exfiltration, or unauthorized access to sensitive information.",
                "mitigation": "Implement parameterized queries (prepared statements), use ORM frameworks with built-in escaping, validate all user inputs server-side, apply principle of least privilege to database accounts, and deploy a Web Application Firewall (WAF)."
            },
            "xss": {
                "severity": "MEDIUM to HIGH",
                "impact": "Session hijacking, credential theft, malicious content injection, or phishing attacks against users.",
                "mitigation": "Implement output encoding/escaping, enforce Content Security Policy (CSP) headers, sanitize HTML inputs, use HTTPOnly and Secure flags on cookies, and validate all user-supplied data."
            },
            "command_injection": {
                "severity": "CRITICAL",
                "impact": "Remote code execution, full system compromise, data theft, or deployment of malware/backdoors.",
                "mitigation": "Never pass user input to system commands, use allowlists for input validation, employ safe APIs instead of shell commands, run applications with minimal privileges, and implement command execution sandboxing."
            },
            "path_traversal": {
                "severity": "MEDIUM to HIGH",
                "impact": "Unauthorized access to sensitive files, source code disclosure, or configuration file exposure.",
                "mitigation": "Normalize file paths, enforce allowlisted directories, reject traversal sequences (../, ..\\), use chroot jails, and validate file paths against a secure base directory."
            },
            "bot": {
                "severity": "LOW to MEDIUM",
                "impact": "Automated attacks, credential stuffing, data scraping, or distributed denial of service.",
                "mitigation": "Implement CAPTCHA, rate limiting, device fingerprinting, behavioral analysis, IP reputation checks, and account lockout policies after failed attempts."
            },
            "ssrf": {
                "severity": "HIGH",
                "impact": "Access to internal services, cloud metadata exposure, port scanning, or internal network reconnaissance.",
                "mitigation": "Block private IP ranges (RFC 1918), disable metadata service access (169.254.169.254), use allowlists for outbound requests, implement network segmentation, and validate URLs against a safe list."
            }
        }

        # Get template for detected attack type
        template = analysis_templates.get(attack_type, {
            "severity": severity,
            "impact": "Potential security compromise detected. Manual review recommended.",
            "mitigation": "Apply defense-in-depth principles: input validation, output encoding, least privilege, network segmentation, and continuous monitoring."
        })

        # Build formatted response
        analysis = f"""
╔══════════════════════════════════════════════════════════
║ THREAT ANALYSIS (Rule-Based)
╠══════════════════════════════════════════════════════════
║ Attack Type: {attack_type.upper().replace('_', ' ')}
║ Severity: {template['severity']}
║ CVSS Score: {cvss_score}
╠══════════════════════════════════════════════════════════
║ IMPACT:
║ {template['impact']}
╠══════════════════════════════════════════════════════════
║ RECOMMENDED MITIGATION:
║ {template['mitigation']}
╠══════════════════════════════════════════════════════════
║ NOTE: This is a rule-based analysis. For deeper insights,
║       enable OpenAI or local LLM integration.
╚══════════════════════════════════════════════════════════
"""
        return analysis.strip()


# Backward compatibility aliases
class ClaudeEngine(AIEngine):
    """Alias for compatibility with existing imports"""
    pass


# Example usage and testing
if __name__ == "__main__":
    # Test with different configurations
    
    # Test 1: Rule-based (always works)
    print("="*60)
    print("TEST 1: Rule-based analysis (no AI)")
    print("="*60)
    engine = AIEngine()
    
    test_detection = {
        "attack_type": "sql_injection",
        "severity": "HIGH",
        "cvss_score": 8.2,
        "payload": "' UNION SELECT password FROM users--"
    }
    
    result = engine.analyze(test_detection)
    print(result)
    print()
    
    # Test 2: Different attack types
    print("="*60)
    print("TEST 2: XSS Attack")
    print("="*60)
    
    xss_detection = {
        "attack_type": "xss",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "payload": "<script>alert(document.cookie)</script>"
    }
    
    result = engine.analyze(xss_detection)
    print(result)
    print()
    
    # Test 3: Command injection
    print("="*60)
    print("TEST 3: Command Injection")
    print("="*60)
    
    cmd_detection = {
        "attack_type": "command_injection",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "payload": "; rm -rf / #"
    }
    
    result = engine.analyze(cmd_detection)
    print(result)
    def rule_based_explanation(self, detection):
        threat_type = detection.get("web", {}).get("label", "unknown")

        explanations = {
            "sql_injection": "Detected SQL manipulation patterns indicating database injection attempt.",
            "xss": "Detected script-based payload indicating cross-site scripting attempt.",
            "command_injection": "Detected shell execution patterns suggesting command injection.",
            "path_traversal": "Detected directory traversal patterns targeting system paths."
        }

        return explanations.get(threat_type, "Threat detected based on anomaly analysis.")
