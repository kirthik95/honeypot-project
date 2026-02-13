import os
from typing import Any, Optional

class ClaudeEngine:
    def __init__(self):
        # Import lazily so the backend can still boot without the optional dependency.
        try:
            import anthropic  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "ClaudeEngine requires the optional 'anthropic' package. "
                "Add it to requirements.txt to enable Claude analysis."
            ) from e

        # ✅ FIX: Accept both ANTHROPIC_API_KEY and CLAUDE_API_KEY
        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY or CLAUDE_API_KEY is not set.")

        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key)

    def analyze(self, detection: Any) -> str:
        """Analyze threat using Claude AI"""
        prompt = f"""
You are a cybersecurity expert analyzing a detected threat.

Detection Data:
{detection}

Provide a concise analysis covering:
1. Threat severity (CRITICAL/HIGH/MEDIUM/LOW)
2. Potential impact on the system
3. Recommended mitigation steps

Keep response under 300 words and focus on actionable insights.
"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",  # ✅ Updated to latest model
                max_tokens=500,
                temperature=0,  # ✅ Deterministic for security analysis
                messages=[{"role": "user", "content": prompt}]
            )

            return response.content[0].text
        except Exception as e:
            return f"Claude analysis unavailable: {str(e)}"