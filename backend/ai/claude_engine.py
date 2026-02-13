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

        api_key = os.getenv("CLAUDE_API_KEY")
        if not api_key:
            raise RuntimeError("CLAUDE_API_KEY is not set.")

        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key)

    def analyze(self, detection: Any) -> str:
        prompt = f"""
        Analyze this cyber threat:
        {detection}
        Provide severity, impact, and mitigation.
        """

        response = self.client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text
