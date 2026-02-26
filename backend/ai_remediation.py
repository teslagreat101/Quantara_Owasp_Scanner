"""
Quantum Protocol v5.0 — AI-Powered Remediation
Uses google-genai (new SDK) + OpenAI fallback for AI analysis and fix suggestions.

Phase 8.2: AI-Powered Remediation
"""

import os
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

# New google-genai SDK (replaces deprecated google-generativeai)
try:
    from google import genai as google_genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from openai import OpenAI as OpenAIClient
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic as anthropic_sdk
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# Preferred Gemini model order — newest first, with fallbacks
_GEMINI_MODELS = [
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-flash-latest",
]


@dataclass
class AIAnalysis:
    risk_explanation: str
    fix_suggestion: str
    code_patch: Optional[str]
    confidence: float  # 0.0 - 1.0
    references: list


class AIRemediationService:
    """AI-powered security analysis and remediation suggestions."""

    def __init__(self):
        self._init_providers()

    def _init_providers(self):
        """Initialize AI providers, reading keys fresh from environment."""
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        self._gemini_client = None
        self._gemini_model_name = None
        self._openai_client = None
        self._anthropic_client = None

        if GEMINI_AVAILABLE and self.api_key:
            try:
                self._gemini_client = google_genai.Client(api_key=self.api_key)
                self._gemini_model_name = _GEMINI_MODELS[0]
            except Exception as e:
                print(f"Gemini init failed: {e}")
                self._gemini_client = None

        if OPENAI_AVAILABLE and self.openai_key:
            try:
                self._openai_client = OpenAIClient(api_key=self.openai_key)
            except Exception as e:
                print(f"OpenAI init failed: {e}")
                self._openai_client = None

        if ANTHROPIC_AVAILABLE and self.anthropic_key:
            try:
                self._anthropic_client = anthropic_sdk.Anthropic(api_key=self.anthropic_key)
            except Exception as e:
                print(f"Anthropic init failed: {e}")
                self._anthropic_client = None

    def is_available(self) -> bool:
        """Check if any AI provider is available."""
        return (
            (GEMINI_AVAILABLE and bool(self.api_key) and self._gemini_client is not None)
            or (OPENAI_AVAILABLE and bool(self.openai_key) and self._openai_client is not None)
            or (ANTHROPIC_AVAILABLE and bool(self.anthropic_key) and self._anthropic_client is not None)
        )

    def _gemini_generate(self, prompt: str, system: str = "") -> str:
        """Call Gemini (new SDK) and return raw text. Raises on error."""
        contents = prompt
        config_kwargs = {}
        if system:
            config_kwargs["system_instruction"] = system

        # Try models in order until one works
        for model_name in _GEMINI_MODELS:
            try:
                response = self._gemini_client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config=google_genai.types.GenerateContentConfig(**config_kwargs) if config_kwargs else None,
                )
                self._gemini_model_name = model_name
                return response.text
            except Exception as e:
                err = str(e)
                # Hard-fail on auth errors — no point trying other models
                if "API_KEY_INVALID" in err or "PERMISSION_DENIED" in err or "UNAUTHENTICATED" in err:
                    raise
                # On quota exhaustion, bail out immediately and let OpenAI handle it
                if "RESOURCE_EXHAUSTED" in err or "429" in err:
                    raise RuntimeError(f"Gemini quota exceeded: {err[:200]}")
                print(f"Gemini model {model_name} failed: {e}, trying next…")
                continue

        raise RuntimeError("All Gemini models failed")

    def _openai_generate(self, prompt: str, system: str = "You are an expert security analyst.") -> str:
        """Call OpenAI and return raw text. Raises on error."""
        resp = self._openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        return resp.choices[0].message.content

    def _anthropic_generate(self, prompt: str, system: str = "You are an expert security analyst.") -> str:
        """Call Anthropic Claude and return raw text. Raises on error."""
        msg = self._anthropic_client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    def _generate(self, prompt: str, system: str = "You are an expert security analyst.") -> str:
        """Generate text — tries Gemini → OpenAI → Anthropic with automatic fallback."""
        if GEMINI_AVAILABLE and self._gemini_client is not None:
            try:
                return self._gemini_generate(prompt, system)
            except Exception as e:
                print(f"Gemini failed, trying OpenAI: {e}")

        if OPENAI_AVAILABLE and self._openai_client is not None:
            try:
                return self._openai_generate(prompt, system)
            except Exception as e:
                print(f"OpenAI failed, trying Anthropic: {e}")

        if ANTHROPIC_AVAILABLE and self._anthropic_client is not None:
            return self._anthropic_generate(prompt, system)

        raise RuntimeError("No AI providers available (check API keys and billing)")

    def analyze_finding(self, finding: Dict[str, Any]) -> AIAnalysis:
        """Analyze a security finding with AI and suggest fixes."""
        if not self.is_available():
            return self._mock_analysis(finding)

        try:
            prompt = self._build_analysis_prompt(finding)
            text = self._generate(prompt)
            return self._parse_ai_response(text)
        except Exception as e:
            print(f"AI analysis failed: {e}")
            return self._mock_analysis(finding)

    def _build_analysis_prompt(self, finding: Dict[str, Any]) -> str:
        """Build prompt for AI analysis."""
        return f"""Analyze this security vulnerability and provide remediation:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Category: {finding.get('category', 'Unknown')}
OWASP: {finding.get('owasp', 'Unknown')}
CWE: {finding.get('cwe', 'Unknown')}

Description:
{finding.get('description', 'No description')}

Matched Content:
{finding.get('matched_content', 'N/A')}

File: {finding.get('file', 'Unknown')}
Line: {finding.get('line_number', 0)}

Provide:
1. Risk explanation (why this is dangerous)
2. Fix suggestion (step-by-step)
3. Code patch example (if applicable)
4. References to learn more

Format as JSON with keys: risk_explanation, fix_suggestion, code_patch, confidence (0-1), references (list)"""

    def _parse_ai_response(self, response_text: str) -> AIAnalysis:
        """Parse AI response into structured analysis."""
        try:
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0].strip()
            else:
                json_str = response_text.strip()

            data = json.loads(json_str)

            return AIAnalysis(
                risk_explanation=data.get("risk_explanation", "No explanation provided"),
                fix_suggestion=data.get("fix_suggestion", "No fix suggestion"),
                code_patch=data.get("code_patch"),
                confidence=float(data.get("confidence", 0.8)),
                references=data.get("references", [])
            )
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            print(f"Failed to parse AI response: {e}")
            return AIAnalysis(
                risk_explanation=response_text[:500],
                fix_suggestion="See analysis above",
                code_patch=None,
                confidence=0.5,
                references=[]
            )

    def _mock_analysis(self, finding: Dict[str, Any]) -> AIAnalysis:
        """Generate mock analysis when AI is not available."""
        severity = finding.get('severity', 'medium').lower()
        title = finding.get('title', 'Unknown Issue')
        cwe = finding.get('cwe', '')

        risk_explanations = {
            'critical': f"This {title} represents a severe security vulnerability that could lead to complete system compromise, data breach, or unauthorized access to sensitive resources.",
            'high': f"This {title} poses significant security risk and should be addressed immediately to prevent potential exploitation.",
            'medium': f"This {title} could be exploited under certain conditions and should be fixed to improve security posture.",
            'low': f"This {title} is a minor security concern that should be addressed as part of regular security maintenance.",
        }

        return AIAnalysis(
            risk_explanation=risk_explanations.get(severity, risk_explanations['medium']),
            fix_suggestion=f"Review the code at the identified location and apply secure coding practices. Refer to {cwe} guidelines for specific remediation steps.",
            code_patch=None,
            confidence=0.7,
            references=[
                f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if cwe else "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/"
            ]
        )

    def chat_assistant(self, question: str, context: Optional[Dict] = None) -> str:
        """AI chat assistant for security questions."""
        if not self.is_available():
            return self._mock_chat_response(question)

        system = (
            "You are an expert application security analyst specializing in OWASP Top 10 "
            "vulnerabilities, secure coding, and penetration testing. "
            "Provide clear, actionable responses with code examples where relevant."
        )

        prompt = f"""Question: {question}

Context: {json.dumps(context, indent=2) if context else 'General security inquiry'}

Provide a clear, actionable response. When relevant, include:
- Root cause explanation
- Step-by-step remediation
- Code examples (before/after)
- References to OWASP or CVE resources"""

        try:
            return self._generate(prompt, system)
        except Exception as e:
            err = str(e)
            # Surface a clean, actionable message for billing/quota failures
            if "insufficient_quota" in err or "credit balance" in err.lower() or "RESOURCE_EXHAUSTED" in err:
                return (
                    "⚠️ All AI providers are currently out of quota or credits.\n\n"
                    "To restore AI Co-Pilot functionality, add credits to at least one provider:\n"
                    "• **Gemini**: https://aistudio.google.com/apikey — enable billing in your Google Cloud project\n"
                    "• **OpenAI**: https://platform.openai.com/account/billing — add credits\n"
                    "• **Anthropic**: https://console.anthropic.com/settings/billing — add credits\n\n"
                    "Once credits are available, restart the backend server and the Co-Pilot will resume."
                )
            return f"AI assistant temporarily unavailable. Error: {str(e)}"

    def _mock_chat_response(self, question: str) -> str:
        """Mock chat response when AI unavailable."""
        responses = {
            'sql injection': """SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query.

Prevention:
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Least privilege database accounts
- ORM frameworks with proper escaping

Example (Python/PostgreSQL):
```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```""",
            'xss': """Cross-Site Scripting (XSS) allows attackers to inject client-side scripts.

Prevention:
- Output encoding/escaping
- Content Security Policy (CSP)
- Input validation
- Use modern frameworks that auto-escape

Example:
```python
# BAD
html = f"<div>{user_input}</div>"

# GOOD
from html import escape
html = f"<div>{escape(user_input)}</div>"
```""",
        }

        question_lower = question.lower()
        for key, response in responses.items():
            if key in question_lower:
                return response

        return """I'm a security assistant (AI not configured - showing placeholder response).

Common security topics I can help with:
- SQL Injection prevention
- XSS (Cross-Site Scripting) protection
- Authentication best practices
- Secure API design
- OWASP Top 10 vulnerabilities

Please configure GEMINI_API_KEY for AI-powered responses."""

    def prioritize_risks(self, findings: list) -> list:
        """AI-powered risk prioritization — sorts findings by actual risk."""
        severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}

        def risk_score(finding):
            base_score = severity_order.get(finding.get('severity', 'medium').lower(), 3)
            confidence_boost = finding.get('confidence', 1.0) * 0.5
            return base_score + confidence_boost

        return sorted(findings, key=risk_score, reverse=True)


# Singleton instance — dotenv already loaded above at module level
ai_service = AIRemediationService()
