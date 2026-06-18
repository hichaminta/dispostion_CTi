import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import re
import json
import logging
import asyncio
try:
    from google import genai
except ImportError:
    genai = None
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("LeakAnalyzer")

class LeakAnalyzer:
    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "gemini").lower()
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
        
        if self.provider == "gemini" and self.gemini_key:
            self.client = genai.Client(api_key=self.gemini_key)
            logger.info("Using Gemini AI Provider")
        elif self.provider == "openai" and self.openai_key:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.openai_key)
            logger.info("Using OpenAI AI Provider")
        elif self.provider == "ollama":
            self.client = "ollama"
            logger.info(f"Using Ollama AI Provider ({self.ollama_model})")
        elif self.provider == "openrouter":
            self.openrouter_key = os.getenv("OPENROUTER_API_KEY")
            self.openrouter_model = os.getenv("OPENROUTER_MODEL", "google/gemini-3.5-flash")
            if self.openrouter_key:
                from openai import OpenAI
                self.client = OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=self.openrouter_key,
                )
                logger.info(f"Using OpenRouter AI Provider ({self.openrouter_model})")
            else:
                self.client = None
                logger.warning("OpenRouter API Key missing.")
        elif self.provider == "nebius":
            self.nebius_key = os.getenv("NEBIUS_API_KEY")
            self.nebius_model = os.getenv("NEBIUS_MODEL", "meta-llama/Llama-3.3-70B-Instruct")
            if self.nebius_key:
                from openai import OpenAI
                self.client = OpenAI(
                    base_url="https://api.studio.nebius.ai/v1/",
                    api_key=self.nebius_key,
                )
                logger.info(f"Using Nebius AI Provider ({self.nebius_model})")
            else:
                self.client = None
                logger.warning("Nebius API Key missing.")
        else:
            self.client = None
            logger.warning(f"AI Provider {self.provider} not fully configured. Falling back to Regex.")

    async def test_connection(self):
        """Tests the connection to the selected AI provider."""
        logger.info(f"Testing connection to {self.provider}...")
        try:
            test_prompt = "Say 'OK'"
            res = await self._query_ai(test_prompt)
            if res:
                logger.info(f"AI Provider {self.provider} is ONLINE and working.")
                return True
            else:
                logger.error(f"AI Provider {self.provider} returned NO response.")
                return False
        except Exception as e:
            logger.error(f"LLM ERROR: Could not connect to {self.provider}: {e}")
            return False

    async def _query_ai(self, prompt):
        """Unified query method for different AI providers with automatic retry & exponential backoff."""
        max_retries = 3
        backoff_factor = 2.0
        
        for attempt in range(1, max_retries + 1):
            try:
                if self.provider == "gemini" and self.gemini_key:
                    response = self.client.models.generate_content(
                        model='gemini-1.5-flash',
                        contents=prompt
                    )
                    return response.text
                elif self.provider == "openai" and self.openai_key:
                    response = self.client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}],
                        response_format={ "type": "json_object" } if "JSON" in prompt else None
                    )
                    return response.choices[0].message.content
                elif self.provider == "ollama":
                    import requests
                    response = requests.post(
                        self.ollama_url,
                        json={
                            "model": self.ollama_model,
                            "prompt": prompt,
                            "stream": False,
                            "format": "json"
                        },
                        timeout=90
                    )
                    return response.json().get("response")
                elif self.provider == "openrouter" and self.client:
                    response = self.client.chat.completions.create(
                        model=self.openrouter_model,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=1024,
                        response_format={ "type": "json_object" } if "JSON" in prompt else None
                    )
                    return response.choices[0].message.content
                elif self.provider == "nebius" and self.client:
                    response = self.client.chat.completions.create(
                        model=self.nebius_model,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=1024,
                        response_format={ "type": "json_object" } if "JSON" in prompt else None
                    )
                    return response.choices[0].message.content
                return None
            except Exception as e:
                logger.warning(f"AI query attempt {attempt}/{max_retries} failed for {self.provider}: {e}")
                if attempt == max_retries:
                    logger.error(f"AI query failed after {max_retries} attempts: {e}")
                    return None
                sleep_time = backoff_factor ** attempt
                await asyncio.sleep(sleep_time)

    def extract_patterns(self, text):
        """Extracts basic patterns using Regex."""
        patterns = {
            "emails": list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))),
            "ips": list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))),
            "urls": list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text))),
            "credentials": list(set(re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+\b', text)))
        }
        return patterns

    async def analyze_leak(self, text, file_context=None):
        """Analyzes the leak text using AI or Regex fallback."""
        extracted = self.extract_patterns(text)
        
        analysis = {
            "is_leak": False,
            "severity": "low",
            "leak_type": "unknown",
            "summary": "No AI analysis available",
            "targets": [],
            "confidence": 50,
            "entities": extracted
        }

        # Basic check for entities
        if any(extracted.values()):
            analysis["is_leak"] = True
            analysis["confidence"] = 70

        if not text and not file_context:
            return analysis

        if self.client:
            try:
                context_str = f"\nFile Sample: {file_context[:1000]}" if file_context else ""
                prompt = f"""
                Analyze the following data leak message and associated file content.
                Your task is to identify CORPORATE, BUSINESS, or GOVERNMENT data leaks.
                
                CRITERIA:
                1. IS A LEAK IF: Contains enterprise data, company employee lists, corporate credentials, business databases, PII from customers (Nom, Prénom, CIN, Téléphone, Adresse, etc.), or any structured data that looks like a database export.
                2. SENSITIVITY: If a file sample is provided, be EXTRA SENSITIVE. If you see emails, names, numbers, or structured lines, mark it as a leak (is_leak: true).
                3. IS NOT A LEAK IF: Purely political news, religious content, public propaganda, general chat, or generic system messages WITHOUT any attached files or data patterns.
                
                SPECIAL INSTRUCTIONS:
                - FILE CONTENT IS KEY: Even if the Telegram message is vague, if the 'File Sample' contains structured data (CSVs, logs, SQL), it IS A LEAK.
                - POLITICAL FILTER: If the message contains political rhetoric BUT also includes a database or credentials, IT IS A LEAK. Focus the summary on the DATA.
                - OUTPUT: Respond ONLY in valid JSON format with these keys:
                {{
                    "is_leak": boolean,
                    "severity": "low|medium|high|critical",
                    "leak_type": "Database|Credentials|PII|Corporate_Secret|Other",
                    "summary": "Short summary in French (max 2 sentences), focusing strictly on the exfiltrated data.",
                    "targets": ["Company or Organization name"],
                    "confidence": number
                }}

                Message text: {text[:1500]}
                {context_str}
                """
                ai_text = await self._query_ai(prompt)
                if ai_text:
                    ai_data = self._parse_ai_json(ai_text)
                    if ai_data and isinstance(ai_data, dict):
                        # Extra validation: ensure it's not a false positive for purely political content
                        if not ai_data.get("is_leak") and ("politique" in ai_text.lower() or "guerre" in ai_text.lower()):
                             logger.info("Message confirmed as purely political/noise.")
                        analysis.update(ai_data)
            except Exception as e:
                logger.error(f"AI Analysis failed: {e}")

        # Final severity adjustments based on findings
        if extracted["credentials"]:
            analysis["severity"] = self._max_severity(analysis["severity"], "high")
            analysis["leak_type"] = "Credentials/Stealer"
        
        return analysis

    def _parse_ai_json(self, text):
        try:
            clean_text = text.strip()
            # Try to find JSON block if markdown is used
            json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', clean_text, re.DOTALL | re.IGNORECASE)
            if json_match:
                clean_text = json_match.group(1).strip()
            
            # Find the first { or [ and the last } or ]
            start_idx = -1
            end_idx = -1
            for i, char in enumerate(clean_text):
                if char in ('{', '['):
                    start_idx = i
                    break
            for i in range(len(clean_text)-1, -1, -1):
                if clean_text[i] in ('}', ']'):
                    end_idx = i
                    break
            
            if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
                clean_text = clean_text[start_idx:end_idx+1]
                
            return json.loads(clean_text)
        except Exception as e:
            logger.debug(f"JSON Parse failed: {e}\nText was: {text[:200]}...")
            return None

    def _max_severity(self, s1, s2):
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return s1 if order.get(s1, 0) >= order.get(s2, 0) else s2
