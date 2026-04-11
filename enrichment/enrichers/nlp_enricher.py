import re
import json
import logging
from collections import Counter
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
from nltk.stem import WordNetLemmatizer
from .base_enricher import BaseEnricher

class NLPEnricher(BaseEnricher):
    """
    Advanced NLP Enricher using NLTK for Named Entity Recognition (NER), 
    POS tagging for context analysis, and extractive summarization.
    """

    def _bootstrap_nltk(self):
        """Ensures all required NLTK datasets are downloaded. Sets a flag if offline."""
        self.nltk_enabled = True
        resources = [
            'punkt', 
            'averaged_perceptron_tagger', 
            'maxent_ne_chunker', 
            'words', 
            'wordnet'
        ]
        for res in resources:
            try:
                # Check if resource exists or attempt silent download
                nltk.download(res, quiet=True, raise_on_error=True)
            except Exception as e:
                logging.warning(f"NLTK Resource '{res}' unavailable (Offline?). Switching to Basic Mode. Error: {e}")
                self.nltk_enabled = False
                break

    def _regex_tokenize(self, text: str) -> list:
        """Fallback word tokenizer using regex."""
        return re.findall(r'\b\w+\b', text.lower())

    def _regex_sent_tokenize(self, text: str) -> list:
        """Fallback sentence tokenizer using regex."""
        return re.split(r'(?<=[.!?])\s+', text)

    def __init__(self):
        super().__init__("NLPEnricher")
        
        # 1. Bootstrap NLTK resources
        self._bootstrap_nltk()
        
        # 2. Initialize NLTK tools
        self.lemmatizer = WordNetLemmatizer()
        
        # Global keywords (standardized for categorization)
        self.global_threat_categories = [
            "trojan", "ransomware", "miner", "coinminer", "worm", "botnet",
            "spyware", "adware", "downloader", "dropper", "phishing",
            "backdoor", "keylogger", "rootkit", "exploit", "hacktool",
            "stealer", "infostealer", "rat", "banker", "c2", "bruteforce", 
            "scanning", "spam", "malware"
        ]

        self.global_known_families = [
            "amadey", "cobaltstrike", "darkgate", "vidar", "redline",
            "smokeloader", "remcos", "agenttesla", "emotet", "trickbot",
            "qakbot", "icedid", "formbook", "lokibot", "nanocore",
            "njrat", "stop", "glassworm", "rhadamanthys", "hawkeye", 
            "lucastealer", "xworm", "tofsee", "stealc", "valleyrat", "lumma"
        ]

        # Context indicators for attacker/source vs victim/target
        self.context_indicators_attacker = ["attacker", "threat actor", "source", "origin", "distributed by", "delivered by"]
        self.context_indicators_victim = ["victim", "target", "affected", "patient zero", "impacted", "vulnerable"]

        # Entity Databases for keyword matching refinement
        self.known_products = [
            "windows", "office", "exchange", "adobe", "reader", "acrobat", "chrome", "firefox", 
            "linux", "vmware", "fortinet", "cisco", "atlassian", "confluence", "jira", "apache",
            "nginx", "mysql", "postgresql", "wordpress", "magento", "android", "ios"
        ]

        # Sources that contain descriptive narrative text (High NPV)
        self.narrative_sources = ["alienvault", "virustotal"]

    def _get_summary(self, text: str, num_sentences: int = 2) -> str:
        """
        Extractive summarization based on word frequency.
        """
        if not text or len(text) < 300: # Don't summarize short text
            return text
            
        try:
            sentences = sent_tokenize(text) if self.nltk_enabled else self._regex_sent_tokenize(text)
            if len(sentences) <= num_sentences:
                return text
                
            words = word_tokenize(text.lower()) if self.nltk_enabled else self._regex_tokenize(text)
            # Simple frequency map
            freq_table = Counter(w for w in words if len(w) > 3)
            
            # Score sentences
            sent_scores = {}
            for i, sent in enumerate(sentences):
                for word, freq in freq_table.items():
                    if word in sent.lower():
                        sent_scores[i] = sent_scores.get(i, 0) + freq
            
            # Get top sentences in original order
            top_sent_indices = sorted(sent_scores, key=sent_scores.get, reverse=True)[:num_sentences]
            summary = " ".join([sentences[i] for i in sorted(top_sent_indices)])
            return summary
        except Exception as e:
            self.logger.debug(f"Summarization failed: {e}")
            return text[:500] + "..."

    def _analyze_context_advanced(self, text: str, entity: str) -> dict:
        """
        Uses POS tagging and token proximity to determine the role of a technical entity.
        Returns a role: 'attacker', 'victim', or 'neutral'.
        """
        res = {"role": "neutral", "confidence": 0.5}
        if not self.nltk_enabled:
            # Simple keyword proximity in basic mode
            text_lower = text.lower()
            for k in self.context_indicators_attacker:
                if k in text_lower: return {"role": "attacker", "confidence": 0.6}
            return res

        try:
            tokens = word_tokenize(text)
            tagged = pos_tag(tokens)
            
            # Find entity position in tokens
            entity_idx = -1
            for i, (word, tag) in enumerate(tagged):
                if entity.lower() in word.lower():
                    entity_idx = i
                    break
            
            if entity_idx == -1: return res
            
            # Look at a window of tokens around the entity
            window_size = 8
            start = max(0, entity_idx - window_size)
            end = min(len(tagged), entity_idx + window_size)
            snippet = tagged[start:end]
            
            # Heuristics:
            # 1. Check for specific context keywords
            snippet_text = " ".join([w.lower() for w, t in snippet])
            for k in self.context_indicators_attacker:
                if k in snippet_text:
                    return {"role": "attacker", "confidence": 0.8}
            for k in self.context_indicators_victim:
                if k in snippet_text:
                    return {"role": "victim", "confidence": 0.8}
            
            # 2. Grammar check: Is it a subject (NNP/NN) followed by an active verb?
            # Very simple heuristic for 'Attacker' role
            for i in range(len(snippet)-1):
                word, tag = snippet[i]
                next_word, next_tag = snippet[i+1]
                if entity.lower() in word.lower() and next_tag.startswith('VB'): # Verb following entity
                    if next_word.lower() in ["attacks", "scans", "targets", "drops", "infests", "connects"]:
                        return {"role": "attacker", "confidence": 0.7}
                        
            return res
        except Exception:
            return res

    def _extract_entities_advanced(self, text: str) -> dict:
        """
        Uses NLTK's Named Entity Recognition (NER).
        """
        extracted = {"organizations": set(), "locations": set(), "products": set()}
        try:
            # First pass: Regex for technical IOCs (remains legacy fallback for speed)
            # CVEs
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
            extracted["cves"] = set(c.upper() for c in cves)
            
            # NLTK NER
            if self.nltk_enabled:
                tokens = word_tokenize(text)
                tagged = pos_tag(tokens)
                tree = ne_chunk(tagged)
                
                for subtree in tree:
                    if isinstance(subtree, nltk.Tree):
                        entity_name = " ".join([word for word, tag in subtree.leaves()])
                        entity_type = subtree.label()
                        
                        if entity_type == 'ORGANIZATION':
                            if len(entity_name) > 2: extracted["organizations"].add(entity_name)
                        elif entity_type in ['GPE', 'LOCATION']:
                            extracted["locations"].add(entity_name)
            
            # Manual Product Check (using lemmatization)
            text_lower = text.lower()
            for p in self.known_products:
                if re.search(r'\b' + re.escape(p) + r'\b', text_lower):
                    extracted["products"].add(p)
                    
        except Exception as e:
            self.logger.warning(f"Advanced entity extraction failed: {e}")
            
        return extracted

    def enrich(self, data: dict) -> dict:
        """
        Main entry point for enrichment.
        """
        enriched_data = data.copy()
        raw_text = data.get("raw_text", "")
        summary_text = data.get("summary", "")
        full_text = f"{summary_text} {raw_text}".strip()
        
        if "enrichment" not in enriched_data:
            enriched_data["enrichment"] = {}

        # 1. Advanced NER and Technical Extraction (Only for narrative sources)
        source_name = data.get("source", "").lower()
        is_narrative = any(s in source_name for s in self.narrative_sources)
        
        entities = {"organizations": set(), "locations": set(), "products": set(), "cves": set()}
        if is_narrative:
            entities = self._extract_entities_advanced(full_text)
        
        # 2. Context Analysis (Only if narrative)
        main_indicator = data.get("indicator") or data.get("id")
        role_info = {"role": "neutral"}
        if is_narrative and main_indicator:
            role_info = self._analyze_context_advanced(full_text, main_indicator)

        # 3. Categorization (Lemmatized) - Always done as it's keyword based
        detected_categories = set()
        if self.nltk_enabled:
            words = [self.lemmatizer.lemmatize(w.lower()) for w in word_tokenize(full_text)]
        else:
            words = self._regex_tokenize(full_text)
            
        for cat in self.global_threat_categories:
            if cat in words:
                detected_categories.add(cat)
        
        for fam in self.global_known_families:
            if fam in words:
                enriched_data["enrichment"]["malware_family"] = fam

        # 4. Summarization (Only if long and narrative)
        if is_narrative and len(full_text) > 500:
            enriched_data["enrichment"]["nlp_summary"] = self._get_summary(full_text)

        # 5. Consolidate Tags
        existing_tags = set(enriched_data.get("tags", []))
        existing_tags.update(detected_categories)
        existing_tags.update(entities.get("locations", []))
        if role_info["role"] != "neutral":
            existing_tags.add(f"context:{role_info['role']}")
        
        enriched_data["tags"] = sorted(list(existing_tags))
        
        # Populate structured enrichment block (Legacy support for Dashboard)
        enriched_data["enrichment"]["nlp_extracted"] = {
            "malware_families": [enriched_data["enrichment"].get("malware_family")] if enriched_data["enrichment"].get("malware_family") else [],
            "threat_categories": sorted(list(detected_categories))
        }

        # Premium structured data block
        enriched_data["enrichment"]["nlp_advanced"] = {
            "organizations": sorted(list(entities.get("organizations", []))),
            "geography": sorted(list(entities.get("locations", []))),
            "affected_products": sorted(list(entities.get("products", []))),
            "cves": sorted(list(entities.get("cves", []))),
            "indicator_role": role_info
        }

        return enriched_data

