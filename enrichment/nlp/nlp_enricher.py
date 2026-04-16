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
            "lucastealer", "xworm", "tofsee", "stealc", "valleyrat", "lumma",
            "stealc", "meduza", "mars", "aurora", "arcei", "asyncrat", "warzone"
        ]

        # Concise list of countries for fast Regex matching
        self.global_known_countries = [
            "afghanistan", "albania", "algeria", "andorra", "angola", "argentina", "armenia", "australia", "austria", "azerbaijan",
            "bahamas", "bahrain", "bangladesh", "barbados", "belarus", "belgium", "belize", "benin", "bhutan", "bolivia",
            "brazil", "bulgaria", "burkina faso", "burundi", "cambodia", "cameroon", "canada", "chad", "chile", "china",
            "colombia", "congo", "costa rica", "croatia", "cuba", "cyprus", "czechia", "denmark", "djibouti", "dominica",
            "ecuador", "egypt", "estonia", "ethiopia", "fiji", "finland", "france", "gabon", "gambia", "georgia", "germany",
            "ghana", "greece", "guatemala", "guinea", "guyana", "haiti", "honduras", "hungary", "iceland", "india", "indonesia",
            "iran", "iraq", "ireland", "israel", "italy", "jamaica", "japan", "jordan", "kazakhstan", "kenya", "kuwait",
            "kyrgyzstan", "laos", "latvia", "lebanon", "lesotho", "liberia", "libya", "lithuania", "luxembourg", "madagascar",
            "malaysia", "maldives", "mali", "malta", "mexico", "moldova", "monaco", "mongolia", "montenegro", "morocco",
            "myanmar", "namibia", "nepal", "netherlands", "new zealand", "nicaragua", "niger", "nigeria", "north korea",
            "norway", "oman", "pakistan", "palau", "panama", "paraguay", "peru", "philippines", "poland", "portugal", "qatar",
            "romania", "russia", "rwanda", "saudi arabia", "senegal", "serbia", "seychelles", "sierra leone", "singapore",
            "slovakia", "slovenia", "somalia", "south africa", "south korea", "spain", "sri lanka", "sudan", "suriname",
            "sweden", "switzerland", "syria", "taiwan", "tajikistan", "tanzania", "thailand", "togo", "tonga", "tunisia",
            "turkey", "turkmenistan", "uganda", "ukraine", "uae", "united arab emirates", "uk", "united kingdom", "usa",
            "united states", "uruguay", "uzbekistan", "vanuatu", "venezuela", "vietnam", "yemen", "zambia", "zimbabwe"
        ]

        # Pre-compile fast regex for all keywords
        self._re_categories = re.compile(r'\b(' + '|'.join(self.global_threat_categories) + r')\b', re.IGNORECASE)
        self._re_families = re.compile(r'\b(' + '|'.join(self.global_known_families) + r')\b', re.IGNORECASE)
        self._re_countries = re.compile(r'\b(' + '|'.join(self.global_known_countries) + r')\b', re.IGNORECASE)

        # Context indicators for attacker/source vs victim/target
        self.context_indicators_attacker = ["attacker", "threat actor", "source", "origin", "distributed by", "delivered by"]
        self.context_indicators_victim = ["victim", "target", "affected", "patient zero", "impacted", "vulnerable"]

        # Entity Databases for keyword matching refinement
        self.known_products = [
            "windows", "office", "exchange", "adobe", "reader", "acrobat", "chrome", "firefox", 
            "linux", "vmware", "fortinet", "cisco", "atlassian", "confluence", "jira", "apache",
            "nginx", "mysql", "postgresql", "wordpress", "magento", "android", "ios"
        ]

        # Sources that contain descriptive narrative text (High NLP value)
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
            # CVEs (Regex)
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
                            extracted["locations"].add(entity_name.lower())
            
            # Manual Product Check
            text_lower = text.lower()
            for p in self.known_products:
                if re.search(r'\b' + re.escape(p) + r'\b', text_lower):
                    extracted["products"].add(p)
            
            # NEW: Add Regex Countries for robustness
            countries_found = self._re_countries.findall(text_lower)
            for c in countries_found:
                extracted["locations"].add(c.lower())
                    
        except Exception as e:
            self.logger.warning(f"Advanced entity extraction failed: {e}")
            
        return extracted

    def _attribute_findings(self, text: str, iocs: list, use_nltk: bool = True):
        """
        Splits text into sentences and attributes found entities/categories 
        to the IOCs mentioned in the same sentence.
        """
        sentences = []
        if use_nltk and self.nltk_enabled:
            try: sentences = sent_tokenize(text)
            except: sentences = self._regex_sent_tokenize(text)
        else:
            sentences = self._regex_sent_tokenize(text)
        
        for sent in sentences:
            sent_lower = sent.lower()
            # 1. Identify which IOCs are in this sentence
            local_iocs = []
            for ioc in iocs:
                val = str(ioc.get("value"))
                if val and val.lower() in sent_lower:
                    local_iocs.append(ioc)
            
            if not local_iocs:
                continue
                
            # 2. Extract findings using fast regex
            categories = list(set(self._re_categories.findall(sent_lower)))
            families = list(set(self._re_families.findall(sent_lower)))
            countries = list(set(self._re_countries.findall(sent_lower)))
            
            # Organizations/Products require NER or full pass (Optional for speed)
            entities = {"organizations": set(), "locations": set(countries), "products": set()}
            if use_nltk and self.nltk_enabled:
                entities = self._extract_entities_advanced(sent)
                locations = list(entities.get("locations", []))
            else:
                locations = countries
            
            # 3. Attribute to local IOCs
            for ioc in local_iocs:
                if "ioc_enrichment" not in ioc:
                    ioc["ioc_enrichment"] = {}
                
                enr = ioc["ioc_enrichment"]
                # Categories
                existing_cats = enr.get("threat_categories", [])
                enr["threat_categories"] = sorted(list(set(existing_cats + categories)))
                # Family
                if families and not enr.get("malware_family"):
                    enr["malware_family"] = families[0]
                # Geography
                existing_geo = enr.get("geography", [])
                enr["geography"] = sorted(list(set(existing_geo + locations)))

    def enrich(self, data: dict) -> dict:
        """
        Main entry point for enrichment. 
        Detects source type to choose between Fast (Regex) and Advanced (NLTK) mode.
        """
        enriched_data = data.copy()
        raw_text = data.get("raw_text", "")
        summary_text = data.get("summary", "")
        full_text = f"{summary_text} {raw_text}".strip()
        
        if "enrichment" not in enriched_data:
            enriched_data["enrichment"] = {}

        source_name = data.get("source", "").lower()
        is_narrative = any(s in source_name for s in self.narrative_sources)
        iocs = enriched_data.get("iocs", [])
        
        # 1. Fast Regex categorization & entities (Runs for everyone)
        text_lower = full_text.lower()
        detected_categories = set(self._re_categories.findall(text_lower))
        detected_families = set(self._re_families.findall(text_lower))
        detected_countries = set(self._re_countries.findall(text_lower))
        
        # 2. Advanced NLTK (Only for narrative sources)
        entities = {"organizations": set(), "locations": detected_countries, "products": set(), "cves": set()}
        role_info = {"role": "neutral"}
        
        if is_narrative:
            # Heavy NLTK pass
            entities = self._extract_entities_advanced(full_text)
            main_indicator = data.get("indicator") or data.get("id")
            if main_indicator:
                role_info = self._analyze_context_advanced(full_text, main_indicator)
            
            # Summarization
            if len(full_text) > 500:
                enriched_data["enrichment"]["nlp_summary"] = self._get_summary(full_text)

        # 3. IOC-Centric Semantic Attribution
        # Rule: Every finding must belong to an IOC.
        if iocs:
            # First pass: Detailed sentence-level attribution
            self._attribute_findings(full_text, iocs, use_nltk=is_narrative)
            
            # Second pass: If it's a simple record (e.g. AbuseIPDB) or some findings 
            # are still global only, propagate them to all IOCs as they likely define the context.
            for ioc in iocs:
                if "ioc_enrichment" not in ioc:
                    ioc["ioc_enrichment"] = {}
                enr = ioc["ioc_enrichment"]
                
                # Global categories
                enr["threat_categories"] = sorted(list(set(enr.get("threat_categories", []) + list(detected_categories))))
                # Global families
                if not enr.get("malware_family") and detected_families:
                    enr["malware_family"] = list(detected_families)[0]
                # Global countries (if it's a technical source, they are already there, but we add NLP ones)
                enr["geography"] = sorted(list(set(enr.get("geography", []) + list(entities.get("locations", [])))))
                
                # Set explicit 'country' field if missing
                if not enr.get("country") and enr["geography"]:
                    enr["country"] = enr["geography"][0]

        # 4. Consolidate Global Tags (Derived from IOC context)
        all_ioc_findings = set()
        for ioc in iocs:
            enr = ioc.get("ioc_enrichment", {})
            all_ioc_findings.update(enr.get("threat_categories", []))
            all_ioc_findings.update(enr.get("geography", []))
            if enr.get("malware_family"):
                all_ioc_findings.add(enr.get("malware_family"))

        existing_tags = set(enriched_data.get("tags", []))
        existing_tags.update(all_ioc_findings)
        if role_info.get("role") != "neutral":
            existing_tags.add(f"context:{role_info['role']}")
        
        enriched_data["tags"] = sorted(list(existing_tags))
        
        # Update Record-level metadata for backward compatibility but primary info is in IOCs
        if detected_families:
            enriched_data["enrichment"]["malware_family"] = list(detected_families)[0]
            
        enriched_data["enrichment"]["nlp_extracted"] = {
            "malware_families": list(detected_families),
            "threat_categories": sorted(list(detected_categories))
        }

        enriched_data["enrichment"]["nlp_advanced"] = {
            "organizations": sorted(list(entities.get("organizations", []))),
            "geography": sorted(list(entities.get("locations", []))),
            "affected_products": sorted(list(entities.get("products", []))),
            "cves": sorted(list(entities.get("cves", []))),
            "indicator_role": role_info
        }

        return enriched_data

