import re
from together import Together
from data_sources.nist import NIST
from data_sources.mitre import MITRE
from utils.config import CONFIG
from utils.logger import log_info, log_error

class AgentBando:
    def __init__(self):
        self.client = Together(api_key=CONFIG["together_api_key"])
        self.nist = NIST()
        self.mitre = MITRE()

    def process_query(self, user_query):
        log_info(f"Processing query: {user_query}")
        query_lower = user_query.lower()
        results = []
        context_data = {}

        # Parse query for CVE or MITRE technique
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', query_lower, re.IGNORECASE)
        technique_match = re.search(r'T\d{4}', query_lower)
        keyword = self._extract_keyword(query_lower)

        if cve_match:
            cve_id = cve_match.group(0).upper()  # Normalize to uppercase
            log_info(f"Detected CVE: {cve_id}")
            context_data = self.nist.get_cve(cve_id)
            if "error" not in context_data:
                results.append(context_data)
        elif technique_match:
            technique_id = technique_match.group(0)
            log_info(f"Detected MITRE technique: {technique_id}")
            context_data = self.mitre.get_technique(technique_id)
            if "error" not in context_data:
                results.append(context_data)
        elif keyword:
            log_info(f"Detected keyword: {keyword}")
            context_data = self.nist.search_cve(keyword)
            if not isinstance(context_data, dict) or "error" not in context_data:
                results.extend(context_data)

        # Handle no results
        if not results:
            log_error(f"No results for query: {user_query}")
            return {"error": "No results found or invalid query"}

        # Summarize with LLM
        context_str = self._format_context(results)
        log_info(f"Context for LLM: {context_str}")
        response = self.client.chat.completions.create(
            model="togethercomputer/Refuel-Llm-V2-Small",
            messages=[
                {
                    "role": "system",
                    "content": "You are Agent-Bando, a SOC assistant. Summarize security data concisely."
                },
                {
                    "role": "user",
                    "content": f"Query: {user_query}\nContext: {context_str}\nSummarize in a clear, actionable way."
                }
            ]
        )
        summary = response.choices[0].message.content
        log_info(f"LLM summary: {summary}")
        return {"results": results, "summary": summary}

    def _extract_keyword(self, query):
        stop_words = {"for", "in", "on", "latest", "show"}
        words = query.lower().split()
        return next((w for w in words if w not in stop_words and not re.match(r'CVE-\d{4}-\d{4,7}|T\d{4}', w, re.IGNORECASE)), None)

    def _format_context(self, results):
        formatted = []
        for item in results:
            if "cve_id" in item:
                formatted.append(
                    f"CVE: {item['cve_id']}, Description: {item['description']}, "
                    f"Severity: {item['severity']}, Impact: {item['impact']}, "
                    f"Published: {item['published']}"
                )
            else:
                formatted.append(
                    f"Technique: {item['id']}, Name: {item['name']}, "
                    f"Description: {item['description']}, Tactic: {item['tactic']}"
                )
        return "\n".join(formatted)