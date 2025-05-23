from dataclasses import dataclass
from typing import List, Dict, Any
from utils.logger import log_info, log_error
from together import Together
import os
from dotenv import load_dotenv
import json
import re

load_dotenv()

@dataclass
class Result:
    cve_id: str
    description: str
    severity: str
    impact: float
    exploitability: float
    exploit_available: str
    published: str
    affected: List[str]
    references: List[str]
    mitre_techniques: List[Dict[str, str]]

class AgentBando:
    def __init__(self):
        self.client = Together(api_key=os.getenv("TOGETHER_API_KEY"))

    def process_query(self, query: str) -> Dict[str, Any]:
        log_info(f"Processing query: {query}")
        try:
            # Simplified prompt with explicit field requirements
            prompt = f"""
For CVE ID {query}, provide a response in two parts, separated by '---':

1. **Summary**: A complete Markdown summary with the following sections:
   - **Description**: Vulnerability details, attack vector, mitigation
   - **Severity**: CVSS score, exploit availability
   - **Affected**: Up to 10 affected products/vendors
   - **MITRE ATT&CK**: Relevant techniques
   - **Threat Actors**: Known actors or exploitation status
   - **Bug Bounty**: Bounty details if available
   - **Recent News**: News or industry impact
   - **Next Steps**: SOC team actions
   - **Missing Data**: Note any gaps
   Use bullet points for each section.

2. **Table Data**: A valid JSON object with:
   - cve_id: string
   - description: string
   - severity: string (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
   - impact: float (CVSS score, 0.0-10.0)
   - exploitability: float (0.0-10.0)
   - exploit_available: string (Yes/No)
   - published: string (YYYY-MM-DD or Unknown)
   - affected: array of strings (product names, max 10)
   - references: array of URLs
   - mitre_techniques: array of {{id, name}}

Wrap JSON in ```json ```. Ensure all fields are included, using defaults if data is unavailable.

Example:
## {query} Summary
- **Description**: Example vulnerability... Attack vector: Remote. Mitigation: Patch.
- **Severity**: CVSS 8.1, exploits available.
- **Affected**: Product A, Product B
- **MITRE ATT&CK**: T1190: Exploit Public-Facing Application
- **Threat Actors**: None known
- **Bug Bounty**: None
- **Recent News**: None
- **Next Steps**: Patch systems, monitor logs
- **Missing Data**: Threat actor details
---
```json
{{
    "cve_id": "{query}",
    "description": "Example vulnerability...",
    "severity": "HIGH",
    "impact": 8.1,
    "exploitability": 2.8,
    "exploit_available": "Yes",
    "published": "2024-07-01",
    "affected": ["Product A", "Product B"],
    "references": ["https://nvd.nist.gov/vuln/detail/{query}"],
    "mitre_techniques": [
        {{"id": "T1190", "name": "Exploit Public-Facing Application"}}
    ]
}}
```
"""
            try:
                response = self.client.completions.create(
                    model="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",  # Updated to Meta Llama model
                    prompt=prompt,
                    max_tokens=1800,  # Increased for complete responses
                    temperature=0.5
                )
                response_text = response.choices[0].text.strip()
                log_info(f"Full API response: {response_text}")

                # Split response
                try:
                    summary, json_data = response_text.split("---", 1)
                    summary = summary.strip()
                    json_data = json_data.strip()
                    log_info(f"Raw summary: {summary}")
                except ValueError:
                    log_error("No '---' separator found")
                    raise ValueError("Invalid response format")

                # Extract JSON
                json_match = re.search(r'```json\s*\n([\s\S]*?)\n```', json_data, re.MULTILINE)
                if json_match:
                    json_str = json_match.group(1).strip()
                else:
                    log_error("No JSON block found")
                    raise ValueError("No JSON block")

                # Parse JSON
                try:
                    table_data = json.loads(json_str)
                    log_info(f"Parsed table data: {table_data}")
                except json.JSONDecodeError as e:
                    log_error(f"JSON parsing failed: {str(e)}")
                    raise

                # Validate and normalize data
                nist_data = {
                    "cve_id": table_data.get("cve_id", query),
                    "description": table_data.get("description", f"Details for {query} unavailable"),
                    "severity": table_data.get("severity", "UNKNOWN").upper(),
                    "impact": float(table_data.get("impact", 0.0)),
                    "exploitability": float(table_data.get("exploitability", 0.0)),
                    "exploit_available": table_data.get("exploit_available", "No"),
                    "published": table_data.get("published", "Unknown"),
                    "affected": table_data.get("affected", []) if isinstance(table_data.get("affected"), list) else [],
                    "references": table_data.get("references", [f"https://nvd.nist.gov/vuln/detail/{query}"]) if isinstance(table_data.get("references"), list) else [f"https://nvd.nist.gov/vuln/detail/{query}"]
                }
                mitre_data = table_data.get("mitre_techniques", []) if isinstance(table_data.get("mitre_techniques"), list) else []

                # Ensure complete summary
                if len(summary.split('\n')) < 10:  # Arbitrary threshold for incomplete summary
                    log_error("Summary appears incomplete")
                    summary = f"""## {query} Summary
- **Description**: {nist_data['description']}. Attack vector: Unknown. Mitigation: Apply vendor patches.
- **Severity**: {nist_data['severity']}, CVSS {nist_data['impact']}, Exploits: {nist_data['exploit_available']}.
- **Affected**: {', '.join(nist_data['affected']) or 'None identified'}
- **MITRE ATT&CK**: {', '.join([f"{t['id']}: {t['name']}" for t in mitre_data]) or 'None identified'}
- **Threat Actors**: Unknown
- **Bug Bounty**: None known
- **Recent News**: Check vendor advisories
- **Next Steps**: Patch systems, monitor for exploitation
- **Missing Data**: Additional details at https://nvd.nist.gov/vuln/detail/{query}
"""

            except Exception as e:
                log_error(f"LLM query or parsing failed: {str(e)}")
                # Fallback
                nist_data = {
                    "cve_id": query,
                    "description": f"Vulnerability details for {query} unavailable",
                    "severity": "UNKNOWN",
                    "impact": 0.0,
                    "exploitability": 0.0,
                    "exploit_available": "No",
                    "published": "Unknown",
                    "affected": [],
                    "references": [f"https://nvd.nist.gov/vuln/detail/{query}"]
                }
                mitre_data = []
                summary = f"""## {query} Summary
- **Description**: Limited information available for {query}.
- **Attack Vector**: Unknown.
- **Severity**: Unknown; check NVD.
- **Affected**: None identified.
- **MITRE ATT&CK**: None identified.
- **Threat Actors**: Unknown.
- **Bug Bounty**: None known.
- **Recent News**: None available.
- **Next Steps**: Monitor NVD or vendor advisories.
- **Missing Data**: Details at https://nvd.nist.gov/vuln/detail/{query}.
"""

            results = [Result(
                cve_id=nist_data["cve_id"],
                description=nist_data["description"],
                severity=nist_data["severity"],
                impact=nist_data["impact"],
                exploitability=nist_data["exploitability"],
                exploit_available=nist_data["exploit_available"],
                published=nist_data["published"],
                affected=nist_data["affected"],
                references=nist_data["references"],
                mitre_techniques=mitre_data
            )]

            return {"results": results, "summary": summary}
        except Exception as e:
            log_error(f"Error processing query: {str(e)}")
            return {"error": f"Failed to process query: {str(e)}"}

if __name__ == "__main__":
    agent = AgentBando()
    response = agent.process_query("CVE-2025-30400")
    print(response)