from dotenv import load_dotenv
import os

load_dotenv()

CONFIG = {
    "together_api_key": os.getenv("TOGETHER_API_KEY"),
    "endpoints": {
        "nist_cve": "https://services.nvd.nist.gov/rest/json/cves/2.0"
    }
}