CVE_DATABASE = {
    "CVE-2024-1234": {
        "description": "Remote code execution in web server",
        "cvss": 9.8,
        "kev": True
    },
    "CVE-2023-9999": {
        "description": "SQL injection vulnerability",
        "cvss": 7.5,
        "kev": False
    }
}

SYSTEM_STACK = {
    "web_server": "nginx 1.18",
    "database": "mysql 5.7",
    "os": "ubuntu 20.04",
    "framework": "django 2.2"
}

ATTACK_GRAPH = {
    "CVE-2024-1234": ["CVE-2023-9999"],
    "CVE-2023-9999": ["privilege_escalation"]
}

MITRE_MAPPING = {
    "CVE-2024-1234": [
        "T1190 - Exploit Public-Facing Application",
        "T1059 - Command and Scripting Interpreter"
    ],
    "CVE-2023-9999": [
        "T1190 - Exploit Public-Facing Application",
        "T1068 - Exploitation for Privilege Escalation"
    ]
}

THREAT_INTEL = {
    "CVE-2024-1234": {
        "active_exploitation": True,
        "threat_actors": [
            "LockBit Ransomware",
            "FIN7"
        ],
        "public_exploit_available": True
    },

    "CVE-2023-9999": {
        "active_exploitation": False,
        "threat_actors": [],
        "public_exploit_available": False
    }
}

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/")
def home():
    return {"message": "SentryIQ Backend Running"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(data: dict):
    cve = data.get("cve")

    cve_data = CVE_DATABASE.get(cve)

    if not cve_data:
        return {
            "cve": cve,
            "status": "unknown",
            "message": "CVE not found in SentryIQ database"
        }

    # Base values
    cvss = cve_data["cvss"]
    kev = cve_data["kev"]

    # Simple system relevance scoring
    relevance = 15

    # Base score calculation
    score = cvss * 5

    if kev:
        score += 25

    score += relevance

    # 🔗 Chain detection logic
    chain = []

    if cve in ATTACK_GRAPH:
        chain = ATTACK_GRAPH[cve]

    chain_risk = 0

    if len(chain) > 0:
        chain_risk = 20  # bonus risk for possible attack path

    score += chain_risk

        # MITRE ATT&CK mapping
    mitre_techniques = []

    if cve in MITRE_MAPPING:
        mitre_techniques = MITRE_MAPPING[cve]

    # Threat intelligence enrichment
    threat_intel = {
        "active_exploitation": False,
        "threat_actors": [],
        "public_exploit_available": False
    }

    if cve in THREAT_INTEL:
        threat_intel = THREAT_INTEL[cve]

    # Final risk classification
    if score >= 90:
        risk = "CRITICAL"
    elif score >= 70:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "cve": cve,
        "description": cve_data["description"],
        "cvss": cvss,
        "kev": kev,
        "system_relevance": relevance,
        "attack_chain": chain,
        "chain_risk_added": chain_risk,
        "mitre_attack_mapping": mitre_techniques,
        "threat_intelligence": threat_intel,
        "risk_score": score,
        "risk_level": risk,
        "system_stack": SYSTEM_STACK,
        "action": "Patch immediately" if risk in ["CRITICAL", "HIGH"] else "Monitor"
    }