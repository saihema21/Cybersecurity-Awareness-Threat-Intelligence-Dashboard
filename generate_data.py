import random
import hashlib
from datetime import datetime, timedelta
import pandas as pd

random.seed(42)

CATEGORIES = [
    "Phishing",
    "Malware",
    "Ransomware",
    "Credential Threat",
    "Web Threat",
    "Network Threat",
    "Vulnerability Exposure",
    "Social Engineering",
    "Data Exposure",
    "Account Security"
]

INDICATOR_TYPES = [
    "IP",
    "Domain",
    "URL",
    "SHA-256",
    "Email/Sender Domain",
    "CVE"
]

SEVERITIES = [
    "Informational",
    "Low",
    "Medium",
    "High",
    "Critical"
]

STATUSES = [
    "NEW",
    "UNDER_REVIEW",
    "MONITORING",
    "CLOSED",
    "FALSE_POSITIVE"
]

SOURCES = [
    "Internal SOC",
    "Security Vendor",
    "Public Threat Feed",
    "Research Report",
    "Community Submission",
    "Unknown Source"
]

MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Credential Access",
    "Discovery",
    "Command and Control",
    "Exfiltration"
]

MITRE_TECHNIQUES = [
    "Phishing",
    "Valid Accounts",
    "User Execution",
    "Credential Phishing",
    "Network Service Scanning",
    "Application Layer Protocol",
    "Data from Information Repositories"
]

THREAT_NAMES = [
    "Synthetic Credential Phishing Campaign",
    "Suspicious Malware Indicator",
    "Ransomware Activity Pattern",
    "Credential Theft Observation",
    "Suspicious Web Activity",
    "Network Threat Observation",
    "Vulnerability Exposure",
    "Social Engineering Attempt",
    "Potential Data Exposure",
    "Account Security Event"
]

def generate_ip():
    ranges = [
        "192.0.2.",
        "198.51.100.",
        "203.0.113."
    ]
    return random.choice(ranges) + str(random.randint(1, 254))


def generate_domain():
    names = [
        "login-check",
        "security-alert",
        "account-verify",
        "update-service",
        "secure-login",
        "identity-check",
        "cloud-security"
    ]
    return random.choice(names) + random.choice(
        [".invalid", ".example.com", ".example.org", ".example.net"]
    )


def generate_url():
    return "https://" + generate_domain() + "/verify"


def generate_hash():
    value = f"synthetic-threat-{random.randint(1, 100000000)}"
    return hashlib.sha256(value.encode()).hexdigest()


def generate_email_domain():
    return "alerts@" + generate_domain()


def generate_cve():
    year = random.randint(2021, 2026)
    number = random.randint(1000, 59999)
    return f"CVE-{year}-{number}"


def generate_indicator(indicator_type):
    if indicator_type == "IP":
        return generate_ip()

    if indicator_type == "Domain":
        return generate_domain()

    if indicator_type == "URL":
        return generate_url()

    if indicator_type == "SHA-256":
        return generate_hash()

    if indicator_type == "Email/Sender Domain":
        return generate_email_domain()

    return generate_cve()


def generate_record(index):
    category = random.choice(CATEGORIES)
    indicator_type = random.choice(INDICATOR_TYPES)

    severity = random.choices(
        SEVERITIES,
        weights=[5, 15, 30, 35, 15]
    )[0]

    confidence = random.randint(25, 98)

    severity_score = {
        "Informational": 10,
        "Low": 25,
        "Medium": 50,
        "High": 75,
        "Critical": 95
    }[severity]

    recency_score = random.randint(40, 100)
    frequency_score = random.randint(20, 100)
    reliability_score = random.randint(40, 100)
    context_score = random.randint(20, 100)

    risk_score = round(
        (
            severity_score * 0.30
            + confidence * 0.25
            + recency_score * 0.15
            + frequency_score * 0.10
            + reliability_score * 0.10
            + context_score * 0.10
        )
    )

    if risk_score <= 20:
        calculated_severity = "Informational"
    elif risk_score <= 40:
        calculated_severity = "Low"
    elif risk_score <= 60:
        calculated_severity = "Medium"
    elif risk_score <= 80:
        calculated_severity = "High"
    else:
        calculated_severity = "Critical"

    timestamp = datetime.now() - timedelta(
        days=random.randint(0, 180),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59)
    )

    first_seen = timestamp - timedelta(days=random.randint(0, 30))
    last_seen = timestamp + timedelta(days=random.randint(0, 5))

    source = random.choice(SOURCES)

    reliability = {
        "Internal SOC": "A",
        "Security Vendor": "A",
        "Public Threat Feed": "B",
        "Research Report": "B",
        "Community Submission": "C",
        "Unknown Source": "D"
    }[source]

    use_mitre = random.random() > 0.25

    cve_id = generate_cve() if (
        indicator_type == "CVE"
        or category == "Vulnerability Exposure"
    ) else None

    return {
        "threat_id": f"THR-2026-{index:04d}",
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "threat_name": random.choice(THREAT_NAMES),
        "threat_category": category,
        "indicator_type": indicator_type,
        "indicator_value": generate_indicator(indicator_type),
        "source_name": source,
        "source_reliability": reliability,
        "confidence_score": confidence,
        "severity": calculated_severity,
        "risk_score": risk_score,
        "status": random.choice(STATUSES),
        "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "country_or_region": random.choice([
            "India",
            "United States",
            "United Kingdom",
            "Germany",
            "Singapore",
            "Australia",
            "Global"
        ]),
        "description": (
            f"Synthetic defensive cybersecurity observation related to "
            f"{category.lower()}. This record is for awareness, "
            f"analysis, and defensive security monitoring."
        ),
        "mitre_tactic": random.choice(MITRE_TACTICS) if use_mitre else None,
        "mitre_technique": random.choice(MITRE_TECHNIQUES) if use_mitre else None,
        "cve_id": cve_id
    }


records = [generate_record(i) for i in range(1, 2001)]

df = pd.DataFrame(records)

df.to_csv(
    "data/threat_intelligence_dataset.csv",
    index=False
)

print("Dataset created successfully!")
print(f"Total records: {len(df)}")
print("File: data/threat_intelligence_dataset.csv")
print("\nSeverity distribution:")
print(df["severity"].value_counts())