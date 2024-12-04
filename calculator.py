# calculator.py

CVSS_4_0_METRICS = {
    "AV": {
        "N": "Attack Vector: Network",
        "A": "Attack Vector: Adjacent",
        "L": "Attack Vector: Local",
        "P": "Attack Vector: Physical"
    },
    "AC": {
        "L": "Attack Complexity: Low",
        "H": "Attack Complexity: High"
    },
    "PR": {
        "N": "Privileges Required: None",
        "L": "Privileges Required: Low",
        "H": "Privileges Required: High"
    },
    "UI": {
        "N": "User Interaction: None",
        "P": "User Interaction: Passive",
        "A": "User Interaction: Active"
    },
    "VC": {
        "H": "Vulnerability Confidentiality: High",
        "L": "Vulnerability Confidentiality: Low",
        "N": "Vulnerability Confidentiality: None"
    },
    "VI": {
        "H": "Vulnerability Integrity: High",
        "L": "Vulnerability Integrity: Low",
        "N": "Vulnerability Integrity: None"
    },
    "VA": {
        "H": "Vulnerability Availability: High",
        "L": "Vulnerability Availability: Low",
        "N": "Vulnerability Availability: None"
    },
    "SC": {
        "H": "System Confidentiality: High",
        "L": "System Confidentiality: Low",
        "N": "System Confidentiality: None"
    },
    "SI": {
        "H": "System Integrity: High",
        "L": "System Integrity: Low",
        "N": "System Integrity: None"
    },
    "SA": {
        "H": "System Availability: High",
        "L": "System Availability: Low",
        "N": "System Availability: None"
    },
    "S": {
        "U": "Scope: Unchanged",
        "C": "Scope: Changed"
    }
}

def parse_cvss_short_code(short_code):
    """
    Parses a CVSS 4.0 short code and returns details about each segment.
    Example input: 'CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:U'
    """
    if not short_code.startswith("CVSS:4.0/"):
        raise ValueError("Input must start with 'CVSS:4.0/'")
    segments = short_code[len("CVSS:4.0/"):].split("/")
    details = {}
    for segment in segments:
        if ":" not in segment:
            continue
        metric, value = segment.split(":")
        metric = metric.strip()
        value = value.strip()
        if metric in CVSS_4_0_METRICS and value in CVSS_4_0_METRICS[metric]:
            details[metric] = CVSS_4_0_METRICS[metric][value]
        else:
            details[metric] = f"Unknown value '{value}' for metric '{metric}'"
    return details

if __name__ == "__main__":
    short_code = input("Enter CVSS 4.0 short code: ").strip()
    try:
        details = parse_cvss_short_code(short_code)
        print("\nCVSS 4.0 Details:")
        for metric, description in details.items():
            print(f"{metric}: {description}")
    except Exception as e:
        print(f"Error: {e}")