# calculator.py

CVSS_3_1_METRICS = {
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
        "R": "User Interaction: Required"
    },
    "S": {
        "U": "Scope: Unchanged",
        "C": "Scope: Changed"
    },
    "C": {
        "H": "Confidentiality: High",
        "L": "Confidentiality: Low",
        "N": "Confidentiality: None"
    },
    "I": {
        "H": "Integrity: High",
        "L": "Integrity: Low",
        "N": "Integrity: None"
    },
    "A": {
        "H": "Availability: High",
        "L": "Availability: Low",
        "N": "Availability: None"
    }
}

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

def parse_cvss_short_code(short_code, version):
    """
    Parses a CVSS short code and returns details about each segment.
    """
    if version == "3.1":
        prefix = "CVSS:3.1/"
        METRICS = CVSS_3_1_METRICS
    elif version == "4.0":
        prefix = "CVSS:4.0/"
        METRICS = CVSS_4_0_METRICS
    else:
        raise ValueError("Unsupported CVSS version")

    if not short_code.startswith(prefix):
        raise ValueError(f"Input must start with '{prefix}'")
    segments = short_code[len(prefix):].split("/")
    details = {}
    for segment in segments:
        if ":" not in segment:
            continue
        metric, value = segment.split(":")
        metric = metric.strip()
        value = value.strip()
        if metric in METRICS and value in METRICS[metric]:
            details[metric] = METRICS[metric][value]
        else:
            details[metric] = f"Unknown value '{value}' for metric '{metric}'"
    return details

def print_colored(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def print_cvss_details(details):
    # Define colors for metrics and values
    metric_color = "1;36"   # Bold cyan
    value_color = "1;33"    # Bold yellow
    error_color = "1;31"    # Bold red

    print(print_colored("="*40, "1;34"))
    print(print_colored("        CVSS Details", "1;32"))
    print(print_colored("="*40, "1;34"))
    for metric, description in details.items():
        if description.startswith("Unknown value"):
            desc = print_colored(description, error_color)
        else:
            desc = print_colored(description, value_color)
        print(f"{print_colored(metric, metric_color)}: {desc}")
    print(print_colored("="*40, "1;34"))

if __name__ == "__main__":
    print(print_colored("Select CVSS version:", "1;35"))
    print(print_colored("1. CVSS 3.1", "1;36"))
    print(print_colored("2. CVSS 4.0", "1;36"))
    version_choice = input(print_colored("Enter option (1 or 2): ", "1;35")).strip()
    if version_choice == "1":
        version = "3.1"
    elif version_choice == "2":
        version = "4.0"
    else:
        print(print_colored("Invalid option selected.", "1;31"))
        exit(1)
    prefix = f"CVSS:{version}/"
    short_code = input(print_colored(f"Enter CVSS {version} short code (starting with '{prefix}'): ", "1;35")).strip()
    try:
        details = parse_cvss_short_code(short_code, version)
        print_cvss_details(details)
    except Exception as e:
        print(print_colored(f"Error: {e}", "1;31"))