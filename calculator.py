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

def print_colored(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def print_cvss_details(details):
    # Define colors for metrics and values
    metric_color = "1;36"   # Bold cyan
    value_color = "1;33"    # Bold yellow
    error_color = "1;31"    # Bold red

    print(print_colored("="*40, "1;34"))
    print(print_colored("        CVSS 4.0 Details", "1;32"))
    print(print_colored("="*40, "1;34"))
    for metric, description in details.items():
        if description.startswith("Unknown value"):
            desc = print_colored(description, error_color)
        else:
            desc = print_colored(description, value_color)
        print(f"{print_colored(metric, metric_color)}: {desc}")
    print(print_colored("="*40, "1;34"))

if __name__ == "__main__":
    short_code = input(print_colored("Enter CVSS 4.0 short code: ", "1;35")).strip()
    try:
        details = parse_cvss_short_code(short_code)
        print_cvss_details(details)
    except Exception as e:
        print(print_colored(f"Error: {e}", "1;31"))