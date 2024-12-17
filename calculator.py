from enum import Enum

# calculator.py


class CVSSVersion(Enum):
    V3_1 = "3.1"
    V4_0 = "4.0"

CVSS_METRICS = {
    CVSSVersion.V3_1: {
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
    },
    CVSSVersion.V4_0: {
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
}

def print_colored(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

class CVSSParser:
    def __init__(self, version: CVSSVersion):
        self.version = version
        self.metrics = CVSS_METRICS[version]
        self.prefix = f"CVSS:{version.value}/"

    def parse(self, short_code: str):
        if not short_code.startswith(self.prefix):
            raise ValueError(f"Input must start with '{self.prefix}'")
        segments = short_code[len(self.prefix):].split("/")
        details = {}
        for segment in segments:
            if ":" not in segment:
                continue
            metric, value = segment.split(":")
            metric = metric.strip()
            value = value.strip()
            if metric in self.metrics and value in self.metrics[metric]:
                details[metric] = self.metrics[metric][value]
            else:
                details[metric] = f"Unknown value '{value}' for metric '{metric}'"
        return details

class CVSSPrinter:
    METRIC_COLOR = "1;36"   # Bold cyan
    VALUE_COLOR = "1;33"    # Bold yellow
    ERROR_COLOR = "1;31"    # Bold red
    TITLE_COLOR = "1;32"
    BORDER_COLOR = "1;34"
    PROMPT_COLOR = "1;35"

    @staticmethod
    def print_details(details):
        print(print_colored("="*40, CVSSPrinter.BORDER_COLOR))
        print(print_colored("        CVSS Details", CVSSPrinter.TITLE_COLOR))
        print(print_colored("="*40, CVSSPrinter.BORDER_COLOR))
        for metric, description in details.items():
            if description.startswith("Unknown value"):
                desc = print_colored(description, CVSSPrinter.ERROR_COLOR)
            else:
                desc = print_colored(description, CVSSPrinter.VALUE_COLOR)
            print(f"{print_colored(metric, CVSSPrinter.METRIC_COLOR)}: {desc}")
        print(print_colored("="*40, CVSSPrinter.BORDER_COLOR))

def select_version():
    print(print_colored("Select CVSS version:", CVSSPrinter.PROMPT_COLOR))
    print(print_colored("1. CVSS 3.1", CVSSPrinter.METRIC_COLOR))
    print(print_colored("2. CVSS 4.0", CVSSPrinter.METRIC_COLOR))
    version_choice = input(print_colored("Enter option (1 or 2): ", CVSSPrinter.PROMPT_COLOR)).strip()
    if version_choice == "1":
        return CVSSVersion.V3_1
    elif version_choice == "2":
        return CVSSVersion.V4_0
    else:
        print(print_colored("Invalid option selected.", CVSSPrinter.ERROR_COLOR))
        exit(1)

def main():
    version = select_version()
    parser = CVSSParser(version)
    short_code = input(
        print_colored(
            f"Enter CVSS {version.value} short code (starting with '{parser.prefix}'): ",
            CVSSPrinter.PROMPT_COLOR
        )
    ).strip()
    try:
        details = parser.parse(short_code)
        CVSSPrinter.print_details(details)
    except Exception as e:
        print(print_colored(f"Error: {e}", CVSSPrinter.ERROR_COLOR))

if __name__ == "__main__":
    main()