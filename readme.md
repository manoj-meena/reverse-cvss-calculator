# CVSS Calculator

A Python-based tool to calculate CVSS (Common Vulnerability Scoring System) scores for vulnerabilities.

## Features

- Calculate CVSS v3.1 base scores
- Simple command-line interface
- Easy to integrate into other tools

## Requirements

- Python 3.7+
- No external dependencies

## Usage

```bash
python calculator.py --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

**Arguments:**
- `--vector`: The CVSS vector string to calculate the score.

## Example

```bash
python calculator.py --vector "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
```

## Output

Displays the CVSS base score and severity rating.

## License

MIT License

## References

- [FIRST CVSS Specification](https://www.first.org/cvss/)
- [NVD CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss)