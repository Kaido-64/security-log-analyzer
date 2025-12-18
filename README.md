# Security Log Analyzer (Python)

A small security tool that parses SSH authentication logs, detects suspicious activity, and produces a JSON report for automation/SIEM use.

## Features
- Detects failed SSH logins (`Failed password`)
- Extracts attacker IPs and counts total failures per IP
- Brute-force detection using a sliding time window (`--window`, `--threshold`)
- Exports results to JSON (`report.json`) for further processing

## How it works
1. Read the log file line by line
2. Filter for failed SSH login lines
3. Extract timestamp + IP (`from <ip>`)
4. Track attempts per IP in a time window (sliding window)
5. Trigger alerts when attempts exceed a threshold
6. Write a structured JSON report

## Usage
```bash
python3 analyzer.py --window 60 --threshold 5
