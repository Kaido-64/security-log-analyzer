# 🔐 Security Log Analyzer (Python)

A lightweight cybersecurity tool that parses SSH authentication logs, detects suspicious login activity and generates a JSON report for further analysis or SIEM integration.

---

## 🚀 Features

- Detect failed SSH login attempts (`Failed password`)
- Extract attacker IP addresses
- Count total failed attempts per IP
- Detect brute-force attacks using a sliding time window
- Export results to structured JSON reports

---

## 🛠 Technologies

- Python
- JSON
- Linux authentication logs (`auth.log`)

---

## ⚙️ How it works

1. Read the log file line by line
2. Filter failed SSH login entries
3. Extract timestamp and IP address (`from <ip>`)
4. Track login attempts per IP
5. Use a sliding time window to detect brute-force patterns
6. Generate alerts if attempts exceed the threshold
7. Export the results as a JSON report

---

## 📦 Installation

Clone the repository

```bash
git clone https://github.com/Kaido-64/Security-Log-Analysator.git
cd Security-Log-Analysator
```

Run the program

```bash
python3 analyzer.py --window 60 --threshold 5
```

---

## 📊 Example Output

Example JSON report:

```json
{
  "192.168.1.10": {
    "failed_attempts": 12,
    "alerts": [
      {
        "timestamp": "2025-01-10 14:22",
        "attempts": 6
      }
    ]
  }
}
```

---

## 📂 Project Structure

```
Security-Log-Analysator
│
├── analyzer.py
├── test_auth.log
├── report.example.json
└── README.md
```

---

## 🎓 What I learned

- Parsing Linux authentication logs
- Detecting brute-force patterns
- Working with Python and JSON
- Basic cybersecurity log analysis
- Writing security automation scripts
