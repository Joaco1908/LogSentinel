# LogSentinel 🕵️‍♂️🔍

**LogSentinel** is a Python tool for detecting suspicious activity in system logs. Built for Blue Team learning, it scans logs for brute-force attempts, unauthorized access, and unusual patterns, generating alerts and simple reports.

---

## 📌 Project Description

**LogSentinel** is a Python-based educational tool for parsing and analyzing system log files with a Blue Team perspective. It helps identify suspicious activity patterns — such as brute-force login attempts, unauthorized access, or abnormal behavior — by scanning logs and applying simple, customizable detection rules.

---

## 💡 Use Cases

- Practice real-world log analysis (e.g., Linux `auth.log`, Apache `access.log`)
- Automatically detect suspicious events
- Improve Python skills in a cybersecurity context
- Build and showcase your first defensive security tool

---

## 📁 Project Structure

```
LogSentinel/
├── src/                # Source code
│   └── main.py         # Main script
├── logs/               # Input log files
├── reports/            # Generated reports
├── requirements.txt    # Project dependencies
├── .gitignore          # Files ignored by Git
└── README.md           # Project documentation
```

---

## 🛠️ Technologies

- Python 3.x
- Regular expressions (regex)
- JSON file handling
- `datetime` for timestamps
- Optional: `ipaddress`, `ipwhois`, `jinja2`, or `matplotlib` for extensions

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Joaco1908/LogSentinel.git
cd LogSentinel

# (Optional) Set up a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (to be updated as needed)
pip install -r requirements.txt
```

---

## 🚧 Project Status

🔧 In development — Initial features: log parsing and detection logic

---

## 👨‍🎓 Educational Purpose

This project is part of my personal learning journey in cybersecurity and Blue Team operations. Contributions and feedback are welcome!

---

## 📄 License

This project is licensed under the MIT License — feel free to use, modify, and share.

---
