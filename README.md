# 🔍 SmartAnalyzer – AI-Powered CLI Log Scanner

SmartAnalyzer is a command-line log analysis tool designed for Blue Teamers, SOC analysts, and cybersecurity learners. It scans system logs for suspicious keywords, scores potential threats, and uses AI to summarize the log content — all within a lightweight `.bat`-launchable Python CLI.

---

## ⚙️ Features

- 📄 Supports `.log`, `.txt`, and raw log files
- 🧠 AI-generated log summaries for human-readable context
- ⚠️ Built-in threat scoring engine
- 🧰 Default + AI-generated keyword detection
- 🗂️ Outputs clean `.md` (Markdown) reports
- 🖱️ Runs via double-clickable `.bat` file on Windows
- ✅ Works on both **Windows** and **Linux** (CLI)

---

## 🚀 How It Works

1. Launch via `run_logscanner.bat` (Windows) or `python logscanner.py` (Linux)
2. Select a log file when prompted
3. Tool scans for suspicious keywords
4. Calculates a **Threat Score**
5. Generates an AI-powered summary of the log
6. Saves output to the `outputs/` folder as a `.md` report

---

## 📂 Folder Structure

SmartAnalyzer/
├── Smartloganalyzer.py
├── run_Smartloganalyzer.bat
├── logs
├── LICENSE
└── README.md

## Tech Stack
->Python 3.x

->OpenRouter API / LLM for log summarization

->CLI interface (no GUI for max speed)

->Markdown for reporting

## License
SmartAnalyzer is licensed under the 'Creative Commons Attribution-NonCommercial 4.0 International License.'

Use it for "personal, learning, or internal" SOC work — but not for commercial purposes without permission.

🔗 License: CC BY-NC 4.0
© 2025 Samuel Dhamodharan

## Author
Samuel Dhamodharan
Aspiring SOC Analyst | Cybersecurity Learner | AI Tinkerer

“I built SmartAnalyzer as a tool I wish I had when starting out with log analysis. Fast, focused, and defender-friendly.”

## 📩 Feedback & Contributions
    This is a solo project with love & grind.
    If you're a SOC analyst, Blue Teamer, or cyber student — feel free to fork it, give feedback, or build on top of it (with credit).




