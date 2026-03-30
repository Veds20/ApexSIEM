# ⚡ ApexSIEM
### AI-Powered Security Operations Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.14-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi" />
  <img src="https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react" />
  <img src="https://img.shields.io/badge/ML-IsolationForest-FF6F00?style=for-the-badge&logo=scikitlearn" />
  <img src="https://img.shields.io/badge/AI-Groq%20LLaMA3-8B3FC4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

---

## 🔍 What is ApexSIEM?

**ApexSIEM** is a real-time, AI-driven Security Information and Event Management (SIEM) system built from scratch. It ingests **real Windows Security Event Logs**, detects threats using **machine learning**, and provides **AI-generated threat analysis** — all visualized on a live SOC-style dashboard.

> ⚠️ This is NOT a simulation. Every alert is derived from real system events. No fake data is ever generated.

---

## ✨ Key Features

### 🔴 Real Log Ingestion
- Reads directly from **Windows Security Event Log** using `pywin32`
- Monitors **5 channels**: Security, System, Application, PowerShell, Sysmon
- Watches **25+ critical Event IDs**: 4625, 4624, 4672, 4688, 4698, 1102, and more
- Also supports Linux (`/var/log/auth.log`), Zeek, Suricata, UFW firewall logs

### 🧠 Intelligent Threat Detection
- **Rule-based engine** maps real Event IDs to attack types
- **Threshold logic** — 5 failed logins in 60 seconds → `brute_force`
- **Pattern recognition** on real command lines, usernames, and log fields
- Zero fake labeling — every classification comes from actual log content

### ⚡ ML Anomaly Detection
- **Isolation Forest** model trained on real trust scores
- Flags statistically unusual events even if they don't match known patterns
- Anomaly score stored per alert for analyst review

### 🤖 AI Threat Analysis
- Powered by **Groq LLaMA 3.3 70B** (free, fast)
- Sends real alert fields — IP, event type, description, related activity
- AI explains **WHY** the alert is suspicious with specific references
- Includes MITRE ATT&CK technique mapping and response recommendations

### 📋 Investigation Workflow
- Analysts must enter their **name** before investigating (accountability)
- Three statuses: **Under Progress** / **Investigated** / **Closed**
- Investigated alerts removed from main dashboard and priority panel
- All investigations tracked in dedicated **Investigations tab**
- **True Positive / False Positive** verdict system

### 📊 Live Dashboard
- Auto-refreshes every 3 seconds
- Severity distribution bar chart
- Attack type pie chart
- Alert timeline area chart
- Filterable live alert feed

---

## 🔎 Detected Attack Types

| Attack Type | Trigger |
|---|---|
| `brute_force` | ≥5 failed logins from same IP in 60s |
| `brute_force_rdp` | Failed RDP logins (EventID 4625, type 10) |
| `log_cleared` | Security audit log wiped (EventID 1102) |
| `privilege_escalation` | Special privileges assigned (EventID 4672) |
| `lateral_movement` | Explicit credentials used from remote IP (EventID 4648) |
| `new_user_created` | New account added (EventID 4720) |
| `scheduled_task_created` | Persistence via task scheduler (EventID 4698) |
| `powershell_suspicious` | Encoded/obfuscated PowerShell (EventID 4104) |
| `malware` | Known tool signatures: mimikatz, rubeus, cobalt strike |
| `kerberos_brute_force` | Repeated Kerberos failures (EventID 4771) |
| `account_lockout` | Account locked out (EventID 4740) |
| `port_scan` | ≥15 firewall blocks from same IP in 60s |
| `network_intrusion` | Suricata/Zeek IDS alerts |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     FRONTEND (React)                     │
│   Dashboard │ Priority Queue │ Investigations │ Modals   │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API (FastAPI)
┌──────────────────────▼──────────────────────────────────┐
│                    BACKEND (Python)                      │
│                                                          │
│  log_ingestion.py → log_parser.py → detection_engine.py │
│       │                                      │           │
│  Windows Event Log              Rule-based + Threshold   │
│  Linux /var/log/*               Attack Classification    │
│  Zeek / Suricata                                         │
│       │                                      │           │
│       └──────────────► SQLite DB ◄───────────┘           │
│                            │                             │
│                    ml_engine.py (IsolationForest)        │
│                            │                             │
│                    Groq API (LLaMA 3.3 70B)              │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite, Recharts, Framer Motion |
| Backend | Python, FastAPI, SQLAlchemy |
| Database | SQLite |
| Log Ingestion | pywin32 (Windows), file tailing (Linux) |
| ML | scikit-learn IsolationForest |
| AI Analysis | Groq API — LLaMA 3.3 70B (free) |
| Auth | JWT tokens |

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- Windows OS (for Windows Event Log ingestion)
- Free Groq API key from [console.groq.com](https://console.groq.com)

### Backend Setup (Run as Administrator)
```powershell
cd ApexSIEM
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install fastapi uvicorn sqlalchemy passlib python-jose[cryptography] scikit-learn numpy python-multipart pywin32 bcrypt httpx
python venv\Scripts\pywin32_postinstall.py -install
$env:GROQ_API_KEY = "your-groq-api-key"
python -m uvicorn backend.app:app --reload --port 8001
```

### Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**

### Default Login
```
Username: admin
Password: admin123
```

---

## 🧪 Generate Real Security Events

```powershell
# Trigger brute force detection (run 6 times)
net use \\localhost\IPC$ /user:hacker wrongpassword

# Create suspicious user
net user suspicioususer Pass@1234 /add
net localgroup administrators suspicioususer /add

# Scheduled task (persistence technique)
schtasks /create /tn "SuspiciousTask" /tr "cmd.exe" /sc once /st 00:00 /f

# Critical — audit log cleared alert
wevtutil cl Security
```

---

## 📁 Project Structure

```
ApexSIEM/
├── backend/
│   ├── app.py                  # FastAPI application entry point
│   ├── auth.py                 # JWT authentication
│   ├── database.py             # SQLAlchemy + SQLite setup
│   ├── models.py               # Alert and User models
│   ├── routes.py               # All API endpoints + AI analysis
│   └── services/
│       ├── log_ingestion.py    # Windows/Linux real log watcher
│       ├── log_parser.py       # Parses real event fields
│       ├── detection_engine.py # Rule-based + threshold detection
│       └── ml_engine.py        # Isolation Forest anomaly detection
└── frontend/
    └── src/
        ├── pages/
        │   ├── Dashboard.jsx       # Live SOC dashboard
        │   ├── Priority.jsx        # High severity alert queue
        │   └── Investigations.jsx  # Investigation status tracking
        └── components/
            ├── AnalyzeModal.jsx    # AI analysis + investigation workflow
            └── Navbar.jsx
```

---

## 🔐 Security Note

This tool is intended for **educational and authorized security monitoring purposes only**. Only deploy on systems you own or have explicit permission to monitor.

---

## 👨‍💻 Author

**Veds20** — Built with passion for cybersecurity and AI.

⭐ **If you found this project impressive, give it a star!**

---

<p align="center">
  <b>ApexSIEM — Because real threats deserve real detection.</b>
</p>