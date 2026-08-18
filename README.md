# 🎯 AttackMind
> **AI-Powered Recon & Attack Surface Analyzer**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20Windows-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Google%20Gemini-orange?style=for-the-badge&logo=google)

Fast, zero-fluff offensive recon tool. Extracts endpoints, hidden parameters, JS secrets, and feeds them to **Gemini AI** for instant vulnerability analysis.

---

## ⚡ Installation

### 📱 Android (Termux)
```bash
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/nabilreza23/AttackMind.git
cd AttackMind
pip install -r requirements.txt
```



### 💻 PC (Linux / Windows)
```bash
git clone https://github.com/nabilreza23/AttackMind.git
cd AttackMind
pip install -r requirements.txt
```

## 🚀 Usage


#### Basic Scan (Without AI)
```bash
python attackmind.py -t https://target.com
```

#### Scan with Gemini AI Analysis
```bash
python attackmind.py -t https://target.com --api-key "YOUR_KEY"
```

#### Dump all JS files
```bash
python attackmind.py -t https://target.com --all-js
```

## 🔥 Features

**🔍 Crawls forms, JS endpoints & Wayback archives for params (SQLi, XSS, IDOR).**

​**🔑 Regex scans JS files for leaked API keys, tokens & credentials.**

​**🤖 Auto security analysis via Google Gemini AI.**


## ⚠️ Disclaimer
​
**This tool is built strictly for educational, ethical, authorized penetration testing, and bug bounty research. Do not test targets without proper written permission.**

