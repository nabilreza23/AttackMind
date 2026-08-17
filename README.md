# ⚡ AttackMind

> **AI-Powered Reconnaissance & Attack Surface Analyzer**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Target](https://img.shields.io/badge/Target-BugBounty%20%7C%20PenTesting-red)

AttackMind is a modern Security Recon tool designed for bug bounty hunters and penetration testers. It crawls target domains, extracts hidden JavaScript endpoints & parameters, and uses AI (OpenAI / Local Ollama) to analyze attack surfaces for potential vulnerabilities.

---

## 🔥 Features
- 🚀 **Fast Recon:** Scrapes JavaScript assets and extracts endpoint parameters automatically.
- 🤖 **AI Security Assessment:** Integrates directly with OpenAI or local LLMs via Ollama to evaluate endpoints for IDOR, Auth Bypass, and logic flaws.
- 🎨 **Beautiful Terminal UI:** Clean, rich dashboard display right in your terminal.
- 🔒 **Privacy-First Option:** Run completely offline using local LLM models with Ollama.

---

## 🛠️ Installation

### 💻 PC / Laptop (Linux, Mac, Windows)
```bash
git clone https://github.com/nabilreza23/AttackMind.git
cd  AttackMin
pip install -r requirements.txt
```
### 📱 Termux / Mobile Users
```bash
pkg update -y
pkg install git python -y
git clone https://github.com/nabilreza23/AttackMind.git
cd AttackMind
pip install requests beautifulsoup4 rich "pydantic<2" httpx httpx2 anyio distro sniffio tqdm
pip install --no-deps openai
```

## 🚀 Usage

#### ​1. Basic Recon Scan (Without AI)
```bash
python attackmind.py -t example.com
```
#### 2. Recon Scan with OpenAI GPT-4 Analysis
```bash
python attackmind.py -t example.com --openai YOUR_OPENAI_API_KEY
```
#### 3. Recon Scan with Local LLM (Ollama)
```bash
python attackmind.py -t example.com --ollama llama3
```

## 🤝 Contributing
​Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
​
## ⚠️ Disclaimer
​This tool is built for educational and authorized security testing purposes only. Do not test targets without explicit authorization.
