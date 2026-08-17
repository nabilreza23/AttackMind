# ⚡ AttackMind

> **AI-Powered Reconnaissance & Attack Surface Analyzer**

AttackMind is a modern Security Recon tool designed for bug bounty hunters and penetration testers. It crawls target domains, extracts hidden JavaScript endpoints & parameters, and uses AI (OpenAI / Local Ollama) to analyze attack surfaces for potential vulnerabilities.

---

## 🔥 Features
- 🚀 **Fast Recon:** Scrapes JavaScript assets and extracts endpoint parameters automatically.
- 🤖 **AI Security Assessment:** Integrates directly with OpenAI or local LLMs via Ollama to evaluate endpoints for IDOR, Auth Bypass, and logic flaws.
- 🎨 **Beautiful Terminal UI:** Clean, rich dashboard display right in your terminal.
- 🔒 **Privacy-First Option:** Run completely offline using local LLM models with Ollama.

---

## 🛠️ Installation

### Standard (Linux / Mac / Windows)
```bash
git clone https://github.com/nabilreza23/AttackMind.git
cd AttackMind
pip install -r requirements.txt
```

### 📱 Termux Users:

​Termux requires C/Rust build tools to build OpenAI dependencies. Run these commands first:
```bash
pkg update && pkg upgrade
pkg install rust clang make python
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### Note for Termux: 
If pip install hangs at building wheel for jiter or openai, run:
`pip install --no-build-isolation openai`


## 🚀 Usage

```bash
python attackmind.py -t example.com
```

## 2. Recon Scan with OpenAI GPT-4 Analysis

```bash
python attackmind.py -t example.com --openai YOUR_OPENAI_API_KEY
```

## 3. Recon Scan with Local LLM (Ollama)

```bash
python attackmind.py -t example.com --ollama llama3
```

## ⚠️ Disclaimer
This tool is built for educational and authorized security testing purposes only. Do not test targets without explicit authorization.
