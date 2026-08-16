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

```bash
git clone https://github.com/nabilreza23/AttackMind.git
cd AttackMind
pip install -r requirements.txt


## 🚀 Usage

```bash
python attackmind.py -t example.com
