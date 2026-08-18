# AttackMind 🎯
**AI-Powered Recon & Attack Surface Analyzer**

AttackMind is a fast, dependency-free Python tool designed for offensive security researchers and bug bounty hunters. It crawls target domains, extracts JS files, parses internal parameters & endpoints (via HTML, forms, and Wayback Machine archives), scans for exposed secrets, and leverages **Google Gemini AI** to provide actionable security assessments.

---

## ✨ Features
- 🔍 **Target Header Inspection**: Swift analysis of HTTP response headers.
- 📜 **JavaScript Discovery**: Scans and lists internal JS files and scripts.
- 🔑 **Secrets Extraction**: Regex-based detection for Google API Keys, AWS Keys, Bearer Tokens, and generic secrets inside JS files.
- 🎯 **Parameter & Form Extraction**: Captures internal GET/POST parameters using internal page crawling and Wayback Archive integration.
- 🤖 **Gemini AI Security Insights**: Evaluates extracted data using **Google Gemini AI** to highlight potential attack vectors (SQLi, XSS, IDOR) and missing security controls.

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nabilreza23/AttackMind.git
   cd AttackMind
   ```


   
