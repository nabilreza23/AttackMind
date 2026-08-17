import re
import json
import urllib3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from openai import OpenAI

# Suppress SSL Warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class AttackMind:
    def __init__(self, target_url, openai_api_key=None, ollama_model=None):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"
        self.domain = urlparse(self.target_url).netloc
        self.headers = {'User-Agent': 'AttackMind-Recon-Engine/1.0'}
        self.js_files = []
        self.endpoints = set()
        self.parameters = set()
        self.headers_info = {}
        self.openai_api_key = openai_api_key
        self.ollama_model = ollama_model

    def banner(self):
        banner_text = "[bold cyan]   _  _ |_  _  _ |  |_  |_|o_  _|[/bold cyan]\n" \
                      "[bold cyan]  (_| | |_ (_|(_ |/|| | | | | |(_|[/bold cyan]\n" \
                      "[bold yellow]      AI-Powered Recon & Attack Surface Analyzer[/bold yellow]"
        console.print(Panel(banner_text, border_style="cyan", expand=False))

    def fetch_page(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)
            self.headers_info = dict(response.headers)
            return response.text
        except Exception as e:
            console.print(f"[bold red][!] Target unreachable:[/bold red] {e}")
            return None

    def extract_assets(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract JS Files
        for script in soup.find_all('script', src=True):
            js_url = urljoin(self.target_url, script['src'])
            self.js_files.append(js_url)

    def analyze_js(self):
        # Patterns for endpoints and parameters
        endpoint_pattern = re.compile(r'["\'](/(?:api|v[0-9]|user|admin|auth|config|dashboard)[a-zA-Z0-9_/-]*)["\']')
        param_pattern = re.compile(r'[\?&]([a-zA-Z0-9_]+)=')

        for js_url in self.js_files[:10]: # Limit to 10 JS files for fast scan
            try:
                res = requests.get(js_url, headers=self.headers, timeout=5, verify=False)
                if res.status_code == 200:
                    found_endpoints = endpoint_pattern.findall(res.text)
                    found_params = param_pattern.findall(res.text)
                    
                    self.endpoints.update(found_endpoints)
                    self.parameters.update(found_params)
            except:
                continue

    def ai_analyze_surface(self):
        prompt = f"""
You are an expert offensive cybersecurity engineer analyzing a target.
Target Header Data: {json.dumps(self.headers_info)}
Discovered Endpoints: {list(self.endpoints)}
Discovered Parameters: {list(self.parameters)}

Analyze this attack surface and give a brief vulnerability analysis:
1. Identify probable CDN/WAF or Server technologies from headers.
2. Highlight high-risk endpoints (e.g., IDOR, Auth Bypass, SQLi potential).
3. Suggest 3 specific manual testing vectors for bug bounty hunting.
Keep the response crisp, technical, and actionable.
        """

        if self.openai_api_key:
            try:
                client = OpenAI(api_key=self.openai_api_key)
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content
            except Exception as e:
                return f"OpenAI Error: {e}"
        elif self.ollama_model:
            try:
                res = requests.post("http://localhost:11434/api/generate", json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False
                })
                return res.json().get("response", "No response from Ollama.")
            except Exception as e:
                return f"Ollama Connection Error (Make sure Ollama is running): {e}"
        else:
            return "[yellow]AI analysis skipped. Provide an OpenAI API Key or Ollama model to enable AI Security Insights.[/yellow]"

    def run(self):
        self.banner()
        console.print(f"[bold green][+] Target Loaded:[/bold green] {self.target_url}\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            
            task1 = progress.add_task(description="Fetching target HTML & Headers...", total=None)
            html = self.fetch_page()
            if not html:
                return

            progress.update(task1, description="Extracting JavaScript files...")
            self.extract_assets(html)

            progress.update(task1, description="Parsing JS for hidden endpoints & parameters...")
            self.analyze_js()

        # Display Headers / Tech
        table = Table(title="Target Header Snapshot", show_header=True, header_style="bold magenta")
        table.add_column("Header Name", style="cyan")
        table.add_column("Value", style="white")
        for k, v in list(self.headers_info.items())[:6]:
            table.add_column if False else table.add_row(k, v[:60])
        console.print(table)
        console.print("\n")

        # Display Results
        console.print(Panel(f"[bold green]JS Files Found:[/bold green] {len(self.js_files)}\n"
                            f"[bold green]Endpoints Discovered:[/bold green] {len(self.endpoints)}\n"
                            f"[bold green]Parameters Extracted:[/bold green] {len(self.parameters)}", title="Recon Summary"))

        if self.endpoints:
            console.print("\n[bold yellow]Sample Discovered Endpoints:[/bold yellow]")
            for ep in list(self.endpoints)[:8]:
                console.print(f" [cyan]•[/cyan] {ep}")

        # AI Analysis Section
        console.print("\n[bold magenta][*] Running AI Attack Surface Analysis...[/bold magenta]")
        ai_result = self.ai_analyze_surface()
        console.print(Panel(ai_result, title="AI Security Assessment", border_style="bold magenta"))

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="AttackMind - AI Powered Recon Engine")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. example.com)")
    parser.add_argument("--openai", help="OpenAI API Key")
    parser.add_argument("--ollama", help="Ollama model name (e.g. llama3, mistral)")

    args = parser.parse_args()

    scanner = AttackMind(target_url=args.target, openai_api_key=args.openai, ollama_model=args.ollama)
    scanner.run()
