import sys
import re
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

BANNER = """[bold cyan]
   _  _ |_  _  _ |  |_  |_|o_  _| 
  (_| | |_ (_|(_ |/|| | | | | |(_|
      AI-Powered Recon & Attack Surface Analyzer
[/bold cyan]"""

def get_utc_time():
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")

def extract_recon_data(target_url):
    console.print(f"\n[bold green][+] Target Loaded:[/bold green] {target_url}")
    console.print(f"[bold dim][*] Scan Initiated at: {get_utc_time()}[/bold dim]\n")

    headers_summary = {}
    js_files = []
    endpoints = set()
    parameters = set()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="Fetching target HTML & Headers...", total=None)
            response = requests.get(target_url, timeout=10, headers={"User-Agent": "AttackMind-Recon/1.0"})
            
            for k, v in list(response.headers.items())[:6]:
                headers_summary[k] = v

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                js_url = urljoin(target_url, script['src'])
                js_files.append(js_url)

            params_in_html = re.findall(r'[\?&]([a-zA-Z0-9_]+)=', response.text)
            for p in params_in_html:
                parameters.add(p)

            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('/') or target_url in href:
                    endpoints.add(href)
                    found_params = re.findall(r'[\?&]([a-zA-Z0-9_]+)=', href)
                    for p in found_params:
                        parameters.add(p)

    except Exception as e:
        console.print(f"[bold red][!] Target unreachable:[/bold red] {e}")
        sys.exit(1)

    return headers_summary, js_files, list(endpoints), list(parameters)

def display_results(headers, js_files, endpoints, parameters):
    if headers:
        header_table = Table(title="Target Header Snapshot", show_header=True, header_style="bold magenta")
        header_table.add_column("Header Name", style="cyan")
        header_table.add_column("Value", style="white")
        for k, v in headers.items():
            header_table.add_row(k, v)
        console.print(header_table)
        console.print()

    summary_panel = f"""
[bold yellow]JS Files Found:[/bold yellow] {len(js_files)}
[bold yellow]Endpoints Discovered:[/bold yellow] {len(endpoints)}
[bold yellow]Parameters Extracted:[/bold yellow] {len(parameters)}
"""
    console.print(Panel(summary_panel.strip(), title="Recon Summary", border_style="green"))

    if js_files:
        js_table = Table(title="Discovered JS Files", show_header=True, header_style="bold blue")
        js_table.add_column("#", style="dim", width=4)
        js_table.add_column("JS Script URL", style="cyan")
        for idx, js in enumerate(js_files[:15], 1):
            js_table.add_row(str(idx), js)
        if len(js_files) > 15:
            js_table.add_row("...", f"and {len(js_files) - 15} more JS files")
        console.print(js_table)
        console.print()

    if parameters:
        param_table = Table(title="Extracted Parameters", show_header=True, header_style="bold green")
        param_table.add_column("#", style="dim", width=4)
        param_table.add_column("Parameter Name", style="yellow")
        for idx, param in enumerate(parameters[:20], 1):
            param_table.add_row(str(idx), param)
        if len(parameters) > 20:
            param_table.add_row("...", f"and {len(parameters) - 20} more parameters")
        console.print(param_table)
        console.print()

def main():
    parser = argparse.ArgumentParser(description="AttackMind - AI Recon Tool")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    console.print(BANNER)
    headers, js_files, endpoints, parameters = extract_recon_data(args.target)
    display_results(headers, js_files, endpoints, parameters)

if __name__ == "__main__":
    main()
