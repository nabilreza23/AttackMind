import sys
import re
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from openai import OpenAI

console = Console()

BANNER = """[bold cyan]
   _  _ |_  _  _ |  |_  |_|o_  _| 
  (_| | |_ (_|(_ |/|| | | | | |(_|
      AI-Powered Recon & Attack Surface Analyzer
[/bold cyan]"""

SECRET_PATTERNS = {
    "Google API Key": r'AIzaSy[A-Za-z0-9_-]{35}',
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "Bearer Token": r'bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
    "Generic Secret/Token": r'(?i)(api[_-]?key|secret|token|auth)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'
}

def get_utc_time():
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")

def fetch_wayback_params(target_domain):
    urls_with_params = set()
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{target_domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(wayback_url, timeout=8, headers={"User-Agent": "AttackMind-Recon/1.0"})
        if res.status_code == 200:
            data = res.json()
            if len(data) > 1:
                for item in data[1:]:
                    url = item[0]
                    if "?" in url and "=" in url:
                        urls_with_params.add(url)
    except Exception:
        pass
    return list(urls_with_params)

def scan_js_for_secrets_and_params(js_files, target_domain):
    found_secrets = []
    discovered_js_params = set()
    headers = {"User-Agent": "AttackMind-Recon/1.0"}
    
    for js_url in js_files[:15]:
        try:
            res = requests.get(js_url, timeout=5, headers=headers)
            if res.status_code == 200:
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, res.text)
                    for match in matches:
                        secret_val = match if isinstance(match, str) else match[1]
                        found_secrets.append((secret_type, secret_val[:25] + "...", js_url))
                
                endpoints_in_js = re.findall(r'["\'](/(?:[a-zA-Z0-9_.\-]+/)*[a-zA-Z0-9_.\-]+\?[a-zA-Z0-9_&=.\-]+)["\']', res.text)
                for ep in endpoints_in_js:
                    full_endpoint = f"https://{target_domain}{ep}"
                    discovered_js_params.add(full_endpoint)
        except Exception:
            continue
    return found_secrets, list(discovered_js_params)

def run_ai_analysis(api_key, target_url, headers, param_urls):
    if not api_key:
        return "[yellow]AI analysis skipped. Set OPENAI_API_KEY environment variable or pass --api-key to enable AI Security Insights.[/yellow]"
    
    try:
        client = OpenAI(api_key=api_key)
        prompt = f"""
As an expert offensive security analyzer, review the following recon data for target: {target_url}

Headers: {headers}
Discovered Parameterized URLs: {param_urls[:15]}

Provide a concise security report highlighting:
1. Potential vulnerability vectors (e.g., SQLi, XSS, IDOR) based on parameters and paths.
2. Missing security headers.
3. Recommended manual test cases for a bug bounty assessment.
Keep it bulleted, technical, and actionable.
"""
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[red]AI Analysis Failed:[/red] {str(e)}"

def extract_recon_data(target_url):
    console.print(f"\n[bold green][+] Target Loaded:[/bold green] {target_url}")
    console.print(f"[bold dim][*] Scan Initiated at: {get_utc_time()}[/bold dim]\n")

    headers_summary = {}
    js_files = []
    endpoints = set()
    param_urls = set()
    unique_params = set()

    target_domain = urlparse(target_url).netloc.replace('www.', '')

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="Fetching HTML, Scanning Sub-pages & Wayback Archive...", total=None)
            response = requests.get(target_url, timeout=10, headers={"User-Agent": "AttackMind-Recon/1.0"})
            
            for k, v in list(response.headers.items())[:6]:
                headers_summary[k] = v

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                js_url = urljoin(target_url, script['src'])
                if js_url not in js_files:
                    js_files.append(js_url)

            internal_links = set()
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(target_url, href)
                parsed = urlparse(full_url)
                parsed_domain = parsed.netloc.replace('www.', '')

                if target_domain in parsed_domain:
                    endpoints.add(parsed.path)
                    internal_links.add(full_url)
                    if parsed.query:
                        param_urls.add(full_url)
                        query_params = parse_qs(parsed.query)
                        for p in query_params.keys():
                            unique_params.add(p)

            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_url = urljoin(target_url, action)
                inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')]
                if inputs:
                    method = form.get('method', 'GET').upper()
                    param_str = "&".join([f"{i}=TEST" for i in inputs])
                    if method == "GET":
                        form_param_url = f"{form_url}?{param_str}"
                    else:
                        form_param_url = f"{form_url} [POST: {', '.join(inputs)}]"
                    param_urls.add(form_param_url)
                    for i in inputs:
                        unique_params.add(i)

            for sub_link in list(internal_links)[:8]:
                try:
                    sub_res = requests.get(sub_link, timeout=4, headers={"User-Agent": "AttackMind-Recon/1.0"})
                    sub_soup = BeautifulSoup(sub_res.text, 'html.parser')
                    for form in sub_soup.find_all('form'):
                        action = form.get('action', '')
                        form_url = urljoin(sub_link, action)
                        inputs = [inp.get('name') for inp in sub_soup.find_all(['input', 'textarea', 'select']) if inp.get('name')]
                        if inputs:
                            param_str = "&".join([f"{i}=TEST" for i in inputs])
                            param_urls.add(f"{form_url}?{param_str}")
                            for i in inputs:
                                unique_params.add(i)
                except Exception:
                    continue

            wayback_urls = fetch_wayback_params(target_domain)
            for w_url in wayback_urls:
                param_urls.add(w_url)
                parsed_w = urlparse(w_url)
                query_params = parse_qs(parsed_w.query)
                for p in query_params.keys():
                    unique_params.add(p)

    except Exception as e:
        console.print(f"[bold red][!] Target unreachable:[/bold red] {e}")
        sys.exit(1)

    return headers_summary, js_files, list(endpoints), list(param_urls), list(unique_params), target_domain

def display_results(headers, js_files, endpoints, param_urls, unique_params, secrets, ai_report, show_all_js):
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
[bold yellow]Target Parameterized Endpoints/Forms:[/bold yellow] {len(param_urls)}
[bold yellow]Unique Parameters Extracted:[/bold yellow] {len(unique_params)}
[bold red]Secrets Discovered:[/bold red] {len(secrets)}
"""
    console.print(Panel(summary_panel.strip(), title="Recon Summary", border_style="green"))
    console.print()

    if secrets:
        secret_table = Table(title="🚨 Exposed Secrets in JS Files", show_header=True, header_style="bold red")
        secret_table.add_column("Type", style="yellow")
        secret_table.add_column("Snippet", style="red")
        secret_table.add_column("Source JS", style="dim")
        for s_type, s_val, s_src in secrets:
            secret_table.add_row(s_type, s_val, s_src)
        console.print(secret_table)
        console.print()

    if js_files:
        js_table = Table(title=f"Discovered JS Files ({'All' if show_all_js else 'Top 15'})", show_header=True, header_style="bold blue")
        js_table.add_column("#", style="dim", width=4)
        js_table.add_column("JS Script URL", style="cyan")
        
        display_js = js_files if show_all_js else js_files[:15]
        for idx, js in enumerate(display_js, 1):
            js_table.add_row(str(idx), js)
        
        if not show_all_js and len(js_files) > 15:
            js_table.add_row("...", f"and {len(js_files) - 15} more JS files (Use --all-js flag to see all)")
        console.print(js_table)
        console.print()

    if param_urls:
        param_url_table = Table(title="Extracted Target Parameters & Endpoints (Ready for Testing)", show_header=True, header_style="bold yellow")
        param_url_table.add_column("#", style="dim", width=4)
        param_url_table.add_column("Target Endpoint & Parameters", style="green")
        for idx, p_url in enumerate(param_urls[:25], 1):
            param_url_table.add_row(str(idx), p_url)
        if len(param_urls) > 25:
            param_url_table.add_row("...", f"and {len(param_urls) - 25} more endpoints")
        console.print(param_url_table)
        console.print()

    if ai_report:
        console.print(Panel(ai_report, title="🤖 AI Security Assessment", border_style="bold cyan"))

def main():
    parser = argparse.ArgumentParser(description="AttackMind - AI Recon Tool")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--api-key", help="OpenAI API Key for AI Analysis")
    parser.add_argument("--all-js", action="store_true", help="Display all discovered JS files without limit")
    args = parser.parse_args()

    console.print(BANNER)
    headers, js_files, endpoints, param_urls, unique_params, target_domain = extract_recon_data(args.target)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Scanning JS files for API Keys & Hidden Endpoints...", total=None)
        secrets, js_param_urls = scan_js_for_secrets_and_params(js_files, target_domain)
        
    for jpu in js_param_urls:
        if jpu not in param_urls:
            param_urls.append(jpu)

    ai_report = run_ai_analysis(args.api_key, args.target, headers, param_urls)
    display_results(headers, js_files, endpoints, param_urls, unique_params, secrets, ai_report, getattr(args, 'all_js', False))

if __name__ == "__main__":
    main()
