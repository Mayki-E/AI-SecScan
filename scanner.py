import argparse
import os
import requests
from datetime import datetime
from rich import print as rich_print
from rich.console import Console
from tqdm import tqdm
import time

console = Console()

def call_mistral_api(messages, api_key, model="mistral-small"):
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model,
        "messages": messages,
        "temperature": 0.3
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        console.print(f"[bold red]API Error:[/bold red] {e}")
        return None

def analyze_security(content, api_key, model="mistral-small"):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a senior security analyst. Analyze the provided code for vulnerabilities. "
                "For each vulnerability found, respond in this format:\n"
                "TRUE|line_number|vulnerability_type|severity|description|fix_suggestion|vulnerable_code_snippet\n"
                "If no vulnerabilities are found, respond ONLY with: FALSE\n"
                "Never add extra text or explanations outside this format."
            )
        },
        {
            "role": "user",
            "content": f"Analyze this code:\n{content}"
        }
    ]
    return call_mistral_api(messages, api_key, model)

def validate_finding(vulnerability_description, code_snippet, api_key, model="mistral-small"):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security validation expert. "
                "Given a vulnerability description and code snippet, confirm if this is a real security issue. "
                "Respond ONLY with:\n"
                "CONFIRMED|explanation (if real)\n"
                "or\n"
                "FALSE|reason (if not real)"
            )
        },
        {
            "role": "user",
            "content": f"Vulnerability: {vulnerability_description}\nCode:\n{code_snippet}"
        }
    ]
    return call_mistral_api(messages, api_key, model)

def save_results_to_file(filepath, scan_results):
    with open(filepath, 'a') as file:
        for result in scan_results:
            file.write(' | '.join(result) + "\n")

def scan_file(file_path, api_key, model, directory, chunk_size=40, overlap=10):
    console.print(f"[bold blue]Scanning[/bold blue]: {file_path}")
    with open(file_path, 'r') as file:
        content = file.readlines()
    file_scan_results = []
    for chunk_start in range(0, len(content), chunk_size - overlap):
        chunk_end = min(chunk_start + chunk_size, len(content))
        code_chunk = ''.join(content[chunk_start:chunk_end])
        response = analyze_security(code_chunk, api_key, model)
        if not response or response == "FALSE":
            continue
        try:
            vulnerabilities = response.split("\n")
            for vuln in vulnerabilities:
                if not vuln.strip() or not vuln.startswith("TRUE|"):
                    continue
                parts = vuln.split("|")
                if len(parts) < 6:
                    continue
                line_numbers = parts[1].strip()
                vuln_type = parts[2].strip()
                severity = parts[3].strip()
                description = parts[4].strip()
                fix = parts[5].strip()
                code_snippet = parts[6].strip() if len(parts) > 6 else ""

                # Validate the finding
                validation = validate_finding(description, code_snippet, api_key, model)
                if not validation:
                    continue
                if validation.startswith("CONFIRMED"):
                    explanation = validation.split("|", 1)[1].strip()
                    file_scan_results.append((
                        file_path,
                        line_numbers,
                        f"{vuln_type} ({severity})",
                        f"{description} (Explanation: {explanation})",
                        fix,
                        code_snippet
                    ))
        except Exception as e:
            console.print(f"[bold red]Error parsing:[/bold red] {response} ({e})")
    for result in file_scan_results:
        file_path, line_numbers, vuln_type, description, fix, code_snippet = result
        console.print(
            f"[bold yellow]{file_path}[/bold yellow] | "
            f"[bold magenta]Line: {line_numbers}[/bold magenta] | "
            f"[bold red]{vuln_type}[/bold red] | "
            f"[bold green]{description}[/bold green] | "
            f"[bold cyan]Fix: {fix}[/bold cyan] | "
            f"[bold white]{code_snippet}[/bold white]"
        )
    return file_scan_results

def scan_directory(directory, file_types=None, scan_all=False, api_key=None, model="mistral-small"):
    if scan_all:
        files_to_scan = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]
    else:
        files_to_scan = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files if any(file.endswith(ft) for ft in file_types)]
    console.print(f"[bold magenta]Total files to scan:[/bold magenta] {len(files_to_scan)}")
    scan_results = []
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_results_{timestamp}.txt"
    filepath = os.path.join("./", filename)
    console.print(f"[bold green]Results saved to:[/bold green] {filepath}")
    for file_path in tqdm(files_to_scan, desc="Scanning files"):
        file_scan_results = scan_file(file_path, api_key, model, directory)
        save_results_to_file(filepath, file_scan_results)

def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(description="Scan source code for security issues with explanations.")
    parser.add_argument("directory", type=str, help="Directory to scan")
    parser.add_argument("--file-types", type=str, nargs="+", default=[".php"], help="File types to scan")
    parser.add_argument("--all", action="store_true", help="Scan all files")
    parser.add_argument("--api-key", type=str, required=True, help="Your Mistral API key")
    parser.add_argument("--model", type=str, default="mistral-small", help="Mistral model to use")
    args = parser.parse_args()
    scan_directory(args.directory, args.file_types, scan_all=args.all, api_key=args.api_key, model=args.model)
    elapsed_time = time.time() - start_time
    console.print(f"[bold green]Finished. Time: {elapsed_time:.2f}s[/bold green]")

if __name__ == "__main__":
    main()
