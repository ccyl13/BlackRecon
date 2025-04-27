# BlackRecon - Developed by Thomas O'Neil Álvarez

import os
import sys
import shutil
import subprocess
import time
import signal
from datetime import datetime
from colorama import Fore, Style, init
import pyfiglet

# Inicializar colorama
init(autoreset=True)

# Capturar CTRL+C elegante
def signal_handler(sig, frame):
    print(Fore.CYAN + "\nBye Bye! Hasta la próxima auditoría. 🚀\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Mostrar banner bonito
def print_banner():
    banner = pyfiglet.figlet_format("BlackRecon")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "Developed by Thomas O'Neil Álvarez")
    print(Fore.GREEN + "GitHub: " + Fore.BLUE + "https://github.com/ccyl13")
    print("=" * 60 + "\n")

# Comprobar herramienta instalada
def check_tool_installed(tool):
    return shutil.which(tool) is not None

# Comprobar requisitos
def check_requirements():
    tools = ["subfinder", "nmap", "whatweb", "httpx"]
    print(Fore.CYAN + "Checking required tools...\n")
    for tool in tools:
        if check_tool_installed(tool):
            print(Fore.GREEN + f"[OK] {tool}")
        else:
            print(Fore.RED + f"[MISSING] {tool}")
            choice = input(Fore.YELLOW + f"Install {tool}? (Y/n): ").strip().lower()
            if choice in ["", "y", "yes"]:
                install_tool(tool)
            else:
                print(Fore.RED + f"Cannot continue without {tool}. Exiting.")
                sys.exit(1)
    print()

# Instalar herramienta
def install_tool(tool):
    if tool in ["subfinder", "httpx"]:
        subprocess.call(["go", "install", f"github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest"])
    elif tool == "nmap" or tool == "whatweb":
        subprocess.call(["apt", "install", "-y", tool])
    else:
        print(Fore.RED + f"No installer configured for {tool}")

# Enumerar subdominios (ahora ignora digitorus y captura errores)
def enumerate_subdomains(domain):
    try:
        result = subprocess.check_output(
            f"subfinder -d {domain} -silent -exclude-sources digitorus",
            shell=True, stderr=subprocess.DEVNULL
        )
        return result.decode().strip().split("\n")
    except subprocess.CalledProcessError:
        return []

# Resolver IPs
def resolve_ip(subdomain):
    try:
        result = subprocess.check_output(f"host {subdomain}", shell=True, stderr=subprocess.DEVNULL).decode()
        if "has address" in result:
            ip = result.split("has address")[-1].strip()
            return ip
    except:
        return None

# Detectar tecnologías
def detect_technologies(subdomain):
    try:
        result = subprocess.check_output(f"whatweb --no-errors {subdomain}", shell=True, stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except:
        return "Unknown"

# Escanear puertos
def scan_ports(ip):
    try:
        result = subprocess.check_output(f"nmap -p 80,443,8080,8443 {ip}", shell=True, stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except:
        return "No open ports detected."

# Crear carpeta de reportes
def create_report_folder():
    if not os.path.exists("BlackRecon-Reports"):
        os.makedirs("BlackRecon-Reports")

# Guardar reporte
def save_report(report_name, results):
    create_report_folder()
    now = datetime.now()
    with open(f"BlackRecon-Reports/{report_name}.txt", "w") as f:
        f.write("="*60 + "\n")
        f.write("BLACKRECON AUDIT REPORT\n")
        f.write("Developed by Thomas O'Neil Álvarez\n")
        f.write("GitHub: https://github.com/ccyl13\n")
        f.write("="*60 + "\n")
        f.write(f"Date: {now.strftime('%Y-%m-%d')}\n")
        f.write(f"Time: {now.strftime('%H:%M:%S')}\n")
        f.write("="*60 + "\n\n")
        for item in results:
            f.write(f"> {item['subdomain']}\n")
            f.write(f"    - IP: {item['ip']}\n")
            f.write(f"    - Technologies:\n")
            for tech in item['tech_list']:
                f.write(f"        * {tech}\n")
            f.write(f"    - Open Ports:\n")
            for port in item['ports_list']:
                f.write(f"        * {port}\n")
            f.write("-" * 50 + "\n")

    print(Fore.GREEN + f"\n✅ Report saved at BlackRecon-Reports/{report_name}.txt")

# Programa principal
def main():
    print_banner()
    check_requirements()

    domain = input(Fore.YELLOW + "Enter the domain to audit (example: example.com): ").strip()
    if not domain:
        print(Fore.RED + "Domain cannot be empty. Exiting.")
        sys.exit(1)

    print(Fore.CYAN + f"\nStarting reconnaissance on {domain}...\n")
    subdomains = enumerate_subdomains(domain)

    if not subdomains or subdomains == ['']:
        print(Fore.RED + "\n❌ No subdomains found or error running subfinder.")
        sys.exit(1)

    results = []

    for sub in subdomains:
        if sub.strip() == "":
            continue
        print(Fore.BLUE + f"> {sub}")
        ip = resolve_ip(sub)
        if ip:
            print(Fore.GREEN + f"    - IP: {ip}")
            tech = detect_technologies(sub)
            tech_list = [t.strip() for t in tech.split(",")] if tech else ["Unknown"]
            print(Fore.MAGENTA + "    - Technologies:")
            for t in tech_list:
                print(Fore.MAGENTA + f"        * {t}")

            ports = scan_ports(ip)
            ports_list = [line.strip() for line in ports.splitlines() if "open" in line]
            if ports_list:
                print(Fore.YELLOW + "    - Open Ports:")
                for p in ports_list:
                    print(Fore.YELLOW + f"        * {p}")
            else:
                print(Fore.YELLOW + "    - Open Ports: None found")

            results.append({
                "subdomain": sub,
                "ip": ip,
                "tech_list": tech_list,
                "ports_list": ports_list if ports_list else ["No open ports detected."]
            })
        else:
            print(Fore.RED + "    - IP: Not resolved")

        print("-" * 50)
        time.sleep(0.2)

    choice = input(Fore.YELLOW + "\nDo you want to save the report? (Y/n): ").strip().lower()
    if choice in ["", "y", "yes"]:
        report_name = input(Fore.YELLOW + "Enter report name (without extension): ").strip()
        if not report_name:
            report_name = "report"
        save_report(report_name, results)
    else:
        print(Fore.CYAN + "\nNo report saved.")

    print(Fore.CYAN + "\nBye Bye! Hasta la próxima auditoría. 🚀\n")

if __name__ == "__main__":
    main()
