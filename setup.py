#!/usr/bin/env python3
import sys
import os
import re
import asyncio
import aiohttp
import json
import random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config.config import get_random_user_agent  # Función para obtener un User-Agent aleatorio
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    banner_text = f"""
{Fore.PURPLE}{Style.BRIGHT}


███╗░░░███╗███████╗██████╗░██╗░░░██╗░██████╗░░░░░░░██████╗███████╗░█████╗░██████╗░░█████╗░██╗░░██╗
████╗░████║██╔════╝██╔══██╗██║░░░██║██╔════╝░░░░░░██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║░░██║
██╔████╔██║█████╗░░██║░░██║██║░░░██║╚█████╗░█████╗╚█████╗░█████╗░░███████║██████╔╝██║░░╚═╝███████║
██║╚██╔╝██║██╔══╝░░██║░░██║██║░░░██║░╚═══██╗╚════╝░╚═══██╗██╔══╝░░██╔══██║██╔══██╗██║░░██╗██╔══██║
██║░╚═╝░██║███████╗██████╔╝╚██████╔╝██████╔╝░░░░░░██████╔╝███████╗██║░░██║██║░░██║╚█████╔╝██║░░██║
╚═╝░░░░░╚═╝╚══════╝╚═════╝░░╚═════╝░╚═════╝░░░░░░░╚═════╝░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

    [*] Information Disclosure Search Tool
{Style.RESET_ALL}
    """
    print(banner_text)

# Configuración de delays (en segundos)
DELAY_MIN = 2
DELAY_MAX = 6
def apply_delay():
    delay = random.uniform(DELAY_MIN, DELAY_MAX)
    #print(f"[+] Applying delay: {round(delay, 2)} seconds")
    return delay

# Listado de patrones regex para buscar posibles filtraciones (se incluyen muchos ejemplos)
REGEX_PATTERNS = [
    # ------------------------ AWS ------------------------ #
    (re.compile(r'(AWS|aws)?_?(ACCESS|SECRET)?_?(KEY|KEY_ID|ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*[:=]\s*["\']?([A-Za-z0-9/\+=]{16,40})["\']?', re.IGNORECASE), "Possible AWS Key"),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r'ASIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Temp Access Key"),
    (re.compile(r'(?i)aws(.{0,20})?secret(.{0,20})?=\s*[0-9a-zA-Z/+]{40}'), "AWS Secret Key"),

    # ------------------------ Google ------------------------ #
    (re.compile(r'AIza[0-9A-Za-z-_]{35}', re.IGNORECASE), "Google API Key"),
    (re.compile(r'\bGOOGLE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{39})(?:"|\'|)', re.IGNORECASE), "Google API Key (var)"),
    (re.compile(r'\bGOOGLE_CLOUD_PROJECT\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Google Cloud Project ID"),
    
    # ------------------------ Firebase ------------------------ #
    (re.compile(r'\bFIREBASE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase API Key"),
    (re.compile(r'\bFIREBASE_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase Secret"),

    # ------------------------ Azure ------------------------ #
    (re.compile(r'(?i)(AccountKey|SharedKey)\s*=\s*([A-Za-z0-9\+/=]{40,})'), "Azure Storage Key"),

    # ------------------------ Generic Tokens & Secrets ------------------------ #
    (re.compile(r'\bAPI[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_+=]{8,})["\']?', re.IGNORECASE), "Generic API Key"),
    (re.compile(r'\bSECRET[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_+=]{8,})["\']?', re.IGNORECASE), "Generic Secret Key"),
    (re.compile(r'\bTOKEN\s*[:=]\s*["\']?([A-Za-z0-9-_]{20,})["\']?', re.IGNORECASE), "Generic Token"),
    (re.compile(r'\bBEARER\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'\bPRIVATE[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_=]+)["\']?', re.IGNORECASE), "Private Key"),
    (re.compile(r'-----BEGIN (RSA|EC|DSA)? PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA)? PRIVATE KEY-----'), "Complete Private Key Block"),

    # ------------------------ GitLab ------------------------ #
    (re.compile(r'\bglpat-[A-Za-z0-9-_]{20,}', re.IGNORECASE), "GitLab Personal Access Token"),
    (re.compile(r'\bGITLAB_PERSONAL_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "GitLab PAT (var)"),

    # ------------------------ Heroku ------------------------ #
    (re.compile(r'\bHEROKU_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Heroku API Key"),

    # ------------------------ Docker / NPM / SonarQube ------------------------ #
    (re.compile(r'\bDOCKER_CONFIG\s*:\s*(?:"|\'|)([A-Za-z0-9-_=\n]+)(?:"|\'|)', re.IGNORECASE), "Docker Config"),
    (re.compile(r'\bNPM_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "NPM Token"),
    (re.compile(r'\bSONARQUBE_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "SonarQube Token"),

    # ------------------------ Databases (genéricos) ------------------------ #
    (re.compile(r'\b(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*[:=]\s*["\']?([A-Za-z0-9@#$%^&+=\-_!]{6,})["\']?', re.IGNORECASE), "Database Password"),

    # ------------------------ OAuth / Client Secrets / Bearer ------------------------ #
    (re.compile(r'(client_secret|app_secret)\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,})["\']?', re.IGNORECASE), "OAuth Client Secret"),
    (re.compile(r'(authorization|api_key|api_token)\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,})["\']?', re.IGNORECASE), "Auth / API Key"),

    # ------------------------ Contraseñas genéricas ------------------------ #
    (re.compile(r'\b(pass|password|passwd)\s*[:=]\s*["\']?([A-Za-z0-9@#$%^&*()_+!\-]{6,})["\']?', re.IGNORECASE), "Possible Password"),

    # ------------------------ Microsoft ------------------------ #
    (re.compile(r'(eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9\.\-_]+\.[A-Za-z0-9\.\-_]+)', re.IGNORECASE), "JWT Token"),
    (re.compile(r'(?i)azure(.{0,20})?client(.{0,20})?id\s*[:=]\s*["\']?([a-f0-9-]{36})["\']?', re.IGNORECASE), "Azure Client ID"),
    (re.compile(r'(?i)azure(.{0,20})?tenant(.{0,20})?id\s*[:=]\s*["\']?([a-f0-9-]{36})["\']?', re.IGNORECASE), "Azure Tenant ID"),
    (re.compile(r'(?i)azure(.{0,20})?client(.{0,20})?secret\s*[:=]\s*["\']?([A-Za-z0-9\+\/=]{32,})["\']?', re.IGNORECASE), "Azure Client Secret"),

    # ------------------------ GitHub Additional ------------------------ #
    (re.compile(r'(?i)gho_[A-Za-z0-9]{36,}', re.IGNORECASE), "GitHub OAuth Token"),
    (re.compile(r'(?i)ghu_[A-Za-z0-9]{36,}', re.IGNORECASE), "GitHub User Token"),
    (re.compile(r'(?i)ghs_[A-Za-z0-9]{36,}', re.IGNORECASE), "GitHub Secret Token"),

    # ------------------------ Payment Gateways ------------------------ #
    (re.compile(r'\bsk_live_[A-Za-z0-9]{32,}', re.IGNORECASE), "Stripe Secret Live Key"),
    (re.compile(r'\bpk_live_[A-Za-z0-9]{32,}', re.IGNORECASE), "Stripe Publishable Live Key"),
    (re.compile(r'sandbox_[A-Za-z0-9]{32,}', re.IGNORECASE), "Payment Gateway Sandbox Key"),

    # ------------------------ MongoDB ------------------------ #
    (re.compile(r'mongodb\+srv:\/\/[A-Za-z0-9]+:[A-Za-z0-9@#$%^&*()_+\-=!]+@[a-z0-9\.-]+\/[a-zA-Z0-9\-_]+', re.IGNORECASE), "MongoDB Connection String"),
    (re.compile(r'\bMONGO_INITDB_ROOT_PASSWORD\s*:\s*(["\']?)([A-Za-z0-9@#$%^&+=]{8,})\1', re.IGNORECASE), "MongoDB Root Password"),

    # ------------------------ PostgreSQL / MySQL ------------------------ #
    (re.compile(r'\bPOSTGRES_PASSWORD\s*[:=]\s*(["\']?)([A-Za-z0-9@#$%^&+=]{8,})\1', re.IGNORECASE), "PostgreSQL Password"),
    (re.compile(r'\bMYSQL_ROOT_PASSWORD\s*[:=]\s*(["\']?)([A-Za-z0-9@#$%^&+=]{8,})\1', re.IGNORECASE), "MySQL Root Password"),
    
    # ------------------------ Firebase (Additional Patterns) ------------------------ #
    (re.compile(r'\bFIREBASE_ADMIN_SDK\s*:\s*(["\']?)([A-Za-z0-9\-_]{30,})\1', re.IGNORECASE), "Firebase Admin SDK Key"),
    (re.compile(r'\bFIREBASE_CLIENT_EMAIL\s*:\s*(["\']?)([a-zA-Z0-9\._%+\-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})\1', re.IGNORECASE), "Firebase Client Email"),

    # ------------------------ Jenkins ------------------------ #
    (re.compile(r'\bJENKINS_API_TOKEN\s*[:=]\s*(["\']?)([A-Za-z0-9\-_]{30,})\1', re.IGNORECASE), "Jenkins API Token"),

    # ------------------------ Cloudflare ------------------------ #
    (re.compile(r'\bCLOUDFLARE_API_KEY\s*[:=]\s*(["\']?)([A-Za-z0-9\-_]{37})\1', re.IGNORECASE), "Cloudflare API Key"),
    (re.compile(r'\bCLOUDFLARE_API_TOKEN\s*[:=]\s*(["\']?)([A-Za-z0-9\-_]{40})\1', re.IGNORECASE), "Cloudflare API Token"),

    # ------------------------ Shopify ------------------------ #
    (re.compile(r'\bshps_[a-f0-9]{32}', re.IGNORECASE), "Shopify Private App Key"),
    (re.compile(r'\bshopify_access_token\s*:\s*(["\']?)([a-f0-9]{32})\1', re.IGNORECASE), "Shopify Access Token"),

    # ------------------------ Amazon SNS / SQS ------------------------ #
    (re.compile(r'arn:aws:sns:[a-z0-9\-]+:[0-9]+:[a-zA-Z0-9\-_]+', re.IGNORECASE), "Amazon SNS ARN"),
    (re.compile(r'arn:aws:sqs:[a-z0-9\-]+:[0-9]+:[a-zA-Z0-9\-_]+', re.IGNORECASE), "Amazon SQS ARN"),

    # ------------------------ General Sensitive Information ------------------------ #
    (re.compile(r'(access_token|auth_token)\s*[:=]\s*(["\']?)([A-Za-z0-9\-_~+/]{16,})\2', re.IGNORECASE), "General Access/Auth Token"),
    (re.compile(r'(secret|private_key)\s*[:=]\s*(["\']?)([A-Za-z0-9\-_+/]{32,})\2', re.IGNORECASE), "Private Key or Secret"),
    (re.compile(r'(authorization:\s*Bearer\s*)([A-Za-z0-9\-_]{30,})', re.IGNORECASE), "Authorization Bearer Token"),

    # ------------------------ 'Catch all' personalizable ------------------------ #
    (re.compile(r'(key|secret|token|pwd|pass|private)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{8,})["\']?', re.IGNORECASE), "Generic Sensitive Keyword"),

    # ------------------------ SSH Keys ------------------------ #
    (re.compile(r'-----BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----[\s\S]*?-----END (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----', re.IGNORECASE), "SSH Private Key"),
    (re.compile(r'-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----', re.IGNORECASE), "SSH Public Key"),

    # ------------------------ S3 Configuration ------------------------ #
    (re.compile(r's3://[A-Za-z0-9.\-_]{3,255}', re.IGNORECASE), "Amazon S3 Bucket URL"),
    (re.compile(r'\bS3_BUCKET\s*[:=]\s*["\']?([a-z0-9.\-_]{3,255})["\']?', re.IGNORECASE), "Amazon S3 Bucket Name"),

   # ------------------------ SFTP Credentials ------------------------ #
    (re.compile(r'\bSFTP_PASSWORD\s*[:=]\s*["\']?([A-Za-z0-9@#$%^&+=\-_!]{8,})["\']?', re.IGNORECASE), "SFTP Password"),
    (re.compile(r'\bSFTP_PRIVATE_KEY\s*:\s*["\']?-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----[\s\S]*?-----END (RSA|DSA|EC) PRIVATE KEY-----["\']?', re.IGNORECASE), "SFTP Private Key"),

    # ------------------------ General Certificate Files ------------------------ #
    (re.compile(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', re.IGNORECASE), "SSL Certificate"),
    (re.compile(r'-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----', re.IGNORECASE), "SSL Certificate Request"),
   
    # ------------------------ Additional Generic Patterns ------------------------ #
    (re.compile(r'\bAPI_SECRET\s*[:=]\s*["\']?([A-Za-z0-9\-_]{32,})["\']?', re.IGNORECASE), "Generic API Secret"),
    (re.compile(r'\bDATABASE_URL\s*[:=]\s*["\']?([A-Za-z0-9+@:/\-._]{25,})["\']?', re.IGNORECASE), "Database URL with Credentials"),
]

# Parámetros de configuración para la concurrencia y timeout
CONCURRENCY_LIMIT = 100
TIMEOUT = 10

async def crawl(url, depth, max_depth, session, semaphore, visited):
    findings = []
    if url in visited:
        return findings
    visited.add(url)
    try:
        async with semaphore:
            headers = {"User-Agent": get_random_user_agent()}
            async with session.get(url, headers=headers, timeout=TIMEOUT) as response:
                if response.status != 200:
                    print(f"{Fore.YELLOW}[CRAWL] Skipped {url} with status {response.status}{Style.RESET_ALL}")
                    return findings
                content = await response.text()
                # Aplicar delay aleatorio para evitar saturar el servidor
                await asyncio.sleep(apply_delay())
    except Exception as e:
        print(f"{Fore.RED}[CRAWL] Error fetching {url}: {e}{Style.RESET_ALL}")
        return findings
    
    # Buscar patrones en el contenido de la página
    for pattern, label in REGEX_PATTERNS:
        matches = pattern.findall(content)
        for match in matches:
            findings.append({
                "type": label,
                "leaked": match,
                "URL": url
            })
    print(f"{Fore.CYAN}[CRAWL] Processed {url} at depth {depth} - findings: {len(findings)}{Style.RESET_ALL}")
    
    # Si aún no alcanzamos la profundidad máxima, extraer enlaces y continuar el crawl
    if depth < max_depth:
        soup = BeautifulSoup(content, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            absolute = urljoin(url, href)
            # Limitar la exploración al mismo dominio
            base_netloc = urlparse(url).netloc
            link_netloc = urlparse(absolute).netloc
            if base_netloc == link_netloc:
                links.add(absolute)
        tasks = []
        for link in links:
            if link not in visited:
                tasks.append(crawl(link, depth + 1, max_depth, session, semaphore, visited))
        if tasks:
            results = await asyncio.gather(*tasks)
            for sub_findings in results:
                findings.extend(sub_findings)
    return findings

async def process_domain(domain, max_depth, semaphore):
    # Asegurarse de que el dominio incluya el protocolo
    if not domain.startswith("http://") and not domain.startswith("https://"):
        seed_url = "http://" + domain
    else:
        seed_url = domain
    visited = set()
    async with aiohttp.ClientSession() as session:
        findings = await crawl(seed_url, 0, max_depth, session, semaphore, visited)
    return findings

async def main_async(input_file, max_depth):
    # Leer dominios/subdominios desde el archivo de entrada
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not read input file: {e}{Style.RESET_ALL}")
        return
    
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    all_findings = []
    for domain in domains:
        print(f"{Fore.YELLOW}[MAIN] Processing domain: {domain}{Style.RESET_ALL}")
        findings = await process_domain(domain, max_depth, semaphore)
        all_findings.extend(findings)
    
    os.makedirs("output", exist_ok=True)
    with open("output/InformationDisclosure.txt", "w", encoding="utf-8") as f:
        for item in all_findings:
            f.write(f"[{item['type']}] : {item['leaked']} : {item['URL']}\n")
    with open("output/InformationDisclosure.json", "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=4)
    print(f"{Fore.GREEN}[MAIN] Saved {len(all_findings)} findings to output files.{Style.RESET_ALL}")

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Crawl domains up to a specified depth and search for information disclosure patterns."
    )
    parser.add_argument("-o", "--input", required=True, help="Archivo de entrada con dominios/subdominios (uno por línea)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Profundidad máxima para el crawl (default: 2)")
    args = parser.parse_args()
    
    banner()
    asyncio.run(main_async(args.input, args.depth))

if __name__ == "__main__":
    main()
