import os
import sys
import json
import logging
import socket
import requests
import dns.resolver
import asyncio
import aiohttp
import time
import itertools # <-- NOWY IMPORT (v6.0)
import aiodns # <-- NOWY IMPORT (v6.0)
from typing import List, Dict, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
from aiohttp_retry import RetryClient, ExponentialRetry

# ==============================================================================
# KONFIGURACJA LOGOWANIA I KOLORÓW
# ==============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
log = logging.getLogger("AdvancedEASM")

# Wyłącz gadatliwe loggery (requests, aiohttp)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("aiohttp_retry").setLevel(logging.WARNING)
logging.getLogger("aiodns").setLevel(logging.WARNING)
requests.packages.urllib3.disable_warnings()

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text): print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}\n {text}\n{'=' * 60}{Colors.ENDC}")
def print_success(text): print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")
def print_fail(text): print(f"{Colors.FAIL}{Colors.BOLD}[!] ZNALEZISKO: {text}{Colors.ENDC}")
def print_info(text): print(f"{Colors.BLUE}[i] {text}{Colors.ENDC}")
def print_warn(text): print(f"{Colors.WARNING}[?] Ostrzeżenie: {text}{Colors.ENDC}")

# ==============================================================================
# === BARDZO WAŻNE: KONFIGURACJA UŻYTKOWNIKA ===
# ==============================================================================
GITHUB_API_TOKEN = "" # <-- WKLEJ TUTAJ SWÓJ TOKEN GITHUB
HIBP_API_KEY = "" # <-- WKLEJ TUTAJ SWÓJ KLUCZ HIBP
VIRUSTOTAL_API_KEY = "" # <-- (v4.0) WKLEJ TUTAJ SWÓJ KLUCZ VT

# --- NOWE GLOBALS (v6.0) ---
CUSTOM_SUBDOMAIN_LIST_PATH = None
CUSTOM_CLOUD_LIST_PATH = None
# ==============================================================================


# --- ZAKTUALIZOWANE LISTY (v3.0) ---
SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "test", "stage", "staging", "prod", "production", "uat", "preprod",
    "admin", "dashboard", "panel", "login", "auth", "sso", "idp",
    "mail", "webmail", "owa", "smtp", "imap", "pop", "autodiscover",
    "vpn", "remote", "gw", "gateway", "access", "portal",
    "app", "blog", "shop", "store", "support", "help", "helpdesk",
    "files", "storage", "backup", "data", "db", "sql", "mysql", "mongo", "redis",
    "git", "gitlab", "github", "ci", "cd", "jenkins", "teamcity", "build",
    "docker", "k8s", "kube", "registry", "kubernetes",
    "intranet", "extranet", "partner", "partners", "client", "clients", "demo",
    "us", "eu", "as", "uk", "fr", "de", "pl",
    "us-east-1", "us-west-1", "eu-west-1", "eu-central-1",
    "old", "legacy", "internal", "external", "corp", "company",
    "ftp", "sftp", "ssh", "rdp", "cpanel", "plesk", "mfa",
    "assets", "static", "media", "content", "cdn",
    "sandbox", "devops", "jira", "confluence", "wiki",
    "api-v1", "api-v2", "api-dev", "api-test",
    "payments", "billing", "checkout", "account", "accounts",
    "azure", "aws", "gcp", "cloud",
    "dev-api", "test-api", "prod-api",
    "dev-app", "test-app", "prod-app",
    "dev-db", "test-db", "prod-db"
]

CLOUD_RESOURCE_WORDLIST = [
    "assets", "backup", "backups", "data", "files", "images", "logs", "media",
    "prod", "production", "public", "share", "shared", "static", "storage",
    "test", "uploads", "web", "www", "sql", "db", "dev", "api", "database",
    "cosmos", "prod-storage", "dev-storage", "prod-db", "dev-db",
    "company", "corp", "internal", "private", "public-assets", "client-files",
    "redis", "cache", "search", "apim"
]

GITHUB_KEYWORDS = [
    "api_key", "apikey", "secret_key", "secretkey", "password", "token",
    "client_secret", "id_rsa", ".npmrc", ".env", "config", "credentials",
    "connectionstring", "AZURE_STORAGE_CONNECTION_STRING", "AWS_ACCESS_KEY_ID"
]

COMMON_EMAIL_PREFIXES = [
    "admin", "administrator", "it", "support", "helpdesk", "security",
    "kontakt", "biuro", "info", "dev", "test", "root", "abuse",
    "billing", "sales", "marketing", "hr", "ceo", "management",
    "postmaster", "webmaster", "devops", "sysadmin", "undisclosed-recipients"
]

TOP_PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 135, 139, 143,
    179, 199, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636,
    873, 990, 993, 995,
    1025, 1026, 1027, 1080, 1110, 1433, 1434, 1521, 1720, 1723,
    2000, 2001, 2049, 2121, 2222,
    3000, 3128, 3268, 3306, 3389, 4000, 4443, 4444,
    5000, 5009, 5060, 5061, 5190, 5357, 5432, 5601, # 5601 = Kibana
    5800, 5900, 5901, 6000, 6001, 6379, # 6379 = Redis
    7000, 7070, 8000, 8008, 8009, 8080, 8081, 8088,
    8181, 8443, 8888, 9000, 9090, 9100, 9200, # 9200 = Elasticsearch
    9443, 9999, 10000,
    11211, 27017, # 27017 = MongoDB
    32768, 32769
]

# --- NOWE LISTY (v6.0) ---
TYPOSQUAT_HOMOGLYPHS = {'o': ['0'], 'l': ['1', 'i'], 'i': ['1', 'l'], 'e': ['3'], 'a': ['4']}
TYPOSQUAT_PREFIXES = ['login-', 'support-', 'help-', 'konto-', 'panel-', 'admin-', 'app-']
TYPOSQUAT_SUFFIXES = ['-login', '-support', '-help', '-konto', '-panel', '-admin', '-app', '-online', '-net']

# Globalny słownik przechowujący stan skanowania
EASM_RESULTS = {}

def reset_easm_results(domain: str) -> str:
    """Resetuje globalny słownik EASM_RESULTS dla nowego celu."""
    global EASM_RESULTS
    EASM_RESULTS = {
        "domain": domain,
        "base_ip": "",
        "subdomains_found_bruteforce": [],
        "crtsh_subdomains": [],
        "vt_subdomains": [],
        "all_unique_subdomains": [],
        "open_ports_on_targets": {},
        "cloud_resources_found": [],
        "github_org_repos": [],
        "github_leaks_found": [],
        "pwned_emails_found": [],
        "typosquat_domains_found": [] # <-- NOWA SEKCJA
    }
    try:
        ip = socket.gethostbyname(domain)
        EASM_RESULTS["base_ip"] = ip
        print_info(f"Domena '{domain}' rozwiązana na adres IP: {ip}")
        return ip
    except socket.gaierror as e:
        print_fail(f"Nie można rozwiązać nazwy domeny: {domain}. {e}")
        return ""

# --- NOWA FUNKCJA (v6.0) ---
def load_wordlist(path: Optional[str], default_list: List[str]) -> List[str]:
    """Wczytuje wordlistę z pliku, jeśli podano, lub zwraca domyślną."""
    if path and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                custom_list = [line.strip() for line in f if line.strip()]
            print_success(f"Pomyślnie wczytano {len(custom_list)} wpisów z {path}")
            return custom_list
        except Exception as e:
            print_fail(f"Nie można wczytać pliku {path}: {e}. Używam domyślnej listy.")
            return default_list
    return default_list

# --- Moduł 1: Skaner Subdomen (Brute-force) ---
async def check_subdomain(session: RetryClient, subdomain: str) -> Optional[str]:
    """Asynchronicznie sprawdza, czy subdomena istnieje."""
    try:
        async with session.get(f"http://{subdomain}", timeout=5) as response:
            return subdomain # Zwróć sukces, nawet jeśli status to 404/500
    except (aiohttp.ClientConnectorError, socket.gaierror, asyncio.TimeoutError):
        return None # Domena nie istnieje
    except Exception:
        return subdomain # Inne błędy (np. SSL) mogą oznaczać, że domena istnieje

async def find_subdomains_bruteforce(domain: str) -> List[str]:
    """Uruchamia asynchroniczny brute-force subdomen."""
    # --- ZAKTUALIZOWANE (v6.0) ---
    wordlist = load_wordlist(CUSTOM_SUBDOMAIN_LIST_PATH, SUBDOMAIN_WORDLIST)
    print_info(f"Rozpoczynam brute-force subdomen (ponad {len(wordlist)} prób)...")
    found_subdomains = []
    
    retry_options = ExponentialRetry(attempts=3)
    async with RetryClient(retry_options=retry_options) as session:
        tasks = []
        for word in wordlist: # <-- ZAKTUALIZOWANE
            subdomain = f"{word}.{domain}"
            tasks.append(check_subdomain(session, subdomain))
            
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                print_fail(f"[Brute-Force] Odkryto subdomenę: {res}")
                found_subdomains.append(res)
                
    EASM_RESULTS["subdomains_found_bruteforce"] = found_subdomains
    print_success(f"Zakończono skanowanie brute-force subdomen. Znaleziono: {len(found_subdomains)}")
    return found_subdomains

# --- Moduł 2: Skaner Zasobów Chmurowych (Rozszerzony) ---
def check_cloud_resource_name(name: str) -> Optional[Tuple[str, str]]:
    """Sprawdza, czy nazwa zasobu chmurowego jest publicznie dostępna (S3, Blob, GCS, SQL, Cosmos, Firebase, ...)."""
    
    # 1. Sprawdź AWS S3
    s3_url = f"http://{name}.s3.amazonaws.com"
    try:
        response = requests.head(s3_url, timeout=3)
        if response.status_code == 200:
            print_fail(f"Odkryto publiczny bucket AWS S3: {s3_url}")
            return ("AWS S3", s3_url)
    except requests.exceptions.RequestException: pass

    # 2. Sprawdź Azure Blob
    blob_url = f"https://{name}.blob.core.windows.net"
    try:
        response = requests.head(blob_url, timeout=3, verify=False)
        if response.status_code == 200:
            print_fail(f"Odkryto konto Azure Blob: {blob_url}")
            return ("Azure Blob", blob_url)
    except requests.exceptions.RequestException: pass
        
    # 3. Sprawdź Google Cloud Storage (GCS)
    gcs_url = f"https://storage.googleapis.com/{name}"
    try:
        response = requests.head(gcs_url, timeout=3)
        if response.status_code == 200 or response.status_code == 403:
            print_fail(f"Odkryto bucket Google GCS: {gcs_url}")
            return ("Google GCS", gcs_url)
    except requests.exceptions.RequestException: pass

    # 4. Sprawdź Azure SQL
    sql_url_host = f"{name}.database.windows.net"
    try:
        socket.gethostbyname(sql_url_host)
        print_fail(f"Odkryto serwer Azure SQL: https://{sql_url_host}")
        return ("Azure SQL", f"https://{sql_url_host}")
    except socket.gaierror: pass

    # 5. Sprawdź Azure Cosmos DB
    cosmos_url_host = f"{name}.documents.azure.com"
    try:
        socket.gethostbyname(cosmos_url_host)
        print_fail(f"Odkryto konto Azure Cosmos DB: https://{cosmos_url_host}")
        return ("Azure CosmosDB", f"https://{cosmos_url_host}")
    except socket.gaierror: pass
        
    # 6. Sprawdź Google Firebase
    firebase_url = f"https://{name}.firebaseio.com/.json"
    try:
        response = requests.get(firebase_url, timeout=3)
        if response.status_code == 200:
            print_fail(f"Odkryto PUBLICZNĄ bazę Firebase: {firebase_url}")
            return ("Google Firebase (PUBLIC)", firebase_url)
        if response.status_code == 401:
            print_fail(f"Odkryto PRYWATNĄ bazę Firebase: {firebase_url}")
            return ("Google Firebase (Private)", firebase_url)
    except requests.exceptions.RequestException: pass
    
    # 7. Sprawdź Azure App Service
    app_url_host = f"{name}.azurewebsites.net"
    try:
        socket.gethostbyname(app_url_host)
        print_fail(f"Odkryto usługę Azure App Service: https://{app_url_host}")
        return ("Azure App Service", f"https://{app_url_host}")
    except socket.gaierror: pass
    
    # 8. Sprawdź Azure Redis
    redis_url_host = f"{name}.redis.cache.windows.net"
    try:
        socket.gethostbyname(redis_url_host)
        print_fail(f"Odkryto usługę Azure Redis: {redis_url_host}")
        return ("Azure Redis", redis_url_host)
    except socket.gaierror: pass

    # 9. Sprawdź Azure Search
    search_url_host = f"{name}.search.windows.net"
    try:
        socket.gethostbyname(search_url_host)
        print_fail(f"Odkryto usługę Azure Cognitive Search: https://{search_url_host}")
        return ("Azure Search", f"https://{search_url_host}")
    except socket.gaierror: pass

    # 10. Sprawdź Azure API Management
    apim_url_host = f"{name}.azure-api.net"
    try:
        socket.gethostbyname(apim_url_host)
        print_fail(f"Odkryto usługę Azure API Management: https://{apim_url_host}")
        return ("Azure API-M", f"https://{apim_url_host}")
    except socket.gaierror: pass
    
    return None

def find_cloud_resources(domain: str):
    """Generuje permutacje nazw i sprawdza popularne zasoby chmurowe."""
    # --- ZAKTUALIZOWANE (v6.0) ---
    wordlist = load_wordlist(CUSTOM_CLOUD_LIST_PATH, CLOUD_RESOURCE_WORDLIST)
    print_info(f"Rozpoczynam wyszukiwanie publicznych zasobów chmurowych ({len(wordlist)} prób)...")
    domain_base = domain.split('.')[0] # z 'firma.com' bierz 'firma'
    permutations = set()
    
    for word in wordlist: # <-- ZAKTUALIZOWANE
        permutations.add(f"{domain_base}-{word}")
        permutations.add(f"{domain_base}{word}")
        permutations.add(f"{word}-{domain_base}")
        permutations.add(f"{domain_base}")
    
    found_storage = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_cloud_resource_name, name): name for name in permutations}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_storage.append({"type": result[0], "url": result[1]})

    EASM_RESULTS["cloud_resources_found"] = found_storage
    print_success(f"Zakończono skanowanie chmury. Znaleziono: {len(found_storage)}")

# --- Moduł 3: Skaner Wycieków Kodu (GitHub) ---
def find_github_leaks(domain: str):
    """Przeszukuje GitHub w poszukiwaniu wrażliwych słów kluczowych w połączeniu z domeną."""
    print_info("Rozpoczynam wyszukiwanie potencjalnych wycieków kodu na GitHub...")
    if not GITHUB_API_TOKEN:
        print_fail("Brak GITHUB_API_TOKEN na górze skryptu!")
        print_warn("Pomiędzy moduł skanowania GitHub. Wygeneruj token, aby go włączyć.")
        return

    headers = {
        "Authorization": f"token {GITHUB_API_TOKEN}",
        "Accept": "application/vnd.github.v3.text-match+json"
    }
    
    found_leaks = []
    
    for keyword in GITHUB_KEYWORDS:
        query = f'"{domain}" "{keyword}"' # Szukaj domeny ORAZ słowa kluczowego
        url = f"https://api.github.com/search/code?q={query}&per_page=5"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("total_count", 0) > 0:
                for item in data.get("items", []):
                    leak_url = item.get('html_url')
                    repo_name = item.get('repository', {}).get('full_name')
                    details = f"Znaleziono słowo kluczowe '{keyword}' w połączeniu z '{domain}'."
                    print_fail(f"Potencjalny wyciek: {repo_name} (Patrz: {leak_url})")
                    found_leaks.append({
                        "url": leak_url,
                        "repo": repo_name,
                        "keyword": keyword,
                        "details": details
                    })
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print_fail("Osiągnięto limit zapytań GitHub API. Spróbuj później.")
                break # Przerwij pętlę
            else:
                print_warn(f"Błąd zapytania do GitHub: {e}")
        except Exception as e:
            print_warn(f"Nieoczekiwany błąd GitHub: {e}")

    EASM_RESULTS["github_leaks_found"] = found_leaks
    print_success(f"Zakończono skanowanie GitHub. Znaleziono: {len(found_leaks)} potencjalnych wycieków.")

# --- Moduł 4: Skaner Wycieków E-maili (HIBP) ---
def check_hibp_email(email: str) -> List[dict]:
    """Sprawdza pojedynczy e-mail w API Have I Been Pwned."""
    if not HIBP_API_KEY:
        log.warn("Brak HIBP_API_KEY. Pomiędzy moduł HIBP.")
        return []
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "AdvancedEASM-Scanner"
    }
    
    try:
        # HIBP wymaga opóźnienia 1.5 sekundy między zapytaniami
        time.sleep(1.6) 
        
        response = requests.get(url, headers=headers, params={"truncateResponse": "false"})
        
        if response.status_code == 200:
            breaches = response.json()
            print_fail(f"WYCIEK! Adres e-mail {email} znaleziono w {len(breaches)} wyciekach!")
            return breaches
        elif response.status_code == 404:
            print_success(f"Czysto. Adres e-mail {email} nie został znaleziony w żadnym wycieku.")
            return []
        else:
            print_warn(f"Błąd HIBP dla {email}: {response.status_code} - {response.text}")
            return []
            
    except requests.exceptions.RequestException as e:
        print_fail(f"Błąd połączenia z HIBP: {e}")
        return []

def find_pwned_emails(domain: str):
    """Sprawdza popularne adresy e-mail dla domeny w HIBP."""
    print_info(f"Rozpoczynam sprawdzanie popularnych e-maili (@{domain}) w Have I Been Pwned...")
    if not HIBP_API_KEY:
        print_fail("Brak HIBP_API_KEY na górze skryptu!")
        print_warn("Pobierz klucz z https://haveibeenpwned.com/API/Key, aby włączyć ten moduł.")
        return

    found_breaches = []
    
    for prefix in COMMON_EMAIL_PREFIXES:
        email = f"{prefix}@{domain}"
        breaches = check_hibp_email(email)
        if breaches:
            found_breaches.append({
                "email": email,
                "breach_count": len(breaches),
                "breaches": [b.get("Name") for b in breaches]
            })

    EASM_RESULTS["pwned_emails_found"] = found_breaches
    print_success(f"Zakończono skanowanie HIBP. Znaleziono wycieki dla {len(found_breaches)} kont.")

# --- Moduł 5: Skaner Certyfikatów (crt.sh) ---
def find_subdomains_crtsh(domain: str) -> List[str]:
    """Pasywnie odpytuje crt.sh o znane subdomeny z certyfikatów."""
    print_info(f"Rozpoczynam pasywne skanowanie subdomen (crt.sh) dla '%.{domain}'...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found_subdomains = set() # Używamy seta, aby uniknąć duplikatów
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        for entry in data:
            name_value = entry.get("name_value", "")
            if name_value:
                # crt.sh zwraca wiele nazw w jednym polu
                names = name_value.split('\n')
                for name in names:
                    name = name.strip()
                    if name.endswith(f".{domain}") and name != domain and not "*" in name:
                        found_subdomains.add(name)
        
        result_list = list(found_subdomains)
        for sub in result_list:
            print_fail(f"[crt.sh] Odkryto subdomenę: {sub}")
            
        EASM_RESULTS["crtsh_subdomains"] = result_list
        print_success(f"Zakończono skanowanie crt.sh. Znaleziono: {len(result_list)} unikalnych subdomen.")
        return result_list
        
    except requests.exceptions.RequestException as e:
        print_fail(f"Błąd połączenia z crt.sh: {e}")
        return []
    except json.JSONDecodeError:
        print_warn(f"crt.sh zwróciło niepoprawny JSON (prawdopodobnie brak wyników).")
        return []

# --- Moduł 6: Asynchroniczny Skaner Portów (z Banner Grabbing) ---
async def _scan_port_async(ip: str, port: int, timeout: float = 1.0) -> Optional[Tuple[int, str]]:
    """Asynchronicznie sprawdza pojedynczy port TCP i pobiera baner."""
    banner = "N/A (Połączenie nieudane)"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        
        # Spróbuj odczytać baner
        try:
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            if not banner:
                banner = "OK (Połączono, brak baneru)"
        except (asyncio.TimeoutError, socket.error):
            banner = "OK (Połączono, nie można odczytać baneru)"
        
        writer.close()
        await writer.wait_closed()
        return (port, banner)
    except (asyncio.TimeoutError, OSError):
        return None # Port zamknięty

async def _run_port_scan_on_ip_async(ip: str) -> List[Tuple[int, str]]:
    """Uruchamia asynchroniczny skan portów dla danego IP."""
    print_info(f"Rozpoczynam szybkie skanowanie {len(TOP_PORTS_TO_SCAN)} portów TCP na {ip}...")
    open_ports = []
    
    tasks = [_scan_port_async(ip, port) for port in TOP_PORTS_TO_SCAN]
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
            port, banner = res
            open_ports.append((port, banner))
            print_fail(f"[Skan Portów] Odkryto otwarty port: {ip}:{port}")
            print_fail(f"  -> Baner: {banner[:100]}...") # Pokaż pierwsze 100 znaków
            
    if not open_ports:
        print_success(f"Nie znaleziono otwartych portów (z Top {len(TOP_PORTS_TO_SCAN)}) na {ip}.")
    
    return open_ports

# --- Moduł 7: Skaner Certyfikatów (VirusTotal) ---
def find_subdomains_virustotal(domain: str) -> List[str]:
    """Pasywnie odpytuje VirusTotal o znane subdomeny."""
    print_info(f"Rozpoczynam pasywne skanowanie subdomen (VirusTotal) dla '{domain}'...")
    if not VIRUSTOTAL_API_KEY:
        print_fail("Brak VIRUSTOTAL_API_KEY na górze skryptu!")
        print_warn("Pomiędzy moduł VirusTotal. Zdobądź darmowy klucz, aby go włączyć.")
        return []

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=300"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    found_subdomains = set()

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        for entry in data.get("data", []):
            subdomain = entry.get("id")
            if subdomain:
                found_subdomains.add(subdomain)
        
        result_list = list(found_subdomains)
        for sub in result_list:
            print_fail(f"[VirusTotal] Odkryto subdomenę: {sub}")
            
        EASM_RESULTS["vt_subdomains"] = result_list
        print_success(f"Zakończono skanowanie VirusTotal. Znaleziono: {len(result_list)} unikalnych subdomen.")
        return result_list
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print_fail("Błąd VirusTotal: Nieautoryzowany. Sprawdź swój VIRUSTOTAL_API_KEY.")
        else:
            print_fail(f"Błąd połączenia z VirusTotal (HTTP {e.response.status_code}): {e}")
        return []
    except Exception as e:
        print_fail(f"Błąd połączenia z VirusTotal: {e}")
        return []

# --- Moduł 8: Skaner Organizacji GitHub ---
def find_github_organization(domain: str):
    """Przeszukuje GitHub w poszukiwaniu Organizacji i jej publicznych repozytoriów."""
    print_info("Rozpoczynam wyszukiwanie Organizacji GitHub...")
    if not GITHUB_API_TOKEN:
        print_fail("Brak GITHUB_API_TOKEN. Pomiędzy moduł skanowania Organizacji GitHub.")
        return

    headers = {"Authorization": f"token {GITHUB_API_TOKEN}"}
    domain_base = domain.split('.')[0]
    
    # 1. Wyszukaj organizację pasującą do nazwy domeny
    search_url = f"https://api.github.com/search/users?q={domain_base}+type:org"
    
    try:
        response = requests.get(search_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get("total_count", 0) == 0:
            print_success(f"Nie znaleziono organizacji GitHub pasującej do '{domain_base}'.")
            return

        # Bierzemy pierwszy, najbardziej trafny wynik
        org_login = data["items"][0]["login"]
        print_fail(f"[GitHub Org] Znaleziono pasującą organizację: {org_login} (https://github.com/{org_login})")
        
        # 2. Wylistuj publiczne repozytoria tej organizacji
        repos_url = f"https://api.github.com/orgs/{org_login}/repos?type=public&per_page=100"
        repos_response = requests.get(repos_url, headers=headers, timeout=10)
        repos_response.raise_for_status()
        repos_data = repos_response.json()
        
        found_repos = []
        for repo in repos_data:
            repo_name = repo.get('full_name')
            repo_url = repo.get('html_url')
            print_fail(f"  -> Odkryto publiczne repozytorium: {repo_name}")
            found_repos.append({"name": repo_name, "url": repo_url})
            
        EASM_RESULTS["github_org_repos"] = found_repos
        print_success(f"Zakończono skanowanie Organizacji GitHub. Znaleziono: {len(found_repos)} publicznych repozytoriów.")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            print_fail("Osiągnięto limit zapytań GitHub API (Org Scan). Spróbuj później.")
        else:
            print_warn(f"Błąd zapytania do GitHub (Org Scan): {e}")
    except Exception as e:
        print_warn(f"Nieoczekiwany błąd GitHub (Org Scan): {e}")


# --- NOWY MODUŁ (v6.0) ---
# --- Moduł 9: Skaner Typosquattingu ---

def _generate_typosquats(domain: str) -> Set[str]:
    """Generuje listę potencjalnych domen typosquattingowych."""
    print_info("Generowanie permutacji typosquattingu...")
    domain_name, tld = domain.split('.', 1)
    permutations = set()

    # 1. Homoglify (np. f1rma.com)
    for char, replacements in TYPOSQUAT_HOMOGLYPHS.items():
        if char in domain_name:
            for rep in replacements:
                permutations.add(f"{domain_name.replace(char, rep, 1)}.{tld}")

    # 2. Opuszczenie znaku (np. fima.com)
    for i in range(len(domain_name)):
        permutations.add(f"{domain_name[:i]}{domain_name[i+1:]}.{tld}")

    # 3. Podwójny znak (np. fiirma.com)
    for i in range(len(domain_name)):
        permutations.add(f"{domain_name[:i+1]}{domain_name[i]}{domain_name[i+1:]}.{tld}")

    # 4. Prefiksy (np. login-firma.com)
    for prefix in TYPOSQUAT_PREFIXES:
        permutations.add(f"{prefix}{domain_name}.{tld}")
        
    # 5. Sufiksy (np. firma-support.com)
    for suffix in TYPOSQUAT_SUFFIXES:
        permutations.add(f"{domain_name}{suffix}.{tld}")
        
    print_info(f"Wygenerowano {len(permutations)} unikalnych kandydatów do typosquattingu.")
    return permutations

async def _check_typosquat_domain(resolver: aiodns.DNSResolver, domain: str) -> Optional[str]:
    """Asynchronicznie sprawdza, czy domena typosquattingowa jest zarejestrowana (ma rekord A)."""
    try:
        await resolver.query(domain, 'A')
        # Jeśli nie rzuci błędu, domena istnieje i jest zarejestrowana
        return domain
    except aiodns.error.DNSError:
        return None # Domena nie istnieje
    except Exception as e:
        log.warn(f"Błąd DNS dla {domain}: {e}")
        return None

async def find_typosquatted_domains(domain: str):
    """Orkiestrator Modułu 9: Generuje i sprawdza domeny typosquattingowe."""
    permutations = _generate_typosquats(domain)
    found_domains = []
    
    resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
    tasks = []
    
    for typo_domain in permutations:
        tasks.append(_check_typosquat_domain(resolver, typo_domain))
        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
            print_fail(f"[Typosquatting] Odkryto zarejestrowaną domenę: {res}")
            found_domains.append(res)
            
    EASM_RESULTS["typosquat_domains_found"] = found_domains
    print_success(f"Zakończono skanowanie typosquattingu. Znaleziono: {len(found_domains)} zarejestrowanych domen.")


# ==============================================================================
# FAZA 5: ORKIESTRATOR I MENU (Nowa wersja v6.0)
# ==============================================================================

def check_api_keys():
    """Sprawdza status kluczy API i informuje użytkownika."""
    print_info("Sprawdzanie kluczy API...")
    keys_ok_count = 0
    if GITHUB_API_TOKEN:
        print_success("Klucz GITHUB_API_TOKEN załadowany.")
        keys_ok_count += 1
    else:
        print_warn("Brak GITHUB_API_TOKEN. Moduły GitHub (wycieki, organizacje) nie będą działać.")
        
    if HIBP_API_KEY:
        print_success("Klucz HIBP_API_KEY załadowany.")
        keys_ok_count += 1
    else:
        print_warn("Brak HIBP_API_KEY. Moduł skanowania e-maili (HIBP) nie będzie działać.")
        
    if VIRUSTOTAL_API_KEY:
        print_success("Klucz VIRUSTOTAL_API_KEY załadowany.")
        keys_ok_count += 1
    else:
        print_warn("Brak VIRUSTOTAL_API_KEY. Moduł skanowania subdomen (VirusTotal) nie będzie działać.")
    
    if keys_ok_count == 3:
        print_success("Wszystkie 3 klucze API są załadowane. Pełna moc skanowania włączona.")
    else:
        print_fail(f"Brakuje {3 - keys_ok_count} z 3 kluczy API. Edytuj ten skrypt, aby je dodać i uzyskać pełne wyniki.")
    return keys_ok_count > 0

def _get_all_subdomains_and_ips() -> Set[str]:
    """
    Funkcja pomocnicza: zbiera wszystkie odkryte subdomeny,
    rozwiązuje ich adresy IP i zwraca unikalny zestaw IP.
    """
    print_info("Zbieranie i rozwiązywanie adresów IP wszystkich odkrytych celów...")
    
    # 1. Zbierz wszystkie unikalne subdomeny z wyników
    all_subdomains = set(
        EASM_RESULTS.get("subdomains_found_bruteforce", []) +
        EASM_RESULTS.get("crtsh_subdomains", []) +
        EASM_RESULTS.get("vt_subdomains", [])
    )
    EASM_RESULTS["all_unique_subdomains"] = list(all_subdomains)
    print_info(f"Łącznie {len(all_subdomains)} unikalnych subdomen do sprawdzenia.")

    # 2. Zbierz wszystkie unikalne IP
    all_ips_to_scan = set()
    if EASM_RESULTS.get("base_ip"):
        all_ips_to_scan.add(EASM_RESULTS["base_ip"])
    
    # Użyj ThreadPoolExecutor do szybkiego rozwiązywania DNS
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(socket.gethostbyname, sub): sub for sub in all_subdomains}
        for future in as_completed(futures):
            try:
                ip = future.result()
                all_ips_to_scan.add(ip)
            except socket.gaierror:
                pass # Ignoruj subdomeny, których nie można rozwiązać
            
    print_info(f"Będę skanował porty na {len(all_ips_to_scan)} unikalnych adresach IP: {list(all_ips_to_scan)}")
    return all_ips_to_scan

async def run_port_scan_on_all_targets_async():
    """Orkiestrator Modułu 6: Uruchamia skanowanie portów na wszystkich celach."""
    all_ips = _get_all_subdomains_and_ips()
    if not all_ips:
        print_warn("Nie znaleziono żadnych adresów IP do przeskanowania (być może musisz najpierw uruchomić skan subdomen).")
        return

    open_ports_results = {}
    for ip in all_ips:
        open_ports_with_banners = await _run_port_scan_on_ip_async(ip)
        if open_ports_with_banners:
            # Konwertuj krotki na słowniki dla JSON
            open_ports_results[ip] = [{"port": p, "banner": b} for p, b in open_ports_with_banners]
            
            # Dodatkowe sprawdzenie Elasticsearch/Kibana
            for port, banner in open_ports_with_banners:
                if port == 9200:
                    print_fail(f"[Elasticsearch] Odkryto potencjalną instancję Elasticsearch na {ip}:9200")
                    EASM_RESULTS["cloud_resources_found"].append({"type": "Elasticsearch?", "url": f"http://{ip}:9200"})
                if port == 5601:
                    print_fail(f"[Kibana] Odkryto potencjalny panel Kibana na {ip}:5601")
                    EASM_RESULTS["cloud_resources_found"].append({"type": "Kibana?", "url": f"http://{ip}:5601"})
                
    EASM_RESULTS["open_ports_on_targets"] = open_ports_results

def run_full_easm(domain: str):
    """Uruchamia wszystkie moduły skanowania EASM jeden po drugim."""
    print_header(f"Rozpoczynam Pełny Zaawansowany Skan EASM (v6.0) dla: {domain}")
    
    if not reset_easm_results(domain): # Resetuje i pobiera bazowy IP
        return # Nie można rozwiązać domeny

    # --- Uruchom wszystkie moduły po kolei ---
    
    # 1. Skanowanie Pasywne (Bezpieczne)
    print_header("MODUŁY PASYWNE (Bezpieczne)")
    find_subdomains_crtsh(domain)
    find_subdomains_virustotal(domain)
    find_github_organization(domain)
    find_github_leaks(domain)
    find_pwned_emails(domain)
    
    # 2. Skanowanie Aktywne (Głośne)
    print_header("MODUŁY AKTYWNE (Głośne)")
    asyncio.run(find_subdomains_bruteforce(domain))
    find_cloud_resources(domain)
    
    # 3. Skanowanie Typosquatting (Głośne - DNS)
    asyncio.run(find_typosquatted_domains(domain))

    # 4. Skanowanie Portów (Bardzo Głośne)
    print_header("MODUŁ SKANOWANIA PORTÓW (Bardzo Głośny)")
    asyncio.run(run_port_scan_on_all_targets_async())
    
    # 5. Zapisz raport
    print_header("Zakończono Pełny Skan EASM")
    save_report()

def save_report():
    """Zapisuje aktualny stan EASM_RESULTS do pliku JSON."""
    if not EASM_RESULTS.get("domain"):
        print_fail("Brak danych do zapisania. Najpierw uruchom skan.")
        return

    domain = EASM_RESULTS["domain"]
    report_filename = f"easm_report_{domain}.json"
    print_info(f"Zapisywanie raportu do: {report_filename}...")
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(EASM_RESULTS, f, indent=4, ensure_ascii=False)
        print_success(f"Pełny raport zapisano pomyślnie.")
    except Exception as e:
        print_fail(f"Nie udało się zapisać raportu JSON: {e}")

def main_menu():
    """Główne, interaktywne menu narzędzia."""
    global CUSTOM_SUBDOMAIN_LIST_PATH, CUSTOM_CLOUD_LIST_PATH
    
    print_header("Zaawansowany Skaner Powierzchni Ataku (Advanced EASM) v6.0 (z Menu)")
    print_warn("UŻYWAJ TEGO NARZĘDZIA ODPOWIEDZIALNIE I TYLKO NA CELE, NA KTÓRE MASZ ZGODĘ.")
    
    target_domain = None
    
    # Sprawdź klucze na starcie, aby poinformować użytkownika
    check_api_keys()

    while True:
        print("\n--- MENU GŁÓWNE ---")
        print(f"  [1] Ustaw Domenę Docelową         (Aktualnie: {Colors.CYAN}{target_domain or 'Brak'}{Colors.ENDC})")
        print(f"  [2] Sprawdź Klucze API            (GitHub, HIBP, VirusTotal)")
        print(f"  [0] Ustawienia (Własne Wordlisty)")
        print("-" * 20)
        print(f"  {Colors.BLUE}--- Skanowanie Pasywne (Bezpieczne) ---{Colors.ENDC}")
        print("  [3] Skanuj Subdomeny (crt.sh)")
        print("  [4] Skanuj Subdomeny (VirusTotal)")
        print("  [5] Skanuj Wycieki Kodu (GitHub)")
        print("  [6] Skanuj Organizację (GitHub)")
        print("  [7] Skanuj Wycieki E-maili (HIBP)")
        print(f"  {Colors.WARNING}--- Skanowanie Aktywne (Głośne) ---{Colors.ENDC}")
        print("  [8] Skanuj Subdomeny (Aktywny Brute-force)")
        print("  [9] Skanuj Zasoby Chmurowe (Brute-force)")
        print("  [10] Skanuj Domeny Typosquattingowe (DNS)")
        print("  [11] Skanuj Porty (Top 100 na odkrytych IP)")
        print("-" * 20)
        print(f"  {Colors.FAIL}{Colors.BOLD}[12] URUCHOM PEŁNY SKAN (Wszystkie Moduły){Colors.ENDC}")
        print(f"  {Colors.GREEN}[13] Zapisz Ostatni Raport do JSON{Colors.ENDC}")
        print("\n  [99] Zakończ")

        choice = input(f"\n{Colors.CYAN}Wybierz opcję: {Colors.ENDC}")

        if choice == '1':
            target_domain = input(f"{Colors.CYAN}Podaj domenę do skanowania (np. twoja-firma.com): {Colors.ENDC}").strip()
            if target_domain:
                reset_easm_results(target_domain)
            else:
                target_domain = None
        
        elif choice == '2':
            check_api_keys()
            
        elif choice == '0':
            print_header("Ustawienia Własnych Wordlist")
            sub_path = input(f"{Colors.CYAN}Podaj ścieżkę do wordlisty subdomen (zostaw puste, by użyć domyślnej):\n> {Colors.ENDC}").strip()
            if sub_path and os.path.exists(sub_path):
                CUSTOM_SUBDOMAIN_LIST_PATH = sub_path
                print_success(f"Ustawiono wordlistę subdomen na: {sub_path}")
            else:
                CUSTOM_SUBDOMAIN_LIST_PATH = None
                print_info("Używam domyślnej wordlisty subdomen.")
                
            cloud_path = input(f"{Colors.CYAN}Podaj ścieżkę do wordlisty zasobów chmury (zostaw puste, by użyć domyślnej):\n> {Colors.ENDC}").strip()
            if cloud_path and os.path.exists(cloud_path):
                CUSTOM_CLOUD_LIST_PATH = cloud_path
                print_success(f"Ustawiono wordlistę zasobów chmury na: {cloud_path}")
            else:
                CUSTOM_CLOUD_LIST_PATH = None
                print_info("Używam domyślnej wordlisty zasobów chmury.")

        elif choice in ['3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13']:
            if not target_domain:
                print_fail("Błąd: Najpierw ustaw domenę docelową (Opcja 1).")
                continue
            
            try:
                if choice == '3':
                    print_header("Moduł: Skanowanie Subdomen (crt.sh)")
                    find_subdomains_crtsh(target_domain)
                elif choice == '4':
                    print_header("Moduł: Skanowanie Subdomen (VirusTotal)")
                    find_subdomains_virustotal(target_domain)
                elif choice == '5':
                    print_header("Moduł: Skanowanie Wycieków Kodu (GitHub)")
                    find_github_leaks(target_domain)
                elif choice == '6':
                    print_header("Moduł: Skanowanie Organizacji (GitHub)")
                    find_github_organization(target_domain)
                elif choice == '7':
                    print_header("Moduł: Skanowanie Wycieków E-maili (HIBP)")
                    find_pwned_emails(target_domain)
                elif choice == '8':
                    print_header("Moduł: Skanowanie Subdomen (Brute-force)")
                    asyncio.run(find_subdomains_bruteforce(target_domain))
                elif choice == '9':
                    print_header("Moduł: Skanowanie Zasobów Chmurowych")
                    find_cloud_resources(target_domain)
                elif choice == '10':
                    print_header("Moduł: Skanowanie Domen Typosquattingowych")
                    asyncio.run(find_typosquatted_domains(target_domain))
                elif choice == '11':
                    print_header("Moduł: Skanowanie Portów")
                    asyncio.run(run_port_scan_on_all_targets_async())
                elif choice == '12':
                    run_full_easm(target_domain)
                elif choice == '13':
                    save_report()
            
            except Exception as e:
                print_fail(f"Wystąpił nieoczekiwany błąd modułu: {e}")
                log.error("Błąd modułu", exc_info=True)


        elif choice == '99' or choice == '0':
            print_info("Do widzenia.")
            sys.exit()
            
        else:
            print_fail("Nieprawidłowa opcja. Spróbuj ponownie.")

# ==============================================================================
# PUNKT STARTOWY
# ==============================================================================
if __name__ == "__main__":
    print_header("Inicjalizacja Zaawansowanego Skanera EASM (v6.0)")
    
    try:
        main_menu()
    except KeyboardInterrupt:
        print_warn("\nPrzerwano przez użytkownika.")
        sys.exit(0)
