#!/usr/bin/env python3
import time
import json
import winreg
import sys
import asyncio
from bs4 import BeautifulSoup
from pyppeteer import launch

# Workaround for Windows asyncio bug
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# CONFIGURATION
INTERESTING_FILE = "interesting_packages.json"
QUERY_DELAY = 3.0  # seconds between CTI queries
CHROME_PATH = r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"  # Update if needed

# ------------------ Registry Enumeration ------------------
UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
]

def get_installed_software():
    software = []
    for hive, path, access in UNINSTALL_KEYS:
        try:
            key = winreg.OpenKey(hive, path, 0, access)
        except FileNotFoundError:
            continue
        for i in range(0, winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                sub = winreg.OpenKey(key, subkey_name, 0, access)
                try:
                    name = winreg.QueryValueEx(sub, "DisplayName")[0]
                    version = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                    software.append({"name": name, "version": version})
                except FileNotFoundError:
                    pass
            except OSError:
                break
    unique = {}
    for s in software:
        key = f"{s['name']}-{s['version']}"
        unique[key] = s
    return list(unique.values())

# ------------------ Load ------------------
def load_interesting_packages(path=INTERESTING_FILE):
    try:
        with open(path, "r") as f:
            return [pkg.lower() for pkg in json.load(f)]
    except Exception as e:
        print(f"[ERROR] Failed to load {path}: {e}")
        return []

# ------------------ Filtering ------------------
def is_interesting(name, keywords):
    nl = name.lower()
    return any(kw in nl for kw in keywords)

# ------------------ Normalize ------------------
def normalize_query(name, version):
    base = name.split()[0]  # Simplify product name to first token
    if '+' in version:
        version = version.split('+')[0].strip()
    parts = version.strip().split('.')
    if len(parts) >= 4:
        ver = f"{parts[0]}.{parts[1]}.{parts[2]}"
    elif len(parts) == 3:
        ver = f"{parts[0]}.{parts[1]}.{parts[2]}"
    elif len(parts) == 2:
        ver = f"{parts[0]}.{parts[1]}"
    else:
        ver = parts[0] if parts else version
    return f"{base} {ver}".replace(' ', '%20')

# ------------------ Manual Pyppeteer Render ------------------
async def fetch_html_with_browser(url, retries=3):
    for attempt in range(retries):
        try:
            browser = await launch(executablePath=CHROME_PATH, headless=True, args=["--no-sandbox"])
            page = await browser.newPage()
            await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36")
            await page.goto(url)
            content = await page.content()
            await browser.close()
            return content
        except ConnectionResetError as cre:
            print(f"    [Retry {attempt + 1}] ConnectionResetError: {cre}")
        except Exception as e:
            print(f"    [Retry {attempt + 1}] Failed to fetch {url}: {e}")
        try:
            await browser.close()
        except:
            pass
        await asyncio.sleep(2)
    return ""

# ------------------ CTI Query ------------------
async def query_wazuh_cti(name, version):
    q = normalize_query(name, version)
    url = f"https://cti.wazuh.com/vulnerabilities/cves?q={q}"
    try:
        html = await fetch_html_with_browser(url)
    except Exception as e:
        print(f"    [ERROR] Render failed for {name} {version}: {e}")
        return []
    if not html:
        return []
    soup = BeautifulSoup(html, 'html.parser')
    ids = soup.find_all('dt')
    descs = soup.find_all('div', class_='cve-search-description')
    pills = soup.find_all('ul', class_='cve-search-pills')
    cves = []
    for i, dt in enumerate(ids):
        cid = dt.text.strip()
        desc = descs[i].text.strip() if i < len(descs) else ''
        pub = 'N/A'
        if i < len(pills):
            for li in pills[i].find_all('li'):
                if '/' in li.text:
                    pub = li.text.strip()
                    break
        cves.append({'id': cid, 'published': pub, 'description': desc})
    return cves

# ------------------ Reporting ------------------
def print_report(vulns):
    if not vulns:
        print("\n[INFO] No vulnerabilities found on Windows.")
        return
    print("\n=== Windows Vulnerability Report ===")
    print("=" * 60)
    for pkg in vulns:
        print(f"\n- {pkg['name']} {pkg['version']}")
        for c in pkg['cves']:
            print(f"  CVE: {c['id']} | Date: {c['published']}")
            print(f"    Desc: {c['description'][:120]}...\n")

# ------------------ Main ------------------
async def main():
    keywords = load_interesting_packages()
    if not keywords:
        return
    print("[INFO] Gathering installed software from registry...")
    all_sw = get_installed_software()
    interesting = [s for s in all_sw if is_interesting(s['name'], keywords)]
    print(f"[INFO] Found {len(all_sw)} entries, scanning {len(interesting)} interesting packages.\n")
    vulns = []
    scanned = set()
    total = len(interesting)
    for idx, pkg in enumerate(interesting, 1):
        name, version = pkg['name'], pkg['version']
        dedup_key = f"{name.split()[0].lower()}_{normalize_query(name, version)}"
        if dedup_key in scanned:
            print(f"[{idx}/{total}] Skipping duplicate: {name} {version}")
            continue
        scanned.add(dedup_key)
        print(f"[{idx}/{total}] Scanning {name} {version}...", end='')
        try:
            cves = await query_wazuh_cti(name, version)
        except Exception as e:
            print(f" [FAIL] Skipping due to error: {e}")
            continue
        if cves:
            print(f" found {len(cves)} CVEs: {[c['id'] for c in cves]}")
            pkg['cves'] = cves
            vulns.append(pkg)
        else:
            print(" no CVEs")
        time.sleep(QUERY_DELAY)
    print_report(vulns)

if __name__ == '__main__':
    asyncio.run(main())
