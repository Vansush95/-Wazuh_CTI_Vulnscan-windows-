# Wazuh CTI Vulnerability Scanner for Windows

This Python-based scanner checks installed software on **Windows machines** against the [Wazuh CTI](https://cti.wazuh.com/) vulnerability database to detect known CVEs (Common Vulnerabilities and Exposures).

> 🏭 **Specially designed for legacy environments** — many critical industries (e.g. manufacturing, healthcare, government) still rely on older systems due to software compatibility or regulatory constraints. This tool helps monitor such environments for publicly disclosed vulnerabilities.

---

## Features

* 🧠 **Smart software detection** via Windows registry
* 🔎 **Keyword-based filtering** from an editable JSON list of "interesting" packages
* 🌐 **Live CVE lookup** via headless scraping from Wazuh CTI
* 🧹 **Deduplication logic** to avoid repetitive queries for same app/version
* 📄 **Readable report** with CVE ID, publish date, and description

---

## Quick Start

### Requirements

* Python 3.8+
* Google Chrome installed

Install dependencies:

```bash
pip install pyppeteer beautifulsoup4
```

### Create `interesting_packages.json`

Define software to monitor (by substring match):

```json
["python", "firefox", "vlc", "7-zip", "notepad++"]
```

### Run the script

```bash
python windows_vuln_scanner.py
```

---

## Sample Output

```text
[3/7] Scanning VLC media player 3.0.20... found 2 CVEs: ['CVE-2023-4735', 'CVE-2022-3702']

=== Windows Vulnerability Report ===
- VLC media player 3.0.20
  CVE: CVE-2023-4735 | Date: 2023/11/12
    Desc: Buffer overflow vulnerability in libvlc...

  CVE: CVE-2022-3702 | Date: 2022/08/17
    Desc: Denial of service in demux module...
```

---

## Limitations

| Constraint               | Explanation                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| ❗ Web scraping fragility | If the Wazuh CTI frontend changes, scraping logic may break              |
| ❗ No official API        | Wazuh CTI does not expose a public CVE API — scraping is the only option |
| ❗ CVE name mismatches    | Slight software naming/version differences may cause false negatives     |
| ❗ Sequential scan only   | Pyppeteer queries run one-by-one for stability                           |
| ❗ Windows-only           | This version is designed for Windows registry environments only          |

---

## Potential Enhancements

* [ ] Export results to JSON or CSV
* [ ] Add severity filtering (e.g., HIGH or CRITICAL only)
* [ ] Implement async scraping pool or queue
* [ ] Normalize software names (e.g., `python`, `python3`, `python3.12`)
* [ ] Switch to official Wazuh CTI API if it becomes available
* [ ] Add Linux support as a separate module

---

## Why Legacy Matters

Many legacy systems cannot be upgraded due to:

* Critical production dependencies
* Vendor lock-in software
* Legal and certification constraints

This tool helps **monitor those systems without installing agents or reconfiguring them**, making it ideal for security assessments in fragile or air-gapped environments.

---

## License

MIT (or your preferred license)
