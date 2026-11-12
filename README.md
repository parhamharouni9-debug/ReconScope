# ReconScope

**A Python-powered TCP port scanner with clear, offline-ready HTML reports.**

ReconScope uses [Nmap](https://nmap.org/) to scan the TCP ports of an authorized target, parses its XML output, and creates an easy-to-read HTML report. Instead of showing only port numbers and technical service labels, the report explains what common services are typically used for.

This project began as my final project for **CS50's Introduction to Programming with Python** and has since been expanded with HTML reporting, service explanations, and more robust error handling.

> **Original CS50 project demo:** [Watch on YouTube](https://youtu.be/HKZilj8Jb6g) (the video may show an earlier version of the project).

## Features

- **Full TCP port scan:** Uses Nmap's TCP connect scan (`-sT`) across ports 1–65535 (`-p-`).
- **Hostname and IPv4 input:** Resolves hostnames to IPv4 addresses using Python's `socket` module.
- **Structured results:** Extracts open TCP ports and service labels from Nmap XML output.
- **Plain-language descriptions:** Explains commonly used services and falls back to entries from the [IANA service name and port registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) when available.
- **Self-contained HTML reports:** Produces a styled report with target information, scan date, port numbers, service names, and descriptions. Reports can be opened offline, shared, or printed to PDF from a browser.
- **Report history:** Saves each report under `reports/` using the target and a timestamp in the filename.
- **Error handling:** Handles common DNS errors, missing Nmap installations, invalid XML, nonzero Nmap exit codes, and scan timeouts.
- **Automated tests:** Includes Pytest tests for parsing, reporting, error handling, and supporting functions; tests do not need a live network scan.

## Requirements

- **Python 3.9 or newer** (the code uses `str.removeprefix`).
- **Nmap** installed and available on your system's `PATH`.
- **Windows** for automatic opening of the generated report. The HTML reports themselves can be opened on any platform; the current auto-open call is Windows-specific.

The application uses Python's standard library. **Pytest is needed only to run the tests.**

## Installation

1. Clone this repository or download its files.
2. Install [Nmap](https://nmap.org/download.html) and make sure the `nmap` command is available in your terminal.
3. Optionally create and activate a virtual environment.
4. Install the development/test dependency:

   ```bash
   python -m pip install -r requirements.txt
   ```

5. Verify that Nmap is accessible:

   ```bash
   nmap --version
   ```

## Usage

Run the program from the project directory:

```bash
python project.py
```

When prompted, enter a hostname or IPv4 address, such as `localhost`, `example.com`, or `192.168.1.10`, then confirm that you are authorized to scan it.

ReconScope runs Nmap, extracts the open TCP ports, and saves an HTML file in the `reports/` directory. On Windows, the report opens automatically in the default app (normally a web browser).

Example output file:

```text
reports/example.com_20261112_204500_123456.html
```

Each report includes:

| Port | Service | What it usually does |
| --- | --- | --- |
| 22 | `ssh` | Used to securely access and manage another computer remotely. |
| 80 | `http` | Used by websites to transfer web pages and other content. |
| 445 | `microsoft-ds` | Commonly used for Windows file and printer sharing through SMB. |

*The table is an illustration, not an actual scan result.*

## How It Works

1. **Validate and resolve:** The application normalizes the provided hostname and resolves it to an IPv4 address.
2. **Scan:** It runs `nmap -sT -Pn -p- --open -oX - <ip>` with a 300-second timeout.
3. **Parse:** XML is parsed using `xml.etree.ElementTree`, and open ports are extracted.
4. **Explain:** Common service labels receive simple explanations. For less common labels, the program consults the local `iana_services.csv` registry, if available.
5. **Render:** The `report_template.html` template is populated with the results. Values inserted into the report are HTML-escaped.
6. **Save:** An individual timestamped `.html` file is created inside `reports/`.

### How service descriptions are chosen

Common service names use curated descriptions in `project.py`. Other service names may be matched against the IANA registry included as `iana_services.csv`. If that file is missing, the program attempts to download it on first use; without network access, it falls back to a generic description.

**Important:** IANA registry entries describe registered port assignments. They do **not** verify which application is actually running on a particular host. ReconScope currently does not use Nmap version detection (`-sV`).

## Project Structure

```text
ReconScope/
├── project.py             # CLI, Nmap execution, XML parsing and report generation
├── report_template.html   # HTML/CSS template for the offline report
├── iana_services.csv      # IANA service/port descriptions for offline lookup
├── test_project.py        # Automated tests using Pytest
├── requirements.txt       # Test dependency: pytest
├── .gitignore             # Excludes local environments, caches and generated reports
└── README.md              # Project documentation
```

The `reports/` directory is created automatically when a report is saved and is excluded from Git.

## Running Tests

Install the testing dependency, then run:

```bash
python -m pytest -v
```

The tests mock DNS and Nmap calls where appropriate, so **they do not scan external hosts**. They also cover HTML escaping and saved report files.

## Current Limitations

- **TCP only:** UDP ports are not scanned.
- **IPv4 only:** Hostnames are resolved with `socket.gethostbyname`; IPv6 scanning is not implemented.
- **Basic input validation:** This version does not fully validate every possible hostname/IP syntax.
- **Not service fingerprinting:** The service labels generally come from Nmap's port mapping, not verified application or version detection.
- **Fixed scan settings:** Every scan covers all TCP ports, skips host discovery (`-Pn`), and has a five-minute subprocess timeout. Some hosts or networks may need longer.
- **Windows auto-open:** Automatic report opening currently uses `os.startfile`, which is Windows-specific.
- **No vulnerability detection:** An open port alone does not indicate a vulnerability or security risk.

## Responsible Use

Only scan systems you own or have explicit permission to assess. Port scanning may be restricted by local policy or law. ReconScope is an educational tool intended for authorized network assessment.

## Acknowledgements

- [Nmap](https://nmap.org/) — TCP scanning and XML output.
- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) — registered service and port descriptions.
- [CS50's Introduction to Programming with Python](https://cs50.harvard.edu/python/) — the course in which the original project was developed.