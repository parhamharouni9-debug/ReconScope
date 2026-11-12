import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import os
import csv
from functools import lru_cache
from urllib.request import urlopen
from html import escape
def main():
    target_name = input("Enter a target domain name: ")
    authorized = input("Do you confirm that you are authorized to scan this target? [y/N]: ").lower().strip()
    if authorized != "y":
        print("Scan cancelled: authorization not confirmed.")
        return
    try:
        check_nmap()
    except RuntimeError as error:
        print(f"Error: {error}")
        return
    try:
        ip_address = resolve_domain(target_name)
    except ValueError as error:
        print(f"Error: {error}")
        return
    try:
        ports = scan_ports(ip_address)
    except RuntimeError as error:
        print(f"Error: {error}")
        return
    try:
        open_ports = parse_open_ports(ports)
    except ValueError as error:
        print(f"Error: {error}")
        return
    report = format_report(target_name, ip_address, open_ports)
    try:
        report_file = save_report(target_name, report)
    except OSError as error:
        print(f"Error: {error}")
        return
    print(f"Report saved to: {report_file}")
    try:
        os.startfile(report_file.resolve())
    except OSError as error:
        print(f"Error: {error}")
        return




def normalize_target(raw):
    target = raw.strip().lower()
    if target =="":
        raise ValueError("Target cannot be empty")
    elif target.startswith(("http://", "https://")):
        raise ValueError("Invalid input")   
    else:
        return target
    
        
def resolve_domain(domain):
    target = normalize_target(domain)
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError("Could not resolve domain") from error
    return ip


def check_nmap():
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
    except FileNotFoundError as error:
        raise RuntimeError("Nmap is not installed or not found in PATH") from error
    if result.returncode != 0:
        raise RuntimeError("Nmap is not functioning properly")
    return result.stdout


def scan_ports(ip):
    try:
        result = subprocess.run(
            ["nmap", "-sT", "-Pn", "-p-", "--open", "-oX", "-", ip],
                capture_output = True,
                text = True, 
                timeout = 300
                )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Nmap scan timed out") from error
    except FileNotFoundError as error:
        raise RuntimeError("Nmap is not installed or not found in PATH") from error
    if result.returncode != 0:
        if result.stderr.strip() == "":
            raise RuntimeError("Nmap is not functioning properly")
        else:
            raise RuntimeError(result.stderr.strip())
    return result.stdout 

def parse_open_ports(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ValueError("Invalid Nmap XML output") from error
    ports = root.findall(".//port")
    open_ports = []
    for number in ports:
        number_port = int(number.get("portid"))
        state_element = number.find("state")
        if state_element is not None:
            status = state_element.get("state")
        else:
            continue
        if status == "open":
            service_element = number.find("service")
            if service_element is not None:
                service_name = service_element.get("name")
            else:
                service_name = "unknown"
            port_info = {"port": number_port, "service": service_name, "description": explain_service(service_name, number_port)}
            open_ports.append(port_info)
    return open_ports


def format_report(target, ip, open_ports):
    """Render an offline-ready ReconScope HTML report."""
    template_path = Path(__file__).resolve().parent / "report_template.html"
    template = template_path.read_text(encoding="utf-8")

    port_rows = []
    for port in sorted(open_ports, key=lambda entry: entry["port"]):
        port_number = escape(str(port["port"]))
        service = escape(str(port.get("service") or "unknown"))
        description = escape(str(
            port.get("description")
            or port.get("Description")
            or "No description is available for this service."
        ))
        port_rows.append(
            f'<tr><td><span class="port-num">{port_number}</span></td>'
            f'<td class="service">{service}</td>'
            f'<td class="desc">{description}</td></tr>'
        )

    if not port_rows:
        port_rows.append(
            '<tr><td colspan="3" class="empty">'
            'No open TCP ports were reported by this scan.'
            '</td></tr>'
        )

    replacements = {
        "__RS_TARGET__": escape(str(target)),
        "__RS_IP__": escape(str(ip)),
        "__RS_COUNT__": str(len(open_ports)),
        "__RS_DATE__": escape(datetime.now().strftime("%B %d, %Y · %H:%M")),
        "__RS_PORT_ROWS__": "\n".join(port_rows),
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)

    return template



def save_report(target, report):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    folder = Path("reports")
    folder.mkdir(exist_ok=True)
    report_file = folder / f"{target}_{timestamp}.html"
    report_file.write_text(report, encoding="utf-8")
    return report_file


@lru_cache(maxsize=1)
def load_iana_services():
    """Load the official IANA TCP service registry."""

    database_file = Path(__file__).resolve().parent / "iana_services.csv"

    if not database_file.exists():
        url = (
            "https://www.iana.org/assignments/"
            "service-names-port-numbers/"
            "service-names-port-numbers.csv"
        )

        try:
            with urlopen(url, timeout=15) as response:
                data = response.read()
            database_file.write_bytes(data)
        except OSError:
            return {}, {}, {}

    by_exact = {}
    by_name = {}
    by_port = {}

    try:
        with database_file.open(
            "r", encoding="utf-8-sig", newline=""
        ) as file:
            reader = csv.DictReader(file)

            for row in reader:
                protocol = (row.get("Transport Protocol") or "").lower()
                name = (row.get("Service Name") or "").lower().strip()
                port_text = (row.get("Port Number") or "").strip()
                description = (row.get("Description") or "").strip()

                if protocol != "tcp":
                    continue

                if not port_text.isdecimal() or not description:
                    continue

                if description.lower() == "reserved":
                    continue

                port = int(port_text)

                if name:
                    by_exact.setdefault((name, port), description)
                    by_name.setdefault(name, description)

                by_port.setdefault(port, description)

    except (OSError, UnicodeError, csv.Error):
        return {}, {}, {}

    return by_exact, by_name, by_port


def explain_service(service_name, port=None):
    """Return a human-readable explanation of a TCP service."""

    name = (service_name or "unknown").strip().lower()

    common_services = {
        "ssh": "Used to securely access and manage another computer remotely.",
        "http": "Used by websites to transfer web pages and other content.",
        "https": "Used for encrypted communication between browsers and websites.",
        "ftp": "Used to transfer files between computers over a network.",
        "ftps": "Used to transfer files over an encrypted FTP connection.",
        "smtp": "Used by mail servers to send and transfer email messages.",
        "smtps": "Used for encrypted email transmission.",
        "submission": "Used by email applications to submit outgoing messages.",
        "pop3": "Used by email applications to download messages from a mail server.",
        "pop3s": "Used to retrieve email over an encrypted connection.",
        "imap": "Used to access and synchronize email stored on a mail server.",
        "imaps": "Used to access email securely through an encrypted connection.",
        "domain": "Used by DNS to translate domain names into IP addresses.",
        "dns": "Used to look up domain names and related network information.",
        "telnet": "Used for remote text-based access, usually without encryption.",
        "microsoft-ds": "Commonly used for Windows file and printer sharing through SMB.",
        "netbios-ssn": "Used by older Windows networking systems for file sharing.",
        "ms-wbt-server": "Commonly used for Windows Remote Desktop connections.",
        "rdp": "Used to view and control another computer's desktop remotely.",
        "mysql": "Used by applications to communicate with MySQL databases.",
        "postgresql": "Used by applications to communicate with PostgreSQL databases.",
        "ms-sql-s": "Used for communication with Microsoft SQL Server databases.",
        "redis": "Used by applications to access an in-memory data store.",
        "mongodb": "Used by applications to access MongoDB databases.",
        "ldap": "Used to search and manage directory information, including users.",
        "ldaps": "Used for encrypted access to directory services.",
        "kerberos-sec": "Used to authenticate users and services on a network.",
        "ntp": "Used to synchronize clocks between computers.",
        "snmp": "Used to monitor and manage network devices.",
        "vnc": "Used to remotely view and control another computer's desktop.",
        "openvpn": "Used to create encrypted VPN connections.",
        "sip": "Used to establish and manage voice or video calls.",
        "rtsp": "Used to control streaming audio and video sessions.",
        "nfs": "Used to share files between computers over a network.",
        "rpcbind": "Helps clients locate RPC services on a computer.",
        "rsync": "Used to synchronize and transfer files between systems.",
        "ipp": "Used for printing and managing printers over a network.",
        "printer": "Commonly associated with network printing services.",
        "amqp": "Used by applications to exchange messages through message brokers.",
        "mqtt": "Used for lightweight messaging, especially between IoT devices.",
        "git": "Used to access Git repositories over the Git protocol.",
        "tcpwrapped": "The connection was closed or restricted before the service could be identified.",
    }

    if name in common_services:
        return common_services[name]

    if name.startswith("ssl/"):
        inner_service = name.removeprefix("ssl/")
        if inner_service in common_services:
            return (
                common_services[inner_service]
                + " Nmap detected an SSL/TLS layer."
            )

    by_exact, by_name, by_port = load_iana_services()

    official_description = by_exact.get((name, port))

    if official_description is None and name != "unknown":
        official_description = by_name.get(name)

    if official_description:
        return f"Registered service description: {official_description}"

    if port in by_port:
        return (
            f"Port {port} is registered for: {by_port[port]}. "
            "This does not confirm which service is actually running."
        )

    return (
        f"Service '{name}' could not be reliably explained. "
        "The application may be custom, private, or unidentified."
    )

if __name__ == "__main__":
    main()