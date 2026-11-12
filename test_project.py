"""Offline tests for ReconScope.

DNS resolution, Nmap execution, and IANA lookups are mocked when appropriate.
No test performs a network scan.
"""

import socket
import subprocess
from types import SimpleNamespace

import pytest

import project


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  Example.com  ", "example.com"),
        ("LOCALHOST", "localhost"),
        (" 192.168.1.10 ", "192.168.1.10"),
    ],
)
def test_normalize_target(raw, expected):
    assert project.normalize_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "  ", "http://example.com", "https://example.com"])
def test_normalize_target_rejects_invalid_input(raw):
    with pytest.raises(ValueError):
        project.normalize_target(raw)


def test_resolve_domain(monkeypatch):
    def fake_lookup(domain):
        assert domain == "example.com"
        return "203.0.113.10"

    monkeypatch.setattr(project.socket, "gethostbyname", fake_lookup)
    assert project.resolve_domain(" EXAMPLE.COM ") == "203.0.113.10"


def test_resolve_domain_dns_failure(monkeypatch):
    def fake_lookup(_domain):
        raise socket.gaierror("simulated DNS failure")

    monkeypatch.setattr(project.socket, "gethostbyname", fake_lookup)
    with pytest.raises(ValueError, match="Could not resolve domain"):
        project.resolve_domain("does-not-exist.invalid")


def test_check_nmap_success(monkeypatch):
    def fake_run(args, **kwargs):
        assert args == ["nmap", "--version"]
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        return SimpleNamespace(returncode=0, stdout="Nmap version test", stderr="")

    monkeypatch.setattr(project.subprocess, "run", fake_run)
    assert project.check_nmap() == "Nmap version test"


def test_check_nmap_not_installed(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(project.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="not installed"):
        project.check_nmap()


def test_check_nmap_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        project.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="error"),
    )
    with pytest.raises(RuntimeError, match="not functioning properly"):
        project.check_nmap()


def test_scan_ports_returns_xml_and_sets_timeout(monkeypatch):
    xml_output = '<nmaprun><host><ports /></host></nmaprun>'

    def fake_run(args, **kwargs):
        assert args == ["nmap", "-sT", "-Pn", "-p-", "--open", "-oX", "-", "127.0.0.1"]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 300}
        return SimpleNamespace(returncode=0, stdout=xml_output, stderr="")

    monkeypatch.setattr(project.subprocess, "run", fake_run)
    assert project.scan_ports("127.0.0.1") == xml_output


def test_scan_ports_reports_stderr(monkeypatch):
    monkeypatch.setattr(
        project.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="  Invalid Nmap option\n"
        ),
    )
    with pytest.raises(RuntimeError, match="^Invalid Nmap option$"):
        project.scan_ports("127.0.0.1")


def test_scan_ports_reports_generic_error_when_stderr_is_blank(monkeypatch):
    monkeypatch.setattr(
        project.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr=" \n"),
    )
    with pytest.raises(RuntimeError, match="Nmap is not functioning properly"):
        project.scan_ports("127.0.0.1")


def test_scan_ports_timeout(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["nmap"], timeout=300)

    monkeypatch.setattr(project.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="Nmap scan timed out"):
        project.scan_ports("127.0.0.1")


def test_scan_ports_nmap_not_installed(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(project.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="not installed"):
        project.scan_ports("127.0.0.1")


def test_parse_open_ports_with_descriptions(monkeypatch):
    # Avoid file access and the IANA registry in this focused parser test.
    monkeypatch.setattr(
        project, "explain_service", lambda service, port: f"Meaning of {service} on {port}"
    )
    xml_text = """
    <nmaprun><host><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
        <port protocol="tcp" portid="443"><service name="https"/></port>
        <port protocol="tcp" portid="25"><state state="filtered"/></port>
        <port protocol="tcp" portid="8080"><state state="open"/></port>
    </ports></host></nmaprun>
    """
    assert project.parse_open_ports(xml_text) == [
        {"port": 80, "service": "http", "description": "Meaning of http on 80"},
        {"port": 8080, "service": "unknown", "description": "Meaning of unknown on 8080"},
    ]


def test_parse_open_ports_invalid_xml():
    with pytest.raises(ValueError, match="Invalid Nmap XML output"):
        project.parse_open_ports("<nmaprun><host>")


def test_explain_common_service():
    assert "securely access" in project.explain_service("SSH", 22)


def test_explain_service_iana_and_fallback(monkeypatch):
    # Simulate a tiny IANA registry to keep the test fully offline.
    monkeypatch.setattr(
        project,
        "load_iana_services",
        lambda: (
            {("example-svc", 9999): "An example registered service"},
            {"example-svc": "An example registered service"},
            {9999: "An example registered service"},
        ),
    )
    assert "An example registered service" in project.explain_service("example-svc", 9999)
    assert "Port 9999" in project.explain_service("unknown", 9999)
    assert "could not be reliably explained" in project.explain_service("unknown", 60000)


def test_load_iana_services_parses_local_csv(tmp_path, monkeypatch):
    # Point project.__file__ at a temporary directory so the real registry
    # and network are never used by this test.
    monkeypatch.setattr(project, "__file__", str(tmp_path / "project.py"))
    (tmp_path / "iana_services.csv").write_text(
        "Service Name,Port Number,Transport Protocol,Description\n"
        "custom-svc,5555,tcp,Example TCP service\n"
        "other-svc,6666,udp,Example UDP service\n"
        "reserved-svc,7777,tcp,Reserved\n",
        encoding="utf-8",
    )
    project.load_iana_services.cache_clear()
    try:
        by_exact, by_name, by_port = project.load_iana_services()
        assert by_exact[("custom-svc", 5555)] == "Example TCP service"
        assert by_name["custom-svc"] == "Example TCP service"
        assert by_port[5555] == "Example TCP service"
        assert ("other-svc", 6666) not in by_exact
        assert 7777 not in by_port
    finally:
        project.load_iana_services.cache_clear()


def test_format_report_creates_offline_html_and_escapes_text():
    report = project.format_report(
        "<script>alert(1)</script>",
        "127.0.0.1",
        [
            {"port": 8080, "service": "<demo>", "description": "A & B"},
            {"port": 22, "service": "ssh", "description": "Remote access"},
        ],
    )
    assert "<!doctype html>" in report.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report
    assert "&lt;demo&gt;" in report
    assert "A &amp; B" in report
    assert "127.0.0.1" in report
    assert "Remote access" in report
    assert report.index('class="port-num">22') < report.index('class="port-num">8080')
    assert "__RS_PORT_ROWS__" not in report


def test_format_report_no_open_ports():
    report = project.format_report("localhost", "127.0.0.1", [])
    assert "No open TCP ports were reported by this scan." in report


def test_save_report_creates_html_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    content = "<!doctype html><html><body>Test report</body></html>"
    file_path = project.save_report("localhost", content)
    assert file_path.exists()
    assert file_path.parent.name == "reports"
    assert file_path.name.startswith("localhost_")
    assert file_path.suffix == ".html"
    assert file_path.read_text(encoding="utf-8") == content


def test_main_cancels_without_authorization(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "localhost" if "target" in _prompt else "n")

    def should_not_run():
        pytest.fail("Nmap should not be called if authorization is not confirmed")

    monkeypatch.setattr(project, "check_nmap", should_not_run)
    project.main()
    assert "Scan cancelled" in capsys.readouterr().out