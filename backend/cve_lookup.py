"""CVE lookup using offline knowledge base."""
import re
from functools import lru_cache


KNOWN_SERVICE_CVES = {
    "openssh 7.2": [{"cve": "CVE-2016-6210", "cvss": 5.3, "description": "User enumeration via authentication response timing"}],
    "openssh": [{"cve": "CVE-2023-38408", "cvss": 9.8, "description": "Remote code execution via ssh-agent forwarding"}],
    "apache 2.4.49": [{"cve": "CVE-2021-41773", "cvss": 9.8, "description": "Path traversal and remote code execution"}],
    "apache": [{"cve": "CVE-2024-38476", "cvss": 9.8, "description": "HTTP Server vulnerability in proxy handling"}],
    "nginx": [{"cve": "CVE-2024-24989", "cvss": 7.5, "description": "NULL pointer dereference in HTTP/3 module"}],
    "mysql": [{"cve": "CVE-2024-20961", "cvss": 4.9, "description": "Vulnerability in MySQL Server optimizer"}],
    "postgresql": [{"cve": "CVE-2024-10977", "cvss": 3.7, "description": "Client-side encoding issue"}],
    "vsftpd": [{"cve": "CVE-2021-3618", "cvss": 7.4, "description": "ALPACA TLS attack allows cross-protocol attacks"}],
    "samba": [{"cve": "CVE-2023-3961", "cvss": 9.8, "description": "Unauthenticated write to arbitrary path"}],
    "openssl": [{"cve": "CVE-2024-2511", "cvss": 5.3, "description": "Unbounded growth in session cache"}],
    "wordpress": [{"cve": "CVE-2024-31210", "cvss": 8.8, "description": "Remote code execution via plugin upload"}],
    "php": [{"cve": "CVE-2024-4577", "cvss": 9.8, "description": "CGI argument injection"}],
    "smtp": [{"cve": "CVE-2020-7247", "cvss": 9.8, "description": "Remote code execution in OpenSMTPD"}],
    "rdp": [{"cve": "CVE-2019-0708", "cvss": 9.8, "description": "BlueKeep - Remote code execution"}],
    "smb": [{"cve": "CVE-2017-0144", "cvss": 9.3, "description": "EternalBlue - Remote code execution"}],
    "telnet": [{"cve": "CVE-2020-10188", "cvss": 9.8, "description": "Buffer overflow in netkit telnetd"}],
}


@lru_cache(maxsize=200)
def lookup_cves_for_service(service_string: str) -> list:
    service_lower = service_string.lower().strip()
    results = []
    for key, cves in KNOWN_SERVICE_CVES.items():
        if key in service_lower:
            results.extend(cves)
    return results


def extract_services_from_nmap_output(output: str) -> list:
    services = []
    pattern = r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+?)$"
    for line in output.split("\n"):
        match = re.match(pattern, line.strip())
        if match:
            port, proto, service, version = match.groups()
            services.append({
                "port": port,
                "protocol": proto,
                "service": service,
                "version": version.strip(),
                "full": f"{service} {version.strip()}"
            })
    return services


def enrich_services_with_cves(services: list) -> list:
    enriched = []
    for svc in services:
        cves = lookup_cves_for_service(svc["full"])
        enriched.append({**svc, "cves": cves})
    return enriched


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    elif cvss >= 7.0:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    elif cvss > 0:
        return "LOW"
    return "INFO"