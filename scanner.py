import json
import logging
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from config import (
    DISCOVERY_PORT,
    LAST_IP_FILE,
    LOG_FILE,
    NEXTDNS_API_KEY,
    NEXTDNS_PROFILE_ID,
    NEXTDNS_REWRITE_HOSTNAME,
    SSID,
    STATE_DIR,
    TAILSCALE_IP,
)

EXPECTED_CONNECTION = {"connection": "LUNA/Rimu Aerisya"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [nextdns] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def ensure_state_dir() -> None:
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)


def http_get_text(url: str, timeout: int = 5) -> str | None:
    request = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return None


def parse_luna_response(text: str | None) -> bool:
    if not text:
        return False
    try:
        return json.loads(text) == EXPECTED_CONNECTION
    except json.JSONDecodeError:
        return False


def check_tailscale() -> bool:
    response = http_get_text(f"http://{TAILSCALE_IP}:{DISCOVERY_PORT}")
    return parse_luna_response(response)


def scan_nearby_devices() -> str:
    cidr = "192.168.1.0/24" if SSID == "DemoSSID" else "192.168.1.0/24"

    if not shutil.which("nmap"):
        raise RuntimeError("nmap is not installed")

    result = subprocess.run(
        [
            "nmap",
            "-p",
            str(DISCOVERY_PORT),
            "--open",
            "--host-timeout",
            "10s",
            "--max-retries",
            "1",
            cidr,
            "-oG",
            "-",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    hosts = []
    for line in result.stdout.splitlines():
        if "Ports:" in line:
            parts = line.split()
            if len(parts) >= 2:
                hosts.append(parts[1])

    if not hosts:
        raise RuntimeError(f"No hosts with port {DISCOVERY_PORT} open found")

    for host in hosts:
        response = http_get_text(f"http://{host}:{DISCOVERY_PORT}")
        if parse_luna_response(response):
            return host

    raise RuntimeError("No host with matching LUNA response found")


def find_rewrite_ids() -> list[str]:
    request = urllib.request.Request(
        f"https://api.nextdns.io/profiles/{NEXTDNS_PROFILE_ID}/rewrites",
        headers={"X-Api-Key": NEXTDNS_API_KEY},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode("utf-8")
    data = json.loads(body)
    return [entry["id"] for entry in data.get("data", []) if entry.get("name") == NEXTDNS_REWRITE_HOSTNAME]


def delete_rewrite(entry_id: str) -> None:
    request = urllib.request.Request(
        f"https://api.nextdns.io/profiles/{NEXTDNS_PROFILE_ID}/rewrites/{entry_id}",
        method="DELETE",
        headers={"X-Api-Key": NEXTDNS_API_KEY},
    )
    with urllib.request.urlopen(request, timeout=10):
        pass
    logging.info("Deleted existing rewrite id=%s", entry_id)


def create_rewrite(ip: str) -> None:
    payload = json.dumps({"name": NEXTDNS_REWRITE_HOSTNAME, "content": ip}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.nextdns.io/profiles/{NEXTDNS_PROFILE_ID}/rewrites",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "X-Api-Key": NEXTDNS_API_KEY},
    )
    logging.info("Pushing to %s!", NEXTDNS_PROFILE_ID)
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode("utf-8")
    logging.info("Created rewrite %s -> %s: %s", NEXTDNS_REWRITE_HOSTNAME, ip, body)


def set_luna_rewrite(new_ip: str) -> None:
    if not new_ip:
        logging.error("ERROR: set_luna_rewrite called with empty IP")
        raise ValueError("new_ip is required")

    last_ip_path = Path(LAST_IP_FILE)
    if last_ip_path.exists():
        last_ip = last_ip_path.read_text(encoding='utf-8').strip()
        if last_ip == new_ip:
            logging.info("IP unchanged (%s), skipping NextDNS update", new_ip)
            return

    for entry_id in find_rewrite_ids():
        delete_rewrite(entry_id)

    create_rewrite(new_ip)
    last_ip_path.write_text(new_ip, encoding='utf-8')


def main() -> int:
    ensure_state_dir()

    if check_tailscale():
        ipaddr = TAILSCALE_IP
    else:
        ipaddr = scan_nearby_devices()

    logging.info("Acquired %s, setting a rewrite...", ipaddr)
    set_luna_rewrite(ipaddr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc: # pylint: disable=broad-exception-caught
        logging.error("%s", exc)
        print(exc, file=sys.stderr)
        sys.exit(1)
