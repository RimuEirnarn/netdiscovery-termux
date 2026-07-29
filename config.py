import os

SSID = "NetSSID"
DISCOVERY_PORT = 6120
TAILSCALE_IP = "100.0.0.0"

NEXTDNS_API_KEY = "API"
NEXTDNS_PROFILE_ID = "abc000"
NEXTDNS_REWRITE_HOSTNAME = "luna.net"

STATE_DIR = os.path.expanduser("~/.luna-service")
LOG_FILE = os.path.join(STATE_DIR, "luna-service.log")
LAST_IP_FILE = os.path.join(STATE_DIR, "last_ip")
LOCK_FILE = os.path.join(STATE_DIR, "run.lock")
