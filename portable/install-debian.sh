#!/bin/sh
# vpnexit installer for Debian 12+, Ubuntu 22.04+ (Raspberry Pi OS, RaspAP hosts).
# Idempotent: re-running upgrades the files and keeps /etc/vpnexit/config.json.
set -e

SRC=$(cd "$(dirname "$0")" && pwd)
PKGS="python3 strongswan strongswan-swanctl libcharon-extra-plugins libstrongswan-extra-plugins
 nftables iproute2 curl openssh-client sshpass openssl ca-certificates"

[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "this installer targets Debian/Ubuntu" >&2; exit 1; }

echo "==> vpnexit (portable) installer"
. /etc/os-release 2>/dev/null || true
echo "    ${PRETTY_NAME:-unknown system}"

echo "==> installing packages"
# shellcheck disable=SC2086
DEBIAN_FRONTEND=noninteractive apt-get update -qq
# shellcheck disable=SC2086
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS

echo "==> copying files"
install -d /usr/local/sbin /usr/local/share/vpnexit/web /etc/vpnexit /var/lib/vpnexit /etc/swanctl/conf.d /etc/swanctl/x509ca
install -m 0755 "$SRC/vpnexit.py" /usr/local/sbin/vpnexit
cp -a "$SRC/web/." /usr/local/share/vpnexit/web/
install -m 0644 "$SRC/vpnexit-web.service" /etc/systemd/system/vpnexit-web.service
install -m 0644 "$SRC/vpnexit-supervisor.service" /etc/systemd/system/vpnexit-supervisor.service

echo "==> charon drop-in"
cat > /etc/strongswan.d/vpnexit.conf <<'EOF'
# Managed by vpnexit. Routes and NAT belong to the panel, and the address the
# peer assigns is used only as the SNAT target (installing it can crash some
# vendor kernels).
charon {
	install_routes = no
	install_virtual_ip = no
	port = 500
	port_nat_t = 4500
}
EOF

echo "==> system CA store (one certificate per file)"
python3 - <<'PY'
import os, re
src = "/etc/ssl/certs/ca-certificates.crt"
dst = "/etc/swanctl/x509ca"
try:
    data = open(src).read()
except OSError:
    raise SystemExit(0)
blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
if len([f for f in os.listdir(dst) if f.startswith("sys-")]) < 10:
    for i, b in enumerate(blocks):
        with open(os.path.join(dst, "sys-%03d.pem" % i), "w") as fh:
            fh.write(b + "\n")
print("    %d roots" % len(blocks))
PY

echo "==> configuration"
if [ ! -f /etc/vpnexit/config.json ]; then
	TOKEN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
	python3 - "$TOKEN" <<'PY'
import json, sys
cfg = {
    "feed_url": "https://s-gke-euw1-nssi3-4.europe-west1.firebasedatabase.app/.json?ns=global-vpn-ios",
    "token": sys.argv[1],
    "share_lan": True, "block_ipv6": True, "auto_reconnect": True,
    "tunnel_mtu": 1400, "refresh_hours": 24, "watchdog_seconds": 20,
    "retry_seconds": 120, "lan_iface": "", "mark": "0x1a1", "table": 417,
    "rule_priority": 1000, "relay_enabled": False, "relay_list": "", "relay_pass": ""
}
with open("/etc/vpnexit/config.json", "w") as fh:
    json.dump(cfg, fh, indent=1)
PY
	chmod 600 /etc/vpnexit/config.json
fi

echo "==> sysctl (ip forwarding)"
cat > /etc/sysctl.d/90-vpnexit.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl -q -p /etc/sysctl.d/90-vpnexit.conf 2>/dev/null || sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "==> services"
systemctl enable --now strongswan-swanctl.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now vpnexit-supervisor.service >/dev/null
systemctl enable --now vpnexit-web.service >/dev/null
systemctl restart vpnexit-supervisor.service vpnexit-web.service

/usr/local/sbin/vpnexit refresh >/dev/null 2>&1 || echo "    (feed fetch failed - retry from the panel)"

PORT=$(python3 -c "print(8088)")
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
TOKEN=$(python3 -c "import json;print(json.load(open('/etc/vpnexit/config.json'))['token'])")

cat <<EOF

  vpnexit is running.

  Panel   : http://${IP:-127.0.0.1}:${PORT}/
  Token   : ${TOKEN}

  Services: systemctl status vpnexit-web vpnexit-supervisor
  Config  : /etc/vpnexit/config.json
  Logs    : journalctl -u vpnexit-supervisor -f

  Note: on a RaspAP host set "lan_iface" to the AP interface (usually wlan0)
        if traffic from wireless clients is not redirected.

EOF
