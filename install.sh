#!/bin/sh
# vpnexit installer for OpenWrt - idempotent, safe to re-run (upgrade in place).
set -e

SRC=$(cd "$(dirname "$0")" && pwd)
PKGS="ucode ucode-mod-fs ucode-mod-uci uclient-fetch \
 strongswan-charon strongswan-swanctl \
 strongswan-mod-aes strongswan-mod-sha1 strongswan-mod-sha2 strongswan-mod-md5 \
 strongswan-mod-md4 strongswan-mod-des strongswan-mod-hmac strongswan-mod-kdf \
 strongswan-mod-gmp strongswan-mod-kernel-netlink strongswan-mod-socket-default \
 strongswan-mod-vici strongswan-mod-pem strongswan-mod-x509 strongswan-mod-pubkey \
 strongswan-mod-constraints strongswan-mod-revocation strongswan-mod-resolve \
 strongswan-mod-pkcs1 strongswan-mod-xcbc strongswan-mod-fips-prf strongswan-mod-mgf1 \
 strongswan-mod-attr strongswan-mod-openssl strongswan-mod-gcm strongswan-mod-ccm \
 strongswan-mod-eap-mschapv2 strongswan-mod-eap-identity \
 kmod-ipsec4 kmod-ipsec6 kmod-crypto-gcm kmod-crypto-authenc \
 kmod-crypto-sha256 kmod-crypto-hmac kmod-crypto-ctr kmod-crypto-aead \
 kmod-crypto-cbc kmod-crypto-echainiv kmod-crypto-seqiv ip-full openssl-util sshpass openssh-client"

[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
[ -f /etc/openwrt_release ] || { echo "this is not OpenWrt" >&2; exit 1; }

echo "==> vpnexit installer"
. /etc/openwrt_release
echo "    $DISTRIB_DESCRIPTION ($DISTRIB_ARCH)"

# ---------------------------------------------------------------- 1. packages
if ! command -v apk >/dev/null 2>&1; then
	echo "!! apk package manager not found (OpenWrt < 24.10 is not supported)" >&2
	exit 1
fi
missing=""
for p in $PKGS; do
	apk info -e "$p" >/dev/null 2>&1 || missing="$missing $p"
done
if [ -n "$missing" ]; then
	echo "==> installing packages:$missing"
	# shellcheck disable=SC2086
	apk add -q $missing || { echo "!! package installation failed" >&2; exit 1; }
else
	echo "==> packages already present"
fi

# ------------------------------------------------------------------ 2. files
echo "==> copying files"
mkdir -p /etc/vpnexit /usr/share/vpnexit /var/run/vpnexit /www/vpnexit
cp -a "$SRC/files/." /
chmod 0755 /usr/sbin/vpnexit /etc/init.d/vpnexit /www/cgi-bin/vpnexit 2>/dev/null || true
chmod 0644 /www/vpnexit/* /usr/share/vpnexit/* 2>/dev/null || true

# The backend lives outside the web root, so expose a read-only copy that can be
# opened directly from a browser.
cp /usr/share/vpnexit/vpnexit.uc /www/vpnexit/source.txt
chmod 0644 /www/vpnexit/source.txt

# LuCI caches the menu tree; drop it so "Services -> VPN Exit" shows up at once.
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null || true

# ------------------------------------------------------------------- 3. ca
# strongSwan's pem plugin reads one certificate per file, so the system bundle
# is split once. Chains learned per server are added later by the app.
if [ ! -d /etc/swanctl/x509ca ] || [ "$(ls /etc/swanctl/x509ca 2>/dev/null | wc -l)" -lt 10 ]; then
	echo "==> splitting system CA bundle"
	mkdir -p /etc/swanctl/x509ca
	ucode -e '
		let fs = require("fs");
		let txt = fs.readfile("/etc/ssl/certs/ca-certificates.crt") ?? "";
		let parts = split(txt, "-----END CERTIFICATE-----");
		let i = 0;
		for (let p in parts) {
			let s = index(p, "-----BEGIN CERTIFICATE-----");
			if (s >= 0) {
				fs.writefile(sprintf("/etc/swanctl/x509ca/sys-%03d.pem", i), substr(p, s) + "-----END CERTIFICATE-----\n");
				i++;
			}
		}
		printf("    %d roots\n", i);
	'
fi

# ------------------------------------------------------- 4. charon drop-in
cat > /etc/strongswan.d/vpnexit.conf <<'EOF'
# Managed by vpnexit - do not edit.
#
# Routes are installed by vpnexit (marked LAN traffic -> table 417); charon must
# never touch the main routing table or the router's own traffic would follow
# the tunnel.
#
# install_virtual_ip is deliberately OFF.  charon adds the address the peer
# assigned to the uplink interface before it installs the CHILD_SA; on some
# vendor kernels (observed on Octeon / OpenWrt 25.x) that sequence panics the
# kernel.  vpnexit learns the address from the SA and uses it only as the SNAT
# target, which is all that is required for the tunnel to work.
charon {
	install_routes = no
	install_virtual_ip = no
	port = 500
	port_nat_t = 4500
	plugins {
		kernel-libipsec { load = no }
		farp { load = no }
		stroke { load = no }
	}
}
EOF

# -------------------------------------------------------------- 5. defaults
mkdir -p /etc/config
if [ ! -f /etc/config/vpnexit ]; then
	echo "==> writing /etc/config/vpnexit"
	token=$(head -c 16 /dev/urandom | hexdump -v -e '/1 "%02x"')
	cat > /etc/config/vpnexit <<EOF
config vpnexit 'main'
	option enabled '1'
	option token '$token'
	option feed_url 'https://s-gke-euw1-nssi3-4.europe-west1.firebasedatabase.app/.json?ns=global-vpn-ios'
	option refresh_hours '24'
	option share_lan '1'
	option block_ipv6 '1'
	option auto_reconnect '1'
	option reconnect_attempts '5'
	option tunnel_mtu '1400'
	option mark '0x1a1'
	option table '417'
	option rule_priority '1000'
	option watchdog_seconds '20'
	option deadman_seconds '45'
	# Update fallback chain: direct -> tunnel -> these SSH relays.
	# Format: user@host:port,user@host:port  (relay_pass is used by sshpass)
	option relay_enabled '0'
	option relay_list ''
	option relay_pass ''
	option lan_iface ''
	option brand 'VPN Exit'
EOF
else
	echo "==> keeping existing /etc/config/vpnexit"
fi

# --------------------------------------------------------------- 6. service
echo "==> starting services"
/etc/init.d/swanctl enable 2>/dev/null || true
/etc/init.d/swanctl restart 2>/dev/null || /etc/init.d/swanctl start 2>/dev/null || true
/etc/init.d/vpnexit enable
/etc/init.d/vpnexit restart

# --------------------------------------------------------- 7. first refresh
echo "==> fetching profiles"
/usr/sbin/vpnexit refresh >/dev/null 2>&1 || echo "    (feed fetch failed - retry from the panel)"

TOKEN=$(uci -q get vpnexit.main.token)
IP=$(uci -q get network.lan.ipaddr | cut -d/ -f1)
[ -n "$IP" ] || IP=192.168.1.1
cat <<EOF

  vpnexit is running.

  Panel   : http://${IP:-192.168.1.1}/vpnexit/
  Token   : ${TOKEN}

  Service : /etc/init.d/vpnexit {start|stop|restart|status}
  CLI     : vpnexit status | locations | connect <key> | disconnect | selftest

EOF
