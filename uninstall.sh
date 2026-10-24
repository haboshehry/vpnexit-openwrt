#!/bin/sh
# Remove vpnexit from an OpenWrt device. The strongSwan packages themselves are
# left in place: they may be used by other tooling on the router.
set -e

PURGE=0
[ "$1" = "--purge" ] && PURGE=1

[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

echo "==> stopping services"
/etc/init.d/vpnexit stop 2>/dev/null || true
/etc/init.d/vpnexit disable 2>/dev/null || true

echo "==> removing routing state"
if command -v vpnexit >/dev/null 2>&1; then
	/usr/sbin/vpnexit disconnect >/dev/null 2>&1 || true
fi
nft delete table inet vpnexit 2>/dev/null || true
nft delete table ip vpnexit_nat 2>/dev/null || true
nft delete table inet vpnexit_probe 2>/dev/null || true
MARK=$(uci -q get vpnexit.main.mark || echo 0x1a1)
TABLE=$(uci -q get vpnexit.main.table || echo 417)
PRIO=$(uci -q get vpnexit.main.rule_priority || echo 1000)
i=0
while [ $i -lt 4 ]; do
	ip rule del fwmark "$MARK" lookup "$TABLE" priority "$PRIO" 2>/dev/null || true
	i=$((i + 1))
done
ip route flush table "$TABLE" 2>/dev/null || true

echo "==> removing files"
rm -f /usr/sbin/vpnexit \
      /etc/init.d/vpnexit \
      /www/cgi-bin/vpnexit \
      /etc/strongswan.d/vpnexit.conf \
      /etc/swanctl/conf.d/vpnexit.conf \
      /etc/swanctl/conf.d/vpnexit-secrets.conf
rm -rf /usr/share/vpnexit /www/vpnexit /var/run/vpnexit
rm -f /etc/swanctl/x509ca/vpnx-*.pem

if [ "$PURGE" = "1" ]; then
	echo "==> removing configuration and cached profiles"
	rm -rf /etc/vpnexit
	rm -f /etc/config/vpnexit
else
	echo "==> kept /etc/config/vpnexit and /etc/vpnexit (use --purge to remove)"
fi

echo "==> done"
