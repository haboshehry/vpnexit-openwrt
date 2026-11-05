#!/bin/sh
# Install the optional VPN clients used by the vpnexit panel.
#
#   install-deps.sh              install everything
#   install-deps.sh ikev2 vless  install the clients for these protocols only
#
# OpenVPN is special-cased.  In the 25.12 feed openvpn-openssl depends on
# kmod-ovpn-backports, a module that is not built for every target; when apk
# cannot resolve it the 24.10 userland package is unpacked instead.  The
# missing module only carries the optional DCO data-channel offload, so a
# plain tun based client keeps working.

set -u

TYPES="${*:-ikev2 l2tp sstp openvpn wireguard amneziawg vless}"
PKGS=""
say() { echo "[deps] $*"; }

add_pkgs() {
	for p in $1; do
		case " $PKGS " in
			*" $p "*) ;;
			*) PKGS="$PKGS $p" ;;
		esac
	done
}

has_type() {
	case " $TYPES " in *" $1 "*) return 0 ;; esac
	return 1
}

if has_type ikev2 || has_type l2tp; then
	add_pkgs "strongswan-charon strongswan-swanctl strongswan-mod-eap-mschapv2 strongswan-mod-pem strongswan-mod-openssl strongswan-mod-gmp strongswan-mod-kernel-netlink strongswan-mod-sha2 strongswan-mod-aes strongswan-mod-hmac strongswan-mod-pubkey strongswan-mod-x509"
fi
if has_type l2tp; then
	add_pkgs "xl2tpd kmod-l2tp ppp ppp-mod-pppol2tp"
fi
if has_type sstp; then
	add_pkgs "sstp-client ppp"
fi
if has_type wireguard || has_type amneziawg; then
	add_pkgs "kmod-wireguard wireguard-tools"
fi
if has_type vless; then
	add_pkgs "xray-core kmod-nft-tproxy"
fi

apk update >/dev/null 2>&1 || say "apk update failed, using the cached index"

# Remove world entries left behind by an earlier failed install; apk refuses to
# resolve anything while an unknown constraint sits in /etc/apk/world.
if grep -q -e '^openvpn-openssl$' -e '^openvpn-mbedtls$' -e '^libcap-ng0$' /etc/apk/world 2>/dev/null; then
	grep -v -e '^openvpn-openssl$' -e '^openvpn-mbedtls$' -e '^libcap-ng0$' /etc/apk/world > /tmp/vpx-world
	cat /tmp/vpx-world > /etc/apk/world
	say "cleaned stale entries from the apk world file"
fi

if [ -n "$PKGS" ]; then
	say "installing:$PKGS"
	if ! apk add $PKGS >/tmp/vpx-apk.log 2>&1; then
		# One unknown name must not block the rest.
		for p in $PKGS; do
			apk add "$p" >>/tmp/vpx-apk.log 2>&1 || say "could not install $p"
		done
	fi
fi

install_openvpn() {
	command -v openvpn >/dev/null 2>&1 && return 0
	say "installing openvpn"
	if apk add openvpn-openssl >>/tmp/vpx-apk.log 2>&1; then
		return 0
	fi
	say "openvpn-openssl is not installable here (missing kmod), using the 24.10 userland build"
	apk add libcap-ng liblzo2 liblz4-1 libnl-genl200 libopenssl3 kmod-tun >>/tmp/vpx-apk.log 2>&1 || true

	REL="${OPENVPN_FALLBACK_RELEASE:-24.10.4}"
	ARCH=$(sed -n 's/^DISTRIB_ARCH="\(.*\)"/\1/p' /etc/openwrt_release 2>/dev/null)
	[ -z "$ARCH" ] && ARCH="arm_cortex-a7_neon-vfpv4"
	BASE="https://downloads.openwrt.org/releases/$REL/packages/$ARCH/packages"
	rm -rf /tmp/vpx-ovpn && mkdir -p /tmp/vpx-ovpn
	if ! uclient-fetch -q -O /tmp/vpx-ovpn/Packages --timeout=40 "$BASE/Packages"; then
		say "cannot download the package index from $BASE"
		return 1
	fi
	FILE=$(awk '/^Package: openvpn-openssl$/,/^$/' /tmp/vpx-ovpn/Packages | sed -n 's/^Filename: //p' | head -n 1)
	if [ -z "$FILE" ]; then
		say "openvpn-openssl is not in the $REL index"
		return 1
	fi
	say "fetching $FILE"
	if ! uclient-fetch -q -O /tmp/vpx-ovpn/openvpn.ipk --timeout=60 "$BASE/$FILE"; then
		say "download failed"
		return 1
	fi
	(
		cd /tmp/vpx-ovpn || exit 1
		tar -xzf openvpn.ipk || exit 1
		tar -xzf data.tar.gz -C / || exit 1
	) || { say "could not unpack the package"; return 1; }
	echo "$REL $FILE" > /etc/vpnexit/.openvpn-legacy
	command -v openvpn >/dev/null 2>&1 && return 0
	return 1
}

if has_type openvpn; then
	install_openvpn || say "openvpn stays unavailable"
fi

say "done"
command -v openvpn >/dev/null 2>&1 && say "openvpn: $(openvpn --version 2>/dev/null | head -n 1)"
command -v wg >/dev/null 2>&1 && say "wireguard: $(wg --version 2>/dev/null)"
command -v sing-box >/dev/null 2>&1 && say "sing-box: $(sing-box version 2>/dev/null | head -n 1)"
command -v sstpc >/dev/null 2>&1 && say "sstp-client: $(sstpc --version 2>&1 | head -n 1)"
exit 0
