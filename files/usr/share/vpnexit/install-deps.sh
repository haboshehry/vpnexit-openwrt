#!/bin/sh
# Install the optional VPN clients used by the vpnexit panel.
#
#   install-deps.sh              install everything
#   install-deps.sh ikev2 vless  install the clients for these protocols only
#
# OpenVPN is special-cased.  In the 25.12 feed openvpn-openssl depends on
# kmod-ovpn-backports, a module that is not built for every target; when the
# package manager cannot resolve it the 24.10 userland package is unpacked
# instead.  The missing module only carries the optional DCO data-channel
# offload, so a plain tun based client keeps working.
#
# Both apk (OpenWrt 25.x) and opkg (24.10 and older, and vendor images) are
# supported.

set -u

TYPES="${*:-ikev2 l2tp sstp openvpn wireguard amneziawg vless}"
PKGS=""
say() { echo "[deps] $*"; }

if command -v apk >/dev/null 2>&1; then
	PM=apk
elif command -v opkg >/dev/null 2>&1; then
	PM=opkg
else
	say "neither apk nor opkg was found"
	exit 1
fi

pkg_add() {
	if [ "$PM" = "apk" ]; then
		apk add "$@"
	else
		opkg install "$@"
	fi
}

pkg_update() {
	if [ "$PM" = "apk" ]; then
		apk update
	else
		opkg update
	fi
}

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

pkg_update >/dev/null 2>&1 || say "package index update failed, using the cached one"

# Remove world entries left behind by an earlier failed install; apk refuses to
# resolve anything while an unknown constraint sits in /etc/apk/world.
if [ "$PM" = "apk" ] && grep -q -e '^openvpn-openssl$' -e '^openvpn-mbedtls$' -e '^libcap-ng0$' /etc/apk/world 2>/dev/null; then
	grep -v -e '^openvpn-openssl$' -e '^openvpn-mbedtls$' -e '^libcap-ng0$' /etc/apk/world > /tmp/vpx-world
	cat /tmp/vpx-world > /etc/apk/world
	say "cleaned stale entries from the apk world file"
fi

if [ -n "$PKGS" ]; then
	say "installing:$PKGS"
	if ! pkg_add $PKGS >/tmp/vpx-apk.log 2>&1; then
		# One unknown name must not block the rest.  On apk a single file
		# conflict (sstp-client and ppp both ship /etc/ppp/chap-secrets) aborts
		# every transaction while the package sits in the world file, so the
		# retry lets the conflicting package take the file over.
		retry=""
		for p in $PKGS; do
			pkg_add "$p" >>/tmp/vpx-apk.log 2>&1 || retry="$retry $p"
		done
		if [ -n "$retry" ] && [ "$PM" = "apk" ]; then
			for p in $retry; do
				apk add --force-overwrite "$p" >>/tmp/vpx-apk.log 2>&1 || say "could not install $p"
			done
		elif [ -n "$retry" ]; then
			say "could not install:$retry"
		fi
	fi
	if [ -s /tmp/vpx-apk.log ]; then
		grep -i -e 'error' -e 'conflict' /tmp/vpx-apk.log | tail -n 3 | sed 's/^/[deps]   /'
	fi
fi

install_openvpn() {
	command -v openvpn >/dev/null 2>&1 && return 0
	say "installing openvpn"
	if pkg_add openvpn-openssl >>/tmp/vpx-apk.log 2>&1; then
		return 0
	fi
	say "openvpn-openssl is not installable here (missing kmod), using the 24.10 userland build"
	pkg_add libcap-ng liblzo2 liblz4-1 libnl-genl200 libopenssl3 kmod-tun >>/tmp/vpx-apk.log 2>&1 || true

	REL="${OPENVPN_FALLBACK_RELEASE:-24.10.4}"
	# Take the architecture from the release file instead of parsing it with
	# sed: the quotes around the value differ between releases (25.12 uses
	# single quotes), and a failed parse used to fall back to a hardcoded ARM
	# arch.  Unpacking that package on a mips64/octeon router replaced openvpn
	# and its libraries with binaries that cannot run.
	ARCH=""
	[ -f /etc/openwrt_release ] && . /etc/openwrt_release
	ARCH="${DISTRIB_ARCH:-$ARCH}"
	if [ -z "$ARCH" ]; then
		say "cannot determine the target architecture, not using the fallback package"
		return 1
	fi
	BASE="https://downloads.openwrt.org/releases/$REL/packages/$ARCH/packages"
	say "fallback package source: $REL/$ARCH"
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
	# Never leave a binary of the wrong architecture behind: it replaces the
	# working client and fails only at connect time.
	if ! openvpn --version >/dev/null 2>&1; then
		say "the $REL package does not run on this router (arch $ARCH), restoring the package manager copy"
		if [ "$PM" = "apk" ]; then
			pkg_add --force-overwrite openvpn-openssl >>/tmp/vpx-apk.log 2>&1 || true
		else
			pkg_add openvpn-openssl >>/tmp/vpx-apk.log 2>&1 || true
		fi
		return 1
	fi
	echo "$REL $FILE" > /etc/vpnexit/.openvpn-legacy
	return 0
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
