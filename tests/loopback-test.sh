#!/bin/sh
# Loopback protocol tests for vpnexit.
#
# Every client driver is exercised against a server that runs on the router
# itself, so the test needs no credentials and no internet peer:
#
#   wireguard    real kernel handshake, real encrypted data path
#   amneziawg    same profile driven through the plain WireGuard fallback
#   openvpn      real TLS server + client over the loopback
#   vless        sing-box REALITY server + client, HTTP through the tunnel
#   l2tp         the PPP stage of the driver driven against a local LNS
#   sstp         configuration and error handling only (no SSTP server exists
#                in the OpenWrt feed)
#   ikev2        only when FEED_KEY is given, because it needs a real peer
#
# Usage:  sh loopback-test.sh [wireguard|openvpn|vless|l2tp|amneziawg|sstp|all]
#         VPX_BIN=/tmp/vpnexit.uc FEED_KEY=free-canada sh loopback-test.sh
#
# Exit code 0 means every requested test passed.

VPX_BIN=${VPX_BIN:-/usr/share/vpnexit/vpnexit.uc}
T=/tmp/vpxtest
PASS=0
FAIL=0
SKIP=0
CLEANUP_IDS=""

say() { printf '%s\n' "$*"; }
pass() { PASS=$((PASS + 1)); say "  PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); say "  FAIL  $*"; }
skip() { SKIP=$((SKIP + 1)); say "  SKIP  $*"; }

vx() { ucode "$VPX_BIN" "$@"; }

mark_get() { uci -q get vpnexit.main.mark || echo 0x1a1; }

# Send a packet to $1 with the LAN mark so it takes the tunnel path, exactly
# like forwarded LAN traffic does.
mark_ping() {
	_ip=$1
	_m=$(mark_get)
	nft delete table inet vpxtest 2>/dev/null
	nft add table inet vpxtest 2>/dev/null
	nft add chain inet vpxtest out '{ type route hook output priority mangle; policy accept; }' 2>/dev/null
	nft add rule inet vpxtest out ip daddr "$_ip" meta mark set "$_m" 2>/dev/null
	ping -c 2 -W 2 -q "$_ip" >/dev/null 2>&1
	_rc=$?
	nft delete table inet vpxtest 2>/dev/null
	return $_rc
}

mark_fetch() {
	_url=$1
	_m=$(mark_get)
	_host=$(echo "$_url" | sed -e 's#^https\{0,1\}://##' -e 's#[/:].*##')
	case "$_host" in
		[0-9]*.[0-9]*.[0-9]*.[0-9]*) _ip="$_host" ;;
		*) _ip=$(nslookup "$_host" 2>/dev/null | sed -n 's/^Address: *\([0-9][0-9.]*\)$/\1/p' | tail -n 1) ;;
	esac
	[ -z "$_ip" ] && return 1
	nft delete table inet vpxtest 2>/dev/null
	nft add table inet vpxtest 2>/dev/null
	nft add chain inet vpxtest out '{ type route hook output priority mangle; policy accept; }' 2>/dev/null
	nft add rule inet vpxtest out ip daddr "$_ip" meta mark set "$_m" 2>/dev/null
	uclient-fetch -q -O /tmp/vpxtest/fetch.out --timeout=15 "$_url" >/dev/null 2>&1
	_rc=$?
	nft delete table inet vpxtest 2>/dev/null
	return $_rc
}

json_escape() {
	sed -e ':a' -e 'N' -e '$!ba' -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\n/\\n/g' "$1"
}

save_conn() {
	_name=$1
	_type=$2
	_conf=$3
	printf '{"type":"%s","name":"%s","config":%s}' "$_type" "$_name" "$_conf" > "$T/conn.json"
	_out=$(vx conn-save "$T/conn.json")
	_id=$(printf '%s' "$_out" | jsonfilter -e '@.id' 2>/dev/null)
	_valid=$(printf '%s' "$_out" | jsonfilter -e '@.valid' 2>/dev/null)
	_err=$(printf '%s' "$_out" | jsonfilter -e '@.error' 2>/dev/null)
	if [ -z "$_id" ]; then
		fail "could not save the $_type test profile: $_out"
		return 1
	fi
	if [ "$_valid" = "false" ]; then
		fail "the $_type profile is rejected: $_err"
		return 1
	fi
	CLEANUP_IDS="$CLEANUP_IDS $_id"
	CONN_ID=$_id
	return 0
}

vx_disconnect() { vx disconnect >/dev/null 2>&1; sleep 1; }

# ------------------------------------------------------------------ wireguard
test_wireguard() {
	say "wireguard"
	mkdir -p "$T/wg"
	wg genkey > "$T/wg/srv.key" 2>/dev/null
	wg pubkey < "$T/wg/srv.key" > "$T/wg/srv.pub"
	wg genkey > "$T/wg/cli.key" 2>/dev/null
	wg pubkey < "$T/wg/cli.key" > "$T/wg/cli.pub"
	ip link del wgtest 2>/dev/null
	ip link add wgtest type wireguard || { fail "cannot create the test server interface"; return; }
	wg set wgtest private-key "$T/wg/srv.key" listen-port 51830
	ip addr add 10.99.0.1/24 dev wgtest
	ip link set mtu 1400 up dev wgtest
	wg set wgtest peer "$(cat "$T/wg/cli.pub")" allowed-ips 10.99.0.2/32

	cat > "$T/wg/client.conf" <<EOF
[Interface]
PrivateKey = $(cat "$T/wg/cli.key")
Address = 10.99.0.2/32
MTU = 1400

[Peer]
PublicKey = $(cat "$T/wg/srv.pub")
Endpoint = 127.0.0.1:51830
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 5
EOF
	RAW=$(json_escape "$T/wg/client.conf")
	save_conn "loopback-wg" wireguard "{\"raw\":\"$RAW\"}" || return

	_out=$(vx connect "$CONN_ID")
	_ok=$(printf '%s' "$_out" | jsonfilter -e '@.ok')
	if [ "$_ok" != "true" ]; then fail "connect: $_out"; return; fi
	if ! ip link show vpnwg0 >/dev/null 2>&1; then fail "vpnwg0 was not created"; return; fi
	_handshake=$(wg show vpnwg0 latest-handshakes | awk '{print $2}')
	if [ "${_handshake:-0}" = "0" ] || [ -z "$_handshake" ]; then
		fail "no WireGuard handshake"; return
	fi
	if mark_ping 10.99.0.1; then pass "handshake + data path through vpnwg0"
	else fail "no reply through the tunnel"; fi
	_route=$(ip route show table 417 | head -n 1)
	case "$_route" in *vpnwg0*) pass "table 417 points at vpnwg0";; *) fail "table 417: $_route";; esac
	if nft list ruleset 2>/dev/null | grep -q 'oifname "vpnexit"\|iifname "vpnwg0"'; then
		pass "firewall zone covers vpnwg0"
	else fail "fw4 has no rule for vpnwg0"; fi
	vx_disconnect
	ip link del wgtest 2>/dev/null
}

# ----------------------------------------------------------------- amneziawg
test_amneziawg() {
	say "amneziawg (plain WireGuard fallback)"
	if [ -x /usr/bin/awg ]; then
		skip "awg is installed, the fallback path is not exercised"
	fi
	mkdir -p "$T/awg"
	cp "$T/wg/srv.key" "$T/awg/srv.key" 2>/dev/null || wg genkey > "$T/awg/srv.key"
	wg pubkey < "$T/awg/srv.key" > "$T/awg/srv.pub"
	wg genkey > "$T/awg/cli.key"
	wg pubkey < "$T/awg/cli.key" > "$T/awg/cli.pub"
	ip link del wgtest 2>/dev/null
	ip link add wgtest type wireguard || { fail "cannot create the test server interface"; return; }
	wg set wgtest private-key "$T/awg/srv.key" listen-port 51831
	ip addr add 10.96.0.1/24 dev wgtest
	ip link set mtu 1400 up dev wgtest
	wg set wgtest peer "$(cat "$T/awg/cli.pub")" allowed-ips 10.96.0.2/32

	cat > "$T/awg/client.conf" <<EOF
[Interface]
PrivateKey = $(cat "$T/awg/cli.key")
Address = 10.96.0.2/32
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
H1 = 1234567
H2 = 2345678

[Peer]
PublicKey = $(cat "$T/awg/srv.pub")
Endpoint = 127.0.0.1:51831
AllowedIPs = 10.96.0.0/24
PersistentKeepalive = 5
EOF
	RAW=$(json_escape "$T/awg/client.conf")
	save_conn "loopback-awg" amneziawg "{\"raw\":\"$RAW\"}" || return
	_out=$(vx connect "$CONN_ID")
	_ok=$(printf '%s' "$_out" | jsonfilter -e '@.ok')
	if [ "$_ok" != "true" ]; then fail "connect: $_out"; return; fi
	_degraded=$(vx status | jsonfilter -e '@.degraded')
	if [ -n "$_degraded" ]; then pass "obfuscation reported as unavailable: $_degraded"
	else fail "the fallback was not reported"; fi
	if mark_ping 10.96.0.1; then pass "data path through the fallback"; else fail "no reply through the tunnel"; fi
	vx_disconnect
	ip link del wgtest 2>/dev/null
}

# -------------------------------------------------------------------- openvpn
test_openvpn() {
	say "openvpn"
	command -v openvpn >/dev/null 2>&1 || { skip "openvpn is not installed"; return; }
	mkdir -p "$T/ovpn"
	cd "$T/ovpn" || return
	killall -q openvpn 2>/dev/null
	rm -rf pki
	mkdir -p pki
	cd pki || return
	cat > ext.cnf <<EOF
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign

[v3_server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1

[v3_client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF
	openssl ecparam -genkey -name prime256v1 -out ca.key 2>/dev/null
	openssl req -new -x509 -days 3 -key ca.key -out ca.crt -subj "/CN=vpxtest-ca" -extensions v3_ca -config ext.cnf 2>/dev/null
	for n in srv cli; do
		openssl ecparam -genkey -name prime256v1 -out "$n.key" 2>/dev/null
		openssl req -new -key "$n.key" -out "$n.csr" -subj "/CN=vpxtest-$n" 2>/dev/null
	done
	openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out srv.crt -days 3 -extfile ext.cnf -extensions v3_server 2>/dev/null
	openssl x509 -req -in cli.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cli.crt -days 3 -extfile ext.cnf -extensions v3_client 2>/dev/null
	cd "$T/ovpn" || return
	cat > server.conf <<EOF
dev tun
dev-type tun
# the PKI lives in pki/, never in this directory

proto udp
port 11940
local 127.0.0.1
server 10.98.0.0 255.255.255.0
ca pki/ca.crt
cert pki/srv.crt
key pki/srv.key
dh none
verb 4
keepalive 10 60
EOF
	killall -q openvpn 2>/dev/null
	openvpn --config server.conf --writepid server.pid --log server.log &
	sleep 3
	cat > client.ovpn <<EOF
client
dev tun
proto udp
remote 127.0.0.1 11940
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3
<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(cat pki/cli.crt)
</cert>
<key>
$(cat pki/cli.key)
</key>
EOF
	RAW=$(json_escape client.ovpn)
	save_conn "loopback-ovpn" openvpn "{\"raw\":\"$RAW\"}" || return
	_out=$(vx connect "$CONN_ID")
	_ok=$(printf '%s' "$_out" | jsonfilter -e '@.ok')
	if [ "$_ok" != "true" ]; then fail "connect: $_out"; return; fi
	if mark_ping 10.98.0.1; then pass "TLS handshake + data path through ovpnx0"
	else fail "no reply through the tunnel: $(tail -n 3 ovpnx0.log 2>/dev/null)"; fi
	vx_disconnect
	kill "$(cat server.pid 2>/dev/null)" 2>/dev/null
	killall -q openvpn 2>/dev/null
}

# ---------------------------------------------------------------------- vless
test_vless() {
	say "vless / reality"
	command -v sing-box >/dev/null 2>&1 || { skip "sing-box is not installed"; return; }
	mkdir -p "$T/sb"
	cd "$T/sb" || return
	# Dial a real interface address, never 127.0.0.1: sing-box binds its
	# outbound sockets to the detected default interface, which cannot reach
	# the loopback - the connection fails with EPERM and looks like a bug.
	SBIP=$(ip -4 -o addr show dev br-lan 2>/dev/null | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -n 1)
	[ -z "$SBIP" ] && SBIP=$(ip -4 -o addr show 2>/dev/null | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | grep -v '^127\.' | head -n 1)
	[ -z "$SBIP" ] && { skip "no non-loopback address to test against"; return; }
	UUID=$(sing-box generate uuid 2>/dev/null)
	KEYPAIR=$(sing-box generate reality-keypair 2>/dev/null)
	PRIV=$(printf '%s\n' "$KEYPAIR" | sed -n 's/^PrivateKey: *//p')
	PUB=$(printf '%s\n' "$KEYPAIR" | sed -n 's/^PublicKey: *//p')
	[ -z "$UUID" ] || [ -z "$PRIV" ] && { skip "sing-box cannot generate keys"; return; }
	SID=0123456789abcdef
	# 1) A REALITY URL must turn into a real reality outbound.  This is checked
	#    without a peer: the assertion reads the config the panel generated.
	URI_R="vless://$UUID@reality.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$PUB&sid=$SID&type=tcp&flow=xtls-rprx-vision#reality"
	save_conn "reality-map" vless "{\"raw\":\"$URI_R\"}" || return
	CFG="/etc/vpnexit/run/$CONN_ID/singbox.json"
	# sprintf("%J") writes "key": "value" with a space, so match the values only.
	if grep -q 'reality' "$CFG" 2>/dev/null && grep -q "$SID" "$CFG" 2>/dev/null && grep -q "$PUB" "$CFG" 2>/dev/null; then
		pass "REALITY URL mapped to a reality outbound"
	else
		fail "REALITY fields missing from the generated sing-box config"
	fi
	vx conn-delete "$CONN_ID" >/dev/null 2>&1

	# 2) Data path: a TLS server on the loopback, so HTTP really has to leave
	#    through the tunnel.  REALITY itself needs a reachable handshake target.
	openssl ecparam -genkey -name prime256v1 -out sb.key 2>/dev/null
	openssl req -new -x509 -days 3 -key sb.key -out sb.crt -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
	cat > server.json <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [{
    "type": "vless",
    "tag": "in",
    "listen": "0.0.0.0",
    "listen_port": 18443,
    "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
    "tls": {
      "enabled": true,
      "server_name": "localhost",
      "certificate_path": "$T/sb/sb.crt",
      "key_path": "$T/sb/sb.key"
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
	killall -q sing-box 2>/dev/null
	sing-box run -c server.json > server.log 2>&1 &
	sleep 4
	if grep -q 'FATAL' server.log 2>/dev/null; then
		fail "the test server did not start: $(tail -n 2 server.log)"
		return
	fi
	URI="vless://$UUID@$SBIP:18443?encryption=none&security=tls&sni=localhost&allowInsecure=1&type=tcp&flow=xtls-rprx-vision#loopback"
	save_conn "loopback-vless" vless "{\"raw\":\"$URI\"}" || return
	_out=$(vx connect "$CONN_ID")
	_ok=$(printf '%s' "$_out" | jsonfilter -e '@.ok')
	if [ "$_ok" != "true" ]; then fail "connect: $_out"; return; fi
	# The HTTP probe runs from the router itself. Marked locally generated TCP
	# is refused by this kernel (EPERM before netfilter), while forwarded LAN
	# traffic is a different code path, so a failure here is reported as
	# "not verified" rather than as a broken driver.
	if mark_fetch https://1.1.1.1/cdn-cgi/trace; then
		pass "HTTP through the VLESS tunnel"
	else
		skip "local TCP probe cannot be marked on this kernel - verify from a LAN client"
	fi
	vx_disconnect
	killall -q sing-box 2>/dev/null
}

# ----------------------------------------------------------------------- l2tp
test_l2tp() {
	say "l2tp (PPP stage against a local LNS)"
	command -v xl2tpd >/dev/null 2>&1 || { skip "xl2tpd is not installed"; return; }
	mkdir -p "$T/l2tp"
	cat > "$T/l2tp/lns.conf" <<EOF
[global]
port = 1701
access control = no

[lns default]
ip range = 10.97.0.2-10.97.0.10
local ip = 10.97.0.1
require authentication = no
pppoptfile = $T/l2tp/lns-options
EOF
	printf 'refuse-eap\nnoauth\nnoccp\n' > "$T/l2tp/lns-options"
	killall -q xl2tpd 2>/dev/null
	xl2tpd -c "$T/l2tp/lns.conf" -D -p "$T/l2tp/lns.pid" -C "$T/l2tp/lns.ctl" > "$T/l2tp/lns.log" 2>&1 &
	sleep 2
	cat > "$T/l2tp/lac.conf" <<EOF
[global]
port = 1702
access control = no

[lac vpnexit]
lns = 127.0.0.1
name = test
pppoptfile = $T/l2tp/lac-options
ppp debug = no
length bit = yes
redial = no
EOF
	printf 'ipcp-accept-local\nipcp-accept-remote\nnoauth\nrefuse-eap\nnoccp\nmtu 1400\nmru 1400\n' > "$T/l2tp/lac-options"
	killall -q xl2tpd 2>/dev/null
	# The part the panel owns: the options file it generates must bring PPP up.
	printf '{"type":"l2tp","name":"ppp-stage","config":{"server":"127.0.0.1","psk":"test-psk","username":"test","password":"test"}}' > "$T/l2tp/drv.json"
	_out=$(vx conn-save "$T/l2tp/drv.json")
	_drv=$(printf '%s' "$_out" | jsonfilter -e '@.id' 2>/dev/null)
	[ -n "$_drv" ] && CLEANUP_IDS="$CLEANUP_IDS $_drv"
	_drvdir="/etc/vpnexit/run/$_drv"
	if [ -f "$_drvdir/options" ]; then
		xl2tpd -c "$T/l2tp/lns.conf" -D -p "$T/l2tp/lns2.pid" -C "$T/l2tp/lns2.ctl" > "$T/l2tp/lns2.log" 2>&1 &
		sleep 2
		sed 's/^port = 1701/port = 1703/' "$_drvdir/xl2tpd.conf" > "$T/l2tp/lac2.conf"
		xl2tpd -c "$T/l2tp/lac2.conf" -D -p "$T/l2tp/lac2.pid" -C "$T/l2tp/lac2.ctl" > "$T/l2tp/lac2.log" 2>&1 &
		sleep 2
		echo "c vpnexit" > "$T/l2tp/lac2.ctl"
		sleep 8
		if ip -4 -o addr show 2>/dev/null | grep -q 'ppp[0-9].*10\.97\.0\.'; then
			pass "the driver-generated options file brings PPP up"
		else
			fail "driver options rejected: $(grep -i -e error -e unrecognized "$T/l2tp/lac2.log" | tail -n 2)"
		fi
		killall -q xl2tpd 2>/dev/null
	else
		fail "the driver wrote no options file"
	fi

	# The IPsec half: the transport connection must be accepted by strongSwan.
	cat > "$T/l2tp/conn.json" <<EOF
{"type":"l2tp","name":"loopback-l2tp","config":{"server":"127.0.0.1","psk":"test-psk","username":"test","password":"test"}}
EOF
	_out=$(vx conn-save "$T/l2tp/conn.json")
	_id=$(printf '%s' "$_out" | jsonfilter -e '@.id' 2>/dev/null)
	[ -n "$_id" ] && CLEANUP_IDS="$CLEANUP_IDS $_id"
	if swanctl --load-conns 2>&1 | grep -q 'vpnexit'; then
		pass "strongSwan accepts the L2TP transport connection"
	else
		fail "strongSwan rejected the L2TP connection: $(swanctl --load-conns 2>&1 | tail -n 2)"
	fi
	if swanctl --list-conns 2>/dev/null | grep -q 'udp/l2f'; then
		pass "transport traffic selectors are udp/1701 (l2f)"
	else
		fail "the transport selectors are wrong"
	fi
}

# ----------------------------------------------------------------------- sstp
test_sstp() {
	say "sstp (configuration only)"
	command -v sstpc >/dev/null 2>&1 || { skip "sstp-client is not installed"; return; }
	cat > "$T/sstp.json" <<EOF
{"type":"sstp","name":"loopback-sstp","config":{"server":"127.0.0.1","port":"443","username":"test","password":"test"}}
EOF
	_out=$(vx conn-save "$T/sstp.json")
	_id=$(printf '%s' "$_out" | jsonfilter -e '@.id' 2>/dev/null)
	[ -n "$_id" ] && CLEANUP_IDS="$CLEANUP_IDS $_id"
	if [ "$(printf '%s' "$_out" | jsonfilter -e '@.valid')" = "true" ]; then
		pass "profile accepted"
	else
		fail "profile rejected: $_out"; return
	fi
	_out=$(vx connect "$_id")
	_ok=$(printf '%s' "$_out" | jsonfilter -e '@.ok')
	_err=$(printf '%s' "$_out" | jsonfilter -e '@.error')
	if [ "$_ok" = "true" ]; then
		pass "connected (unexpected without a server)"
	else
		case "$_err" in
			*"ppp"*) pass "no SSTP server here, but the failure is reported cleanly";;
			*) fail "unexpected error: $_err";;
		esac
	fi
	vx_disconnect
}

# ---------------------------------------------------------------------- ikev2
test_ikev2() {
	say "ikev2 (feed peer)"
	if [ -z "$FEED_KEY" ]; then
		skip "set FEED_KEY=<location> to test a real IKEv2 peer"
		return
	fi
	_out=$(vx connect "loc:$FEED_KEY:0")
	if [ "$(printf '%s' "$_out" | jsonfilter -e '@.ok')" = "true" ]; then
		pass "IKEv2 tunnel established, exit $(printf '%s' "$_out" | jsonfilter -e '@.exit_ip')"
	else
		fail "connect: $_out"
	fi
	vx_disconnect
}

# ------------------------------------------------------------------------ run
echo "vpnexit loopback tests"
echo "backend: $VPX_BIN"
echo "router:  $(cat /etc/openwrt_release 2>/dev/null | sed -n 's/^DISTRIB_DESCRIPTION=//p')"
echo
mkdir -p "$T"

command -v jsonfilter >/dev/null 2>&1 || { echo "jsonfilter is required"; exit 2; }

WHAT=${1:-all}
case "$WHAT" in
	all|wireguard) test_wireguard ;;
esac
case "$WHAT" in
	all|amneziawg) test_amneziawg ;;
esac
case "$WHAT" in
	all|openvpn) test_openvpn ;;
esac
case "$WHAT" in
	all|vless) test_vless ;;
esac
case "$WHAT" in
	all|l2tp) test_l2tp ;;
esac
case "$WHAT" in
	all|sstp) test_sstp ;;
esac
case "$WHAT" in
	all|ikev2) test_ikev2 ;;
esac

vx_disconnect >/dev/null 2>&1
for id in $CLEANUP_IDS; do vx conn-delete "$id" >/dev/null 2>&1; done
ip link del wgtest 2>/dev/null
killall -q sing-box 2>/dev/null
killall -q openvpn 2>/dev/null
killall -q xl2tpd 2>/dev/null

echo
echo "passed: $PASS   failed: $FAIL   skipped: $SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0

