# vpnexit

A single panel on an OpenWrt router that brings up **one VPN tunnel** and shares
it with the LAN, without touching the router's own default route.

Version 2 adds a manual mode: besides the profile feed, you can add your own
profile for **IKEv2, L2TP/IPsec, SSTP, OpenVPN, WireGuard, AmneziaWG and
VLESS/REALITY**, connect it, test the exit, and share it with the LAN.

```
        LAN clients                                          VPN server
  192.168.68.0/24  ──►  nft mark 0x1a1  ──►  table 417  ──►  tunnel  ──►  internet
                              │                                   ▲
                       router itself stays on the WAN uplink ─────┘
```

The router keeps its normal internet access: only forwarded LAN traffic (and
DNS from the router) is marked, so SSH to the router keeps working while the
tunnel is up.

## Supported protocols

| Type | Client used | Status |
|------|-------------|--------|
| IKEv2 (EAP-MSCHAPv2 or PSK) | strongSwan + swanctl | verified end to end |
| WireGuard | kernel `wg` | verified end to end |
| OpenVPN | `openvpn` (tun) | verified end to end |
| L2TP/IPsec | strongSwan transport + `xl2tpd` | transport + PPP stage verified |
| SSTP | `sstpc` + pppd | profile and error path verified, needs a live server |
| AmneziaWG | `awg` when present, else `wg` | fallback verified |
| VLESS / REALITY | `sing-box` (tun) | config + REALITY mapping verified |

Notes:

* **AmneziaWG** needs the `kmod-amneziawg` module, which is not in the official
  OpenWrt feed. The panel detects it: with `awg` installed the obfuscation keys
  are used, otherwise the profile runs as plain WireGuard and the panel shows
  that the obfuscation parameters are ignored.
* **OpenVPN**: on 25.12 `openvpn-openssl` depends on `kmod-ovpn-backports`,
  which is not built for every target. `install-deps.sh` falls back to the
  24.10 userland package (the missing module only carries the optional DCO
  offload).
* **VLESS** is handled by `sing-box`, which implements the same protocol and
  REALITY. Paste a `vless://` URL, the panel parses it and generates the
  outbound.

## Install

On the router:

```sh
git clone https://github.com/haboshehry/vpnexit-openwrt /tmp/vpnexit
cd /tmp/vpnexit
sh install.sh              # files only
sh install.sh --with-deps  # also install the VPN clients
```

The panel is then at `http://<router>/vpnexit/`. The first request asks for the
token; it is printed by `install.sh` and stored in `/etc/config/vpnexit`
(`token`). To read it again:

```sh
uci get vpnexit.main.token
```

## Using the panel

**Connections** — add one profile per VPN:

| Field | Meaning |
|-------|---------|
| IKEv2 | server, username, password; optional remote ID and PSK (PSK mode replaces EAP) |
| L2TP/IPsec | server, username, password, IPsec PSK |
| SSTP | server, port, username, password |
| OpenVPN | paste the `.ovpn` file, optional username/password |
| WireGuard / AmneziaWG | paste the `wg.conf` / Amnezia config |
| VLESS | paste the `vless://...` URL |

`Connect` brings the tunnel up and applies the routing. `Test` connects,
verifies the exit, and puts the previous tunnel back. `Disconnect` removes the
tunnel and every rule it added.

**Exit feed** — the daily profile feed, if `feed_url` is set. Each location is
an IKEv2 profile with failover to the other servers of the same location.

**Share with LAN** — on by default. When a tunnel is connected:

* LAN forwarding is marked `0x1a1` and routed through table 417.
* The tunnel interface gets a temporary `vpnexit` firewall zone, so `fw4`
  accepts the forwarded traffic, and a `masquerade`/`snat` rule for the marked
  packets.
* DNS from the LAN is redirected to the router, and the router's own queries to
  public resolvers are marked so they leave through the tunnel too. Queries to
  the ISP resolver (a LAN address) are left alone.
* IPv6 from the LAN is blocked while the tunnel is up, so nothing leaks around it.

Turning the switch off removes the rules but keeps the tunnel up (the router
itself can still use it).

## CLI

```sh
vpnexit status                     # JSON status
vpnexit connections                # configured profiles
vpnexit connect <id|loc:key:0>     # connect synchronously
vpnexit disconnect
vpnexit selftest                   # compare direct and tunnel exit IP
vpnexit conn-save /tmp/c.json      # provision a profile from JSON
vpnexit conn-delete <id>
vpnexit caps                       # which clients are installed
vpnexit refresh                    # re-download the profile feed
```

Connecting from the panel is asynchronous (the CGI request would time out), the
panel polls `/api/status` while the worker runs.

## Health test

`tests/loopback-test.sh` runs a server on the router itself for every protocol
that can be tested locally (WireGuard handshake, OpenVPN TLS, VLESS, the L2TP
PPP stage) and checks the real data path with a marked probe:

```sh
sh tests/loopback-test.sh            # all
sh tests/loopback-test.sh wireguard  # one
VPX_BIN=/tmp/vpnexit.uc FEED_KEY=free-canada sh tests/loopback-test.sh ikev2
```

The tests found two real bugs during development: a `lock` option that OpenWrt's
`pppd` rejects (the L2TP profile failed to start PPP) and a point-to-point
address parse that made every tun/ppp tunnel look like it had no address.

## Files

```
/etc/config/vpnexit            settings (token, feed, mark, table, mtu)
/etc/vpnexit/connections.json  manual profiles (0600)
/etc/vpnexit/run/<id>/         generated config and logs per profile
/usr/share/vpnexit/vpnexit.uc  backend (ucode), CLI + CGI API
/usr/share/vpnexit/install-deps.sh
/www/cgi-bin/vpnexit           CGI entry point
/www/vpnexit/                  panel
/var/run/vpnexit/state.json    current tunnel state
```

## Uninstall

```sh
sh uninstall.sh          # removes the panel and its files
apk del openvpn-openssl sing-box sstp-client xl2tpd wireguard-tools   # optional
```
