# vpnexit for OpenWrt

A small web panel that lives on the router, downloads a daily IKEv2 profile
feed, connects the router to the location you pick, and shares that exit with
every wired and Wi-Fi client on the LAN.

* panel: `http://192.168.1.1/vpnexit/`
* no Python, no Node, no jq — the backend is a single `ucode` script (ucode is
  already part of LuCI, so nothing extra runs in the background)
* the router keeps using its own uplink; only LAN traffic is steered

```
LAN/Wi-Fi client ──► router (nft mark 0x1a1)
                        ├─ ip rule fwmark 0x1a1 → table 417
                        ├─ SNAT to the address assigned by the peer
                        ├─ ESP (IKEv2 / strongSwan) → VPN exit
                        └─ router's own SSH/LuCI/DNS traffic stays on WAN
```

## Install

```sh
scp vpnexit-openwrt.tar.gz root@192.168.1.1:/tmp/
ssh root@192.168.1.1
cd /tmp && tar xzf vpnexit-openwrt.tar.gz && sh vpnexit-openwrt/install.sh
```

The installer is idempotent: it only adds missing packages, keeps
`/etc/config/vpnexit` and the downloaded profile cache, then prints the panel
URL and the admin token.

Requirements: OpenWrt 24.10+ (the `apk` package manager), `ucode`, `nftables`
(fw4). Tested on OpenWrt 25.12.6 / mips64 octeon.

## Use

1. Open `http://192.168.1.1/vpnexit/` and paste the token.
2. Press **Refresh** if the list is empty.
3. Pick a country. The panel connects, installs the routing rules, and
   verifies the exit address. Every LAN/Wi-Fi device now uses that exit.
4. **Disconnect** removes the rules and the tunnel; the router and the LAN
   return to the normal uplink.

CLI:

```sh
vpnexit status
vpnexit locations
vpnexit connect free-netherlands 0
vpnexit selftest
vpnexit disconnect
```

## Settings (`/etc/config/vpnexit`)

| option | default | meaning |
|---|---|---|
| `feed_url` | the Firebase feed | JSON profile feed |
| `refresh_hours` | `24` | how often the supervisor downloads the feed |
| `share_lan` | `1` | steer LAN/Wi-Fi traffic through the tunnel |
| `block_ipv6` | `1` | drop IPv6 forwarded from the LAN while the tunnel is up |
| `auto_reconnect` | `1` | re-establish a dropped tunnel |
| `reconnect_attempts` | `5` | attempts before giving up |
| `tunnel_mtu` | `1400` | MSS is clamped to `mtu - 40` |
| `mark` / `table` / `rule_priority` | `0x1a1` / `417` / `1000` | policy routing knobs |
| `lan_iface` | auto (`br-lan`) | interface whose traffic is redirected |
| `token` | generated | panel password |

## How it works

* **Profiles** — `uclient-fetch` pulls the feed, `ucode` normalises it
  (`title_en`, country code derived from the key, premium flag, server list) and
  caches it in `/etc/vpnexit/locations.json`.
* **Trust** — the peers only send their leaf certificate inside IKE_AUTH, so the
  issuer chain is learned once over TLS from the same host, the leaf name is
  verified with `openssl x509 -checkhost`, and the issuers are stored as single
  PEM files under `/etc/swanctl/x509ca/` (the pem plugin reads one cert per
  file). The system CA bundle is split once at install time.
* **Tunnel** — one swanctl connection (`vpnexit`) with EAP-MSCHAPv2, DPD every
  30 s, wildcard traffic selectors. `charon` runs with `install_routes = no`
  and `install_virtual_ip = no`; routing and NAT belong to the panel.
* **Routing** — LAN packets are marked in `prerouting` (nftables), a dedicated
  ip rule sends marked packets to table 417, that table only holds a default
  route via the WAN gateway, and a `srcnat` rule rewrites the source to the
  address the peer assigned. Conntrack reverses the NAT for the replies, so no
  address has to be configured locally.
* **Health** — the supervisor checks the CHILD_SA every 20 s, restores missing
  rules, reconnects with a bounded retry count, and refreshes the feed once a
  day.

## Footprint

Measured on the test device (2 × octeon, 400 MB RAM):

* `charon` ≈ 4 MB RSS, supervisor (`ucode`) ≈ 2 MB RSS
* panel assets ≈ 30 KB; no extra daemon — the panel is served by the existing
  uhttpd on port 80 and its API is one CGI process per request
* runtime state lives in `/var/run/vpnexit` (tmpfs), so there are no periodic
  flash writes apart from the daily profile cache

## Known issue: kernel panic on some vendor kernels

While testing on **OpenWrt 25.12.6 / Ubiquiti USG (mips64 octeon)** the kernel
panicked whenever `charon` installed the address the peer assigned
(`install_virtual_ip = yes`) right before installing the CHILD_SA. Raw
`ip xfrm` operations (state, policy, encap, replay, ESP output) and the ESP data
path were verified to be stable on the same kernel, so the trigger is the
address installation step performed by strongSwan.

`install_virtual_ip = no` avoids it: the address is only used as the SNAT
target, which is sufficient. That is the default written by the installer.

A tunnel established with that setting carried real traffic (exit address
`50.7.177.71` instead of the uplink `38.180.210.34`, ESP counters increasing).
If you see a reboot during connect on a different device, check
`/etc/strongswan.d/vpnexit.conf` first.

## Uninstall

```sh
sh /tmp/vpnexit-openwrt/uninstall.sh
```

Keeps `/etc/config/vpnexit`; pass `--purge` to remove the configuration and the
profile cache as well.
