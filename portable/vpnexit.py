#!/usr/bin/env python3
"""vpnexit - portable build for Debian / Ubuntu / Raspberry Pi / RaspAP.

Same panel and API as the OpenWrt build, without ucode: strongSwan (swanctl)
terminates one IKEv2 SA, nftables marks LAN traffic and a dedicated routing
table sends it through the tunnel, while the host keeps its own uplink.

Layout
  /etc/vpnexit/config.json     settings
  /etc/vpnexit/locations.json  cached feed
  /var/lib/vpnexit/state.json  runtime state
  /var/log/vpnexit.log         journal
"""
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.parse

BASE = "/etc/vpnexit"
STATE_DIR = "/var/lib/vpnexit"
STATE = os.path.join(STATE_DIR, "state.json")
CONF = os.path.join(BASE, "config.json")
LOCS = os.path.join(BASE, "locations.json")
CHAINS = os.path.join(BASE, "chains")
SWAN_CONF = "/etc/swanctl/conf.d/vpnexit.conf"
SWAN_SECRETS = "/etc/swanctl/conf.d/vpnexit-secrets.conf"
X509CA = "/etc/swanctl/x509ca"
LOG = "/var/log/vpnexit.log"
CONN = CHILD = "vpnexit"
PROBE = "https://1.1.1.1/cdn-cgi/trace"

DEFAULTS = {
    "feed_url": "https://s-gke-euw1-nssi3-4.europe-west1.firebasedatabase.app/.json?ns=global-vpn-ios",
    "token": "",
    "share_lan": True,
    "block_ipv6": True,
    "auto_reconnect": True,
    "tunnel_mtu": 1400,
    "refresh_hours": 24,
    "watchdog_seconds": 20,
    "retry_seconds": 120,
    "lan_iface": "",
    "mark": "0x1a1",
    "table": 417,
    "rule_priority": 1000,
    "relay_enabled": False,
    "relay_list": "",
    "relay_pass": "",
}


# --------------------------------------------------------------------- utils

def ensure_dirs():
    for d in (BASE, STATE_DIR, CHAINS, os.path.dirname(SWAN_CONF), X509CA):
        os.makedirs(d, exist_ok=True)


def log(msg):
    line = "%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg)
    try:
        with open(LOG, "a") as fh:
            fh.write(line)
        if os.path.getsize(LOG) > 256 * 1024:
            with open(LOG, "rb") as fh:
                tail = fh.read()[-128 * 1024:]
            with open(LOG, "wb") as fh:
                fh.write(tail)
    except OSError:
        pass


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def load_json(path, default):
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else default
    except (OSError, ValueError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def cfg(key=None):
    data = dict(DEFAULTS)
    data.update(load_json(CONF, {}))
    return data if key is None else data.get(key, DEFAULTS.get(key))


def cfg_set(**kw):
    data = dict(DEFAULTS)
    data.update(load_json(CONF, {}))
    data.update(kw)
    ensure_dirs()
    save_json(CONF, data)
    return data


def state_read():
    st = load_json(STATE, {"state": "idle"})
    st.setdefault("state", "idle")
    return st


def state_patch(**kw):
    st = state_read()
    st.update(kw)
    ensure_dirs()
    save_json(STATE, st)
    return st


# ------------------------------------------------------------------ profiles

COUNTRY = {
    "netherlands": "NL", "usa": "US", "unitedstates": "US", "germany": "DE",
    "france": "FR", "canada": "CA", "singapore": "SG", "japan": "JP",
    "unitedkingdom": "GB", "uk": "GB", "turkey": "TR", "turkiye": "TR",
    "uae": "AE", "emirates": "AE", "india": "IN", "brazil": "BR",
    "australia": "AU", "finland": "FI", "sweden": "SE", "norway": "NO",
    "spain": "ES", "italy": "IT", "poland": "PL", "switzerland": "CH",
    "austria": "AT", "belgium": "BE", "denmark": "DK", "ireland": "IE",
    "hongkong": "HK", "taiwan": "TW", "southkorea": "KR", "korea": "KR",
    "russia": "RU", "ukraine": "UA", "kazakhstan": "KZ", "romania": "RO",
    "bulgaria": "BG", "greece": "GR", "portugal": "PT", "mexico": "MX",
    "argentina": "AR", "chile": "CL", "colombia": "CO", "southafrica": "ZA",
    "egypt": "EG", "israel": "IL", "saudiarabia": "SA", "qatar": "QA",
    "kuwait": "KW", "pakistan": "PK", "bangladesh": "BD", "indonesia": "ID",
    "malaysia": "MY", "thailand": "TH", "vietnam": "VN", "philippines": "PH",
    "newzealand": "NZ", "czechia": "CZ", "hungary": "HU", "croatia": "HR",
    "serbia": "RS", "slovakia": "SK", "slovenia": "SI", "lithuania": "LT",
    "latvia": "LV", "estonia": "EE", "moldova": "MD", "armenia": "AM",
    "georgia": "GE", "azerbaijan": "AZ", "mongolia": "MN", "nepal": "NP",
}


def flag_emoji(cc):
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc)


def country_from_key(key):
    parts = [p for p in re.split(r"[-_]", (key or "").lower()) if p]
    while parts and parts[0] in ("free", "premium", "trial", "vip", "basic"):
        parts.pop(0)
    for start in range(len(parts)):
        for end in range(len(parts), start, -1):
            cand = "".join(parts[start:end])
            if cand in COUNTRY:
                return COUNTRY[cand]
    return COUNTRY.get(parts[-1], "") if parts else ""


def normalise(key, raw):
    if not isinstance(raw, dict) or not raw.get("published", True):
        return None
    entries = raw.get("ikev2")
    if not isinstance(entries, list):
        return None
    servers = []
    for e in entries:
        if not isinstance(e, dict) or not e.get("published", True):
            continue
        host = (e.get("server") or "").strip()
        ip = (e.get("ip") or "").strip()
        if not host and not ip:
            continue
        servers.append({
            "host": host or ip,
            "ip": ip,
            "user": (e.get("username") or "").strip(),
            "pass": e.get("password") or "",
            "local_id": (e.get("local_id") or e.get("username") or "").strip(),
        })
    if not servers:
        return None
    cc = country_from_key(key)
    if not cc:
        f = (raw.get("country") or "").strip().upper()
        cc = f[:2] if len(f) >= 2 and f[:2].isalpha() else ""
    title = (raw.get("title_en") or "").strip() or key.replace("-", " ").title()
    return {"key": key, "title": title, "country": cc, "flag": flag_emoji(cc),
            "premium": bool(raw.get("premium", False)),
            "position": raw.get("position", 999), "servers": servers}


def locations():
    data = load_json(LOCS, {"items": []})
    if not isinstance(data.get("items"), list):
        return {"items": [], "count": 0, "fetched_at": 0}
    return data


def find_location(key):
    for it in locations()["items"]:
        if it.get("key") == key:
            return it
    return None


# --------------------------------------------------------------------- fetch

def url_host(url):
    m = re.match(r"^https?://([^/:]+)", url or "")
    return m.group(1) if m else ""


def resolve4(host):
    rc, out = run("getent ahostsv4 %s" % shlex.quote(host), timeout=15)
    ips = []
    for line in out.splitlines():
        ip = line.split()[0] if line.split() else ""
        if ip.count(".") == 3 and ip not in ips:
            ips.append(ip)
    return ips[:4]


def fetch_direct(url, outfile):
    return run("curl -fsS --max-time 25 -o %s %s" % (shlex.quote(outfile), shlex.quote(url)), timeout=40)


def fetch_via_tunnel(url, outfile):
    host = url_host(url)
    ips = resolve4(host)
    if not ips:
        return 1, "cannot resolve %s" % host
    mark = cfg("mark")
    run("nft delete table inet vxprobe")
    run("nft add table inet vxprobe")
    run("nft add chain inet vxprobe out '{ type route hook output priority mangle; policy accept; }'")
    for ip in ips:
        run("nft add rule inet vxprobe out ip daddr %s meta mark set %s" % (ip, mark))
    try:
        rc, out = run("curl -fsS --max-time 30 -o %s %s" % (shlex.quote(outfile), shlex.quote(url)), timeout=45)
    finally:
        run("nft delete table inet vxprobe")
    log("refresh: tried %d address(es) through the tunnel, rc=%d" % (len(ips), rc))
    return rc, out


def fetch_via_relay(url, outfile):
    if not cfg("relay_enabled"):
        return 1, "relay disabled"
    relay_list = cfg("relay_list") or ""
    password = cfg("relay_pass") or ""
    if not relay_list or not password:
        return 1, "no relay configured"
    for item in [x.strip() for x in relay_list.split(",") if x.strip()]:
        user, host, port = "root", item, 22
        if "@" in host:
            user, host = host.split("@", 1)
        if ":" in host:
            host, port = host.rsplit(":", 1)
        try:
            port = int(port)
        except ValueError:
            port = 22
        log("refresh: trying relay %s:%d" % (host, port))
        remote = "curl -fsS --max-time 30 %s" % shlex.quote(url)
        cmd = ("sshpass -p %s ssh -p %d -o StrictHostKeyChecking=no "
               "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
               "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
               "%s@%s %s > %s") % (shlex.quote(password), port, shlex.quote(user),
                                   shlex.quote(host), shlex.quote(remote), shlex.quote(outfile))
        rc, _ = run(cmd, timeout=60)
        if rc != 0:
            continue
        try:
            with open(outfile) as fh:
                body = fh.read()
            if isinstance(json.loads(body), dict):
                log("refresh: fetched through relay %s (%d bytes)" % (host, len(body)))
                return 0, "relay %s" % host
        except (OSError, ValueError):
            continue
    return 1, "all relays failed"


def refresh():
    url = cfg("feed_url")
    ensure_dirs()
    tmp = os.path.join(STATE_DIR, "feed.json")
    rc, out = fetch_direct(url, tmp)
    if rc != 0 and state_read().get("state") == "connected":
        log("refresh: direct failed (%d), trying the tunnel" % rc)
        rc, out = fetch_via_tunnel(url, tmp)
    if rc != 0:
        rc, out = fetch_via_relay(url, tmp)
    if rc != 0:
        log("refresh: failed: %s" % out.strip()[:200])
        return {"ok": False, "error": "feed download failed"}
    try:
        with open(tmp) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {"ok": False, "error": "feed is not valid JSON"}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if not isinstance(doc, dict):
        return {"ok": False, "error": "feed root is not an object"}
    items = [x for x in (normalise(k, v) for k, v in doc.items()) if x]
    if not items:
        return {"ok": False, "error": "no usable profiles"}
    items.sort(key=lambda x: (x["premium"], x["position"], x["key"]))
    data = {"items": items, "count": len(items), "fetched_at": int(time.time())}
    save_json(LOCS, data)
    log("refresh: %d locations" % len(items))
    return {"ok": True, "count": len(items), "fetched_at": data["fetched_at"]}


# ---------------------------------------------------------------------- trust

def learn_chain(host):
    if not host:
        return False
    os.makedirs(CHAINS, exist_ok=True)
    cache = os.path.join(CHAINS, host + ".pem")
    if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < 604800:
        return True
    rc, out = run("openssl s_client -showcerts -servername %s -connect %s:443 </dev/null 2>/dev/null"
                  % (shlex.quote(host), shlex.quote(host)), timeout=25)
    if rc != 0 or "BEGIN CERTIFICATE" not in out:
        log("trust: no chain for %s" % host)
        return False
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not blocks:
        return False
    leaf = "/tmp/vpnexit-leaf.pem"
    with open(leaf, "w") as fh:
        fh.write(blocks[0] + "\n")
    rc, _ = run("openssl x509 -in %s -noout -checkhost %s" % (leaf, shlex.quote(host)), timeout=15)
    if rc != 0:
        log("trust: certificate does not match %s" % host)
        return False
    with open(cache, "w") as fh:
        fh.write("\n".join(blocks) + "\n")
    for i, block in enumerate(blocks[1:], 1):
        path = os.path.join(X509CA, "vpnx-%s-%02d.pem" % (host, i))
        with open(path, "w") as fh:
            fh.write(block + "\n")
    log("trust: learned %d issuer(s) for %s" % (len(blocks) - 1, host))
    return True


# ------------------------------------------------------------------- swanctl

IKE = "aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024"
ESP = "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1"


def write_conn(srv):
    ident = srv.get("local_id") or srv.get("user")
    addr = srv.get("ip") or srv.get("host")
    text = f"""# Managed by vpnexit
connections {{
  {CONN} {{
    version = 2
    local_addrs = %any
    remote_addrs = {addr}
    proposals = {IKE}
    local {{
      auth = eap-mschapv2
      id = {ident}
      eap_id = {srv['user']}
    }}
    remote {{
      auth = pubkey
      id = {srv['host']}
    }}
    vips = 0.0.0.0
    dpd_delay = 30s
    dpd_timeout = 120s
    children {{
      {CHILD} {{
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        esp_proposals = {ESP}
        start_action = none
        dpd_action = restart
        close_action = none
      }}
    }}
  }}
}}
"""
    with open(SWAN_CONF, "w") as fh:
        fh.write(text)
    secret = (srv.get("pass") or "").replace("\\", "\\\\").replace('"', '\\"')
    with open(SWAN_SECRETS, "w") as fh:
        fh.write('secrets {\n  eap-%s {\n    id = %s\n    secret = "%s"\n  }\n}\n'
                 % (CONN, ident, secret))
    os.chmod(SWAN_SECRETS, 0o600)


def sas_parse():
    rc, out = run("swanctl --list-sas", timeout=25)
    st = {"ike": False, "child": False, "vip": "", "remote": "", "rx": 0, "tx": 0, "uptime": 0}
    for line in out.splitlines():
        if re.match(r"^vpnexit: #\d+, ESTABLISHED", line):
            st["ike"] = True
        elif "INSTALLED" in line and "reqid" in line:
            st["child"] = True
        else:
            m = re.search(r"local\s+'[^']*'\s+@\s+[0-9.]+\[\d+\](?:\s+\[([0-9.]+)\])?", line)
            if m and not st["vip"] and m.group(1):
                st["vip"] = m.group(1)
                continue
            m = re.search(r"remote\s+'[^']*'\s+@\s+([0-9.]+)\[", line)
            if m:
                st["remote"] = m.group(1)
                continue
            m = re.match(r"\s+in\s+\S+,\s+(\d+)\s+bytes", line)
            if m:
                st["rx"] = int(m.group(1))
                continue
            m = re.match(r"\s+out\s+\S+,\s+(\d+)\s+bytes", line)
            if m:
                st["tx"] = int(m.group(1))
                continue
            m = re.search(r"established\s+(\d+)s ago", line)
            if m and not st["uptime"]:
                st["uptime"] = int(m.group(1))
    return st


# ------------------------------------------------------------------- routing

def iface_cidr(dev):
    rc, out = run("ip -4 -o addr show dev %s" % shlex.quote(dev), timeout=15)
    m = re.search(r"inet\s+([0-9.]+/\d+)", out)
    return m.group(1) if m else ""


def lan_iface():
    if cfg("lan_iface"):
        return cfg("lan_iface")
    for cand in ("br-lan", "br0", "wlan0", "eth0"):
        rc, _ = run("ip link show %s" % cand, timeout=10)
        if rc == 0:
            return cand
    return "eth0"


def default_route():
    rc, out = run("ip -4 route show default", timeout=15)
    line = out.splitlines()[0] if out.splitlines() else ""
    gw = re.search(r"via\s+([0-9.]+)", line)
    dev = re.search(r"dev\s+(\S+)", line)
    return (gw.group(1) if gw else None), (dev.group(1) if dev else None)


def ruleset(vip):
    mark, table = cfg("mark"), cfg("table")
    mtu = int(cfg("tunnel_mtu"))
    mss = max(1200, mtu - 80)
    lan = lan_iface()
    wan, _ = default_route()[1], None
    lan_cidr = iface_cidr(lan) or "192.168.1.0/24"
    excl = ["127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", lan_cidr, vip + "/32"]
    wan_cidr = iface_cidr(wan)
    if wan_cidr:
        excl.append(wan_cidr)
    srv = state_read().get("server_ip")
    if srv:
        excl.append(srv + "/32")
    rules = [
        "table inet vpnexit {",
        "\tset exclude4 {",
        "\t\ttype ipv4_addr",
        "\t\tflags interval",
        "\t\tauto-merge",
        "\t\telements = { %s }" % ", ".join(excl),
        "\t}",
        "\tchain mark {",
        "\t\ttype filter hook prerouting priority mangle; policy accept;",
        '\t\tiifname != "%s" return' % lan,
        "\t\tip daddr @exclude4 return",
        "\t\tmeta mark set %s counter" % mark,
        "\t}",
        "\tchain mss {",
        "\t\ttype filter hook postrouting priority mangle; policy accept;",
        "\t\tmeta mark %s tcp flags syn tcp option maxseg size set %d" % (mark, mss),
        "\t}",
        "\tchain dnsout {",
        "\t\ttype route hook output priority mangle; policy accept;",
        "\t\tudp dport 53 meta mark set %s counter" % mark,
        "\t\ttcp dport 53 meta mark set %s counter" % mark,
        "\t}",
    ]
    if cfg("block_ipv6"):
        rules += [
            "\tchain fwd6 {",
            "\t\ttype filter hook forward priority filter; policy accept;",
            '\t\tiifname "%s" oifname "%s" meta nfproto ipv6 drop' % (lan, wan),
            "\t}",
        ]
    rules += [
        "}",
        "table ip vpnexit_nat {",
        "\tchain post {",
        "\t\ttype nat hook postrouting priority srcnat; policy accept;",
        '\t\toifname "%s" meta mark %s counter snat ip to %s' % (wan, mark, vip),
        "\t}",
        "}",
    ]
    return "\n".join(rules) + "\n"


def routing_apply(vip):
    if not vip:
        return {"ok": False, "error": "no tunnel address"}
    gw, wan = default_route()
    if not wan:
        return {"ok": False, "error": "no default route"}
    text = ruleset(vip)
    ensure_dirs()
    path = os.path.join(STATE_DIR, "last.nft")
    with open(path, "w") as fh:
        fh.write(text)
    rc, out = run("nft -c -f %s" % shlex.quote(path), timeout=20)
    if rc != 0:
        log("routing: invalid ruleset: %s" % out.strip()[:200])
        return {"ok": False, "error": "ruleset rejected"}
    batch = ""
    if run("nft list table inet vpnexit")[0] == 0:
        batch += "delete table inet vpnexit\n"
    if run("nft list table ip vpnexit_nat")[0] == 0:
        batch += "delete table ip vpnexit_nat\n"
    batch += text
    bpath = os.path.join(STATE_DIR, "apply.nft")
    with open(bpath, "w") as fh:
        fh.write(batch)
    rc, out = run("nft -f %s" % shlex.quote(bpath), timeout=20)
    if rc != 0:
        log("routing: apply failed: %s" % out.strip()[:200])
        return {"ok": False, "error": "cannot apply rules"}
    table, prio, mark = cfg("table"), cfg("rule_priority"), cfg("mark")
    route = ("ip route replace default via %s dev %s table %d" % (gw, wan, table)
             if gw else "ip route replace default dev %s table %d" % (wan, table))
    rc, out = run(route, timeout=15)
    if rc != 0:
        return {"ok": False, "error": "cannot add route"}
    for _ in range(4):
        run("ip rule del fwmark %s lookup %d priority %d" % (mark, table, prio))
    rc, out = run("ip rule add fwmark %s lookup %d priority %d" % (mark, table, prio), timeout=15)
    if rc != 0:
        return {"ok": False, "error": "cannot add ip rule"}
    log("routing: active (%s -> %s via %s, vip %s)" % (lan_iface(), wan, gw or "-", vip))
    return {"ok": True, "vip": vip}


def routing_clear():
    table, prio, mark = cfg("table"), cfg("rule_priority"), cfg("mark")
    run("nft delete table inet vpnexit")
    run("nft delete table ip vpnexit_nat")
    run("nft delete table inet vpnexit_probe")
    for _ in range(4):
        run("ip rule del fwmark %s lookup %d priority %d" % (mark, table, prio))
    run("ip route flush table %d" % table)


def routing_active(vip):
    if not vip:
        return False
    if run("nft list table inet vpnexit")[0] != 0:
        return False
    if run("ip rule show | grep -q 'fwmark %s lookup %d'" % (cfg("mark"), cfg("table")))[0] != 0:
        return False
    return run("ip route show table %d | grep -q default" % cfg("table"))[0] == 0


# ------------------------------------------------------------------- connect

def wait_child(seconds):
    for _ in range(seconds):
        s = sas_parse()
        if s["child"] and s["vip"]:
            return s
        time.sleep(1)
    return sas_parse()


def teardown():
    routing_clear()
    run("swanctl --terminate --ike %s" % CONN, timeout=25)


def connect(key, index=0, verify=True):
    loc = find_location(key)
    if not loc:
        return {"ok": False, "error": "unknown location %s" % key}
    idx = index if 0 <= index < len(loc["servers"]) else 0
    state_patch(state="connecting", key=key, index=idx, error="", vip="",
                rx=0, tx=0, uptime=0, checked_at=int(time.time()))
    if cfg("share_lan"):
        pass
    routing_clear()
    order = [(idx + k) % len(loc["servers"]) for k in range(len(loc["servers"]))]
    used, srv, s = idx, loc["servers"][idx], None
    last = ""
    for ci, si in enumerate(order[:3]):
        cand = loc["servers"][si]
        if not cand.get("user") or not cand.get("pass"):
            continue
        if ci:
            log("connect: %s did not answer, trying %s" % (srv["host"], cand["host"]))
        srv = cand
        learn_chain(cand["host"])
        write_conn(cand)
        run("swanctl --load-creds", timeout=30)
        rc, out = run("swanctl --load-conns", timeout=30)
        if rc != 0:
            last = out
            continue
        teardown()
        rc, out = run("swanctl --initiate --child %s --timeout 15" % CHILD, timeout=40)
        s = wait_child(8)
        if s["child"] and s["vip"]:
            used = si
            break
        last = out
        run("swanctl --terminate --ike %s" % CONN, timeout=25)
    if not s or not s["child"] or not s["vip"]:
        log("connect: handshake failed: %s" % last.strip()[-300:])
        state_patch(state="error", vip="", exit_ip="", error="handshake failed",
                    checked_at=int(time.time()), server_host=srv["host"], index=used)
        return {"ok": False, "error": "handshake failed"}
    state_patch(vip=s["vip"], server_ip=s["remote"], server_host=srv["host"],
                index=used, since=int(time.time()), checked_at=int(time.time()), misses=0)
    routing = {"active": False}
    if cfg("share_lan"):
        rr = routing_apply(s["vip"])
        routing["active"] = rr["ok"]
        if not rr["ok"]:
            log("connect: routing failed: %s" % rr.get("error"))
    test = selftest() if verify else {"ok": False, "detail": "not tested"}
    state_patch(state="connected", exit_ip=test.get("ip", ""),
                error="" if test.get("ok") else test.get("detail", ""),
                attempts=0, checked_at=int(time.time()))
    log("connect: up, vip %s, exit %s" % (s["vip"], test.get("ip", "-")))
    return {"ok": True, "vip": s["vip"], "exit_ip": test.get("ip", "")}


def disconnect():
    log("disconnect")
    teardown()
    for p in (SWAN_CONF, SWAN_SECRETS):
        try:
            os.unlink(p)
        except OSError:
            pass
    state_patch(state="idle", vip="", exit_ip="", error="", checked_at=int(time.time()))
    return {"ok": True}


# ------------------------------------------------------------------ selftest

def probe_ip(marked):
    if marked:
        run("nft delete table inet vpnexit_probe")
        run("nft add table inet vpnexit_probe")
        run("nft add chain inet vpnexit_probe out '{ type route hook output priority mangle; policy accept; }'")
        run("nft add rule inet vpnexit_probe out ip daddr 1.1.1.1 meta mark set %s" % cfg("mark"))
    rc, out = run("curl -fsS --max-time 12 %s" % PROBE, timeout=20)
    if marked:
        run("nft delete table inet vpnexit_probe")
    m = re.search(r"ip=([0-9.]+)", out)
    return m.group(1) if m else ""


def selftest():
    st = state_read()
    vip = st.get("vip") or ""
    if not vip:
        return {"ok": False, "detail": "tunnel is down"}
    temporary = False
    if not routing_active(vip):
        rr = routing_apply(vip)
        if not rr["ok"]:
            return {"ok": False, "detail": rr.get("error", "routing failed")}
        temporary = True
    direct = probe_ip(False)
    marked = probe_ip(True)
    if temporary:
        routing_clear()
    if not marked:
        return {"ok": False, "detail": "no answer through the tunnel", "direct": direct}
    if direct and direct == marked:
        return {"ok": False, "detail": "traffic still uses the uplink", "direct": direct}
    return {"ok": True, "ip": marked, "direct": direct, "detail": "exit verified"}


# -------------------------------------------------------------------- status

def status():
    st = state_read()
    out = {
        "state": st.get("state", "idle"),
        "vip": st.get("vip", ""),
        "exit_ip": st.get("exit_ip", ""),
        "error": st.get("error", ""),
        "warning": "",
        "uptime": int(st.get("uptime", 0) or 0),
        "rx": int(st.get("rx", 0) or 0),
        "tx": int(st.get("tx", 0) or 0),
        "since": int(st.get("since", 0) or 0),
        "routing": {"active": routing_active(st.get("vip") or ""),
                    "share_lan": bool(cfg("share_lan"))},
    }
    loc = find_location(st["key"]) if st.get("key") else None
    if loc:
        out["location"] = {k: loc[k] for k in ("key", "title", "country", "flag", "premium")}
    if st.get("server_host"):
        out["server"] = {"host": st["server_host"], "index": int(st.get("index", 0) or 0)}
    if out["state"] == "connected" and not out["routing"]["active"] and out["routing"]["share_lan"]:
        out["warning"] = "routing rules are missing"
    if out["state"] == "connected" and not out["routing"]["share_lan"]:
        out["warning"] = "LAN sharing is disabled in settings"
    return out


def settings():
    data = cfg()
    data.pop("relay_pass", None)
    data["version"] = "1.0.0-portable"
    return data


# ------------------------------------------------------------------ watchdog

def worker_alive():
    pid_file = os.path.join(STATE_DIR, "worker.pid")
    try:
        with open(pid_file) as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def supervise_once():
    if worker_alive():
        return
    st = state_read()
    if st.get("state") == "error":
        if not cfg("auto_reconnect"):
            return
        if time.time() - int(st.get("checked_at", 0) or 0) < int(cfg("retry_seconds")):
            return
        log("watchdog: retrying after failure")
        connect(st.get("key", ""), int(st.get("index", 0) or 0), verify=False)
        return
    if st.get("state") not in ("connected", "connecting"):
        return
    s = sas_parse()
    if s["child"]:
        vip = s["vip"] or st.get("vip") or ""
        if cfg("share_lan") and vip and not routing_active(vip):
            rr = routing_apply(vip)
            if rr["ok"]:
                log("watchdog: routing rules restored")
        state_patch(state="connected", vip=vip, uptime=s["uptime"], rx=s["rx"],
                    tx=s["tx"], checked_at=int(time.time()), attempts=0)
        return
    misses = int(st.get("misses", 0) or 0) + 1
    if misses < 2:
        state_patch(misses=misses, checked_at=int(time.time()))
        return
    attempts = int(st.get("attempts", 0) or 0) + 1
    log("watchdog: tunnel lost (attempt %d)" % attempts)
    routing_clear()
    run("swanctl --terminate --ike %s" % CONN, timeout=25)
    if not cfg("auto_reconnect") or attempts > 5:
        state_patch(state="error", error="tunnel lost", attempts=attempts,
                    checked_at=int(time.time()), vip="", rx=0, tx=0)
        return
    state_patch(state="connecting", attempts=attempts, misses=0, checked_at=int(time.time()))
    r = connect(st.get("key", ""), int(st.get("index", 0) or 0), verify=False)
    if not r.get("ok"):
        state_patch(state="error", error=r.get("error", "reconnect failed"),
                    attempts=attempts, checked_at=int(time.time()))


def supervise():
    ensure_dirs()
    if state_read().get("state") == "connecting":
        state_patch(state="idle")
    log("supervisor started")
    last_check = 0
    while True:
        hours = int(cfg("refresh_hours") or 0)
        if hours > 0 and time.time() - last_check > 600:
            last_check = time.time()
            if time.time() - int(locations().get("fetched_at", 0) or 0) > hours * 3600:
                refresh()
        try:
            supervise_once()
        except Exception as exc:  # noqa: BLE001
            log("watchdog error: %s" % exc)
        time.sleep(int(cfg("watchdog_seconds") or 20))


# ---------------------------------------------------------------------- HTTP

def serve(host="0.0.0.0", port=8088):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    web = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "vpnexit"

        def log_message(self, *args):  # keep the journal quiet
            return

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _token(self, query):
            tok = self.headers.get("X-Auth-Token") or ""
            if not tok:
                cookie = self.headers.get("Cookie") or ""
                m = re.search(r"vpnexit=([^;]+)", cookie)
                if m:
                    tok = urllib.parse.unquote(m.group(1))
            if not tok:
                tok = query.get("t", [""])[0]
            return tok

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return {}

        def do_GET(self):
            self.handle_any("GET")

        def do_POST(self):
            self.handle_any("POST")

        def handle_any(self, method):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            if path in ("/", "/index.html"):
                path = "/web/index.html"
            if not path.startswith("/api/") and not path.startswith("/web/"):
                self.send_error(404)
                return
            if path == "/api/health":
                self._json({"ok": True, "service": "vpnexit", "version": "1.0.0-portable",
                            "state": state_read().get("state")})
                return
            token = self._token(query)
            if not cfg("token") or token != cfg("token"):
                self._json({"ok": False, "error": "unauthorized"}, 401)
                return
            endpoint = path[len("/api/"):] if path.startswith("/api/") else ""
            if endpoint == "status":
                self._json({"ok": True, "status": status()})
            elif endpoint == "locations":
                if query.get("refresh") == ["1"]:
                    refresh()
                data = locations()
                self._json({"ok": True, "items": data.get("items", []),
                            "count": data.get("count", 0),
                            "fetched_at": data.get("fetched_at", 0)})
            elif endpoint == "refresh":
                self._json(refresh())
            elif endpoint == "settings":
                if method == "GET":
                    self._json({"ok": True, "settings": settings()})
                else:
                    body = self._body()
                    patch = {}
                    for key in ("share_lan", "block_ipv6", "auto_reconnect", "relay_enabled"):
                        if key in body:
                            patch[key] = bool(body[key])
                    if "tunnel_mtu" in body:
                        patch["tunnel_mtu"] = max(1200, min(1420, int(body["tunnel_mtu"])))
                    if body.get("feed_url"):
                        patch["feed_url"] = body["feed_url"].strip()
                    if body.get("token") and len(body["token"].strip()) >= 8:
                        patch["token"] = body["token"].strip()
                    cfg_set(**patch)
                    st = state_read()
                    if st.get("state") == "connected" and st.get("vip"):
                        if cfg("share_lan"):
                            routing_apply(st["vip"])
                        else:
                            routing_clear()
                    self._json({"ok": True, "settings": settings()})
            elif endpoint == "connect" and method == "POST":
                body = self._body()
                key = (body.get("key") or "").strip()
                if not key or not find_location(key):
                    self._json({"ok": False, "error": "unknown location"})
                    return
                if worker_alive():
                    self._json({"ok": False, "error": "busy: a connection attempt is running"})
                    return
                idx = int(body.get("index") or 0)
                state_patch(state="connecting", key=key, index=idx, error="",
                            vip="", rx=0, tx=0, uptime=0, checked_at=int(time.time()))

                def job():
                    try:
                        connect(key, idx, verify=True)
                    except Exception as exc:  # noqa: BLE001
                        log("worker error: %s" % exc)
                        state_patch(state="error", error=str(exc), checked_at=int(time.time()))

                threading.Thread(target=job, daemon=True).start()
                self._json({"ok": True, "async": True, "state": "connecting"})
            elif endpoint == "disconnect" and method == "POST":
                self._json(disconnect())
            elif endpoint == "selftest" and method == "POST":
                r = selftest()
                if r.get("ok"):
                    state_patch(exit_ip=r.get("ip", ""), checked_at=int(time.time()))
                self._json({"ok": r.get("ok", False), "result": r})
            elif endpoint == "log":
                n = int(query.get("lines", ["120"])[0])
                rc, out = run("tail -n %d %s" % (n, shlex.quote(LOG)), timeout=10)
                self._json({"ok": True, "text": out})
            else:
                self._json({"ok": False, "error": "unknown endpoint"}, 404)

    with lock:
        srv = ThreadingHTTPServer((host, port), Handler)
        srv.serve_forever()


# ---------------------------------------------------------------------- main

def main(argv):
    ensure_dirs()
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "serve":
        serve(port=int(argv[2]) if len(argv) > 2 else 8088)
    elif cmd == "supervise":
        supervise()
    elif cmd == "refresh":
        print(json.dumps(refresh()))
    elif cmd == "locations":
        print(json.dumps(locations()))
    elif cmd == "connect":
        print(json.dumps(connect(argv[2], int(argv[3]) if len(argv) > 3 else 0)))
    elif cmd == "disconnect":
        print(json.dumps(disconnect()))
    elif cmd == "selftest":
        print(json.dumps(selftest()))
    elif cmd == "relay-test":
        out = os.path.join(STATE_DIR, "relay.json")
        rc, note = fetch_via_relay(cfg("feed_url"), out)
        print(json.dumps({"rc": rc, "note": note,
                          "bytes": os.path.getsize(out) if os.path.exists(out) else 0}))
    elif cmd == "status":
        print(json.dumps(status()))
    elif cmd == "token":
        print(cfg("token"))
    else:
        print("usage: vpnexit.py {serve|supervise|refresh|locations|connect|disconnect|selftest|status|relay-test}")


if __name__ == "__main__":
    import sys
    main(sys.argv)
