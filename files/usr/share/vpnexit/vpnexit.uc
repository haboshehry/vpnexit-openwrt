#!/usr/bin/ucode
// vpnexit - multi-protocol VPN exit controller for OpenWrt.
//
// One panel, one routing engine.  Any configured tunnel - feed IKEv2, manual
// IKEv2, L2TP/IPsec, SSTP, OpenVPN, WireGuard, AmneziaWG or VLESS/REALITY -
// is brought up by its own driver and then shared with the LAN through the
// same nftables mark + policy route.  The system default route is never
// modified, so the router keeps its own uplink and stays reachable.

const fs = require("fs");
const uci = require("uci");

const DATA = "/etc/vpnexit";
const RUN = "/var/run/vpnexit";
const LOGFILE = RUN + "/log";
const STATE = RUN + "/state.json";
const LOCS = DATA + "/locations.json";
const CHAINS = DATA + "/chains";
const CONNFILE = DATA + "/connections.json";
const RUNDIR = DATA + "/run";
const SWANCTL_CONF = "/etc/swanctl/conf.d/vpnexit.conf";
const SWANCTL_SECRETS = "/etc/swanctl/conf.d/vpnexit-secrets.conf";
const CONN = "vpnexit";
const CHILD = "vpnexit";
const PROBE = "https://1.1.1.1/cdn-cgi/trace";

const WGIFACE = "vpnwg0";
const OVPNIFACE = "ovpnx0";
const VLESSIFACE = "vpnvl0";

// ------------------------------------------------------------------ utilities

function now() { return time(); }

function shellq(s) {
	s = "" + (s ?? "");
	return "'" + replace(s, /'/g, "'\\''") + "'";
}

// Run a shell command, return { rc, out }. popen() gives us both the exit
// status and the output, without a temporary file per call.
function run(cmd) {
	let p = fs.popen(cmd + " 2>&1");
	if (!p) return { rc: 127, out: "" };
	let out = p.read("all") ?? "";
	let rc = p.close();
	return { rc: rc, out: out };
}

function readfile(path) { return fs.readfile(path) ?? ""; }

function hexval(ch) {
	let i = index("0123456789abcdef", lc(ch));
	return i < 0 ? -1 : i;
}

function urldecode(s) {
	s = "" + (s ?? "");
	if (index(s, "%") < 0 && index(s, "+") < 0) return s;
	let out = "";
	for (let i = 0; i < length(s); i++) {
		let ch = substr(s, i, 1);
		if (ch == "+") { out += " "; continue; }
		if (ch == "%" && i + 2 < length(s)) {
			let hi = hexval(substr(s, i + 1, 1)), lo = hexval(substr(s, i + 2, 1));
			if (hi >= 0 && lo >= 0) { out += chr(hi * 16 + lo); i += 2; continue; }
		}
		out += ch;
	}
	return out;
}

function urlencode(s) {
	s = "" + (s ?? "");
	let out = "";
	for (let i = 0; i < length(s); i++) {
		let ch = substr(s, i, 1);
		if (match(ch, /[A-Za-z0-9._~-]/)) { out += ch; continue; }
		out += sprintf("%%%02X", ord(ch));
	}
	return out;
}

function writefile(path, data, mode) {
	fs.writefile(path, data);
	if (mode) run("chmod " + mode + " " + shellq(path));
}

function ensure_dir(path) {
	if (!fs.stat(path)) run("mkdir -p " + shellq(path));
}

function log(msg) {
	ensure_dir(RUN);
	let cur = readfile(LOGFILE);
	if (length(cur) > 65536) cur = substr(cur, length(cur) - 32768);
	fs.writefile(LOGFILE, cur + sprintf("%d %s\n", now(), msg));
}

function clean(text) {
	let keep = [];
	for (let line in split(text ?? "", "\n")) {
		if (index(line, "failed to load - ") >= 0) continue;
		if (index(line, "requires cap_setuid") >= 0) continue;
		if (length(trim(line)) == 0) continue;
		push(keep, rtrim(line));
	}
	return join("\n", keep);
}

function intval(v, def) {
	if (v == null) return def;
	let n = +(v);
	if (n != n) return def;
	return int(n);
}

function boolval(v, def) {
	if (v == null) return def;
	if (type(v) == "boolean") return v;
	let s = lc("" + v);
	return (s == "1" || s == "true" || s == "yes" || s == "on");
}

function first_word(v) {
	let p = split(trim("" + (v ?? "")), " ");
	return p[0] ?? "";
}

function has_bin(path) { return fs.stat(path) != null; }

// ------------------------------------------------------------------- config

let _cursor = null;
function cursor() {
	if (!_cursor) _cursor = uci.cursor();
	return _cursor;
}

function cfg(key, def) {
	let v = cursor().get("vpnexit", "main", key);
	if (v == null || v == "") return def;
	return v;
}

function cfg_int(key, def) { return intval(cfg(key, def), def); }
function cfg_bool(key, def) { return boolval(cfg(key, def), def); }

function cfg_set(key, value) {
	cursor().set("vpnexit", "main", key, "" + value);
	cursor().commit("vpnexit");
}

function settings_obj() {
	return {
		share_lan: cfg_bool("share_lan", true),
		block_ipv6: cfg_bool("block_ipv6", true),
		auto_reconnect: cfg_bool("auto_reconnect", true),
		reconnect_attempts: cfg_int("reconnect_attempts", 5),
		tunnel_mtu: cfg_int("tunnel_mtu", 1400),
		refresh_hours: cfg_int("refresh_hours", 24),
		feed_url: cfg("feed_url", ""),
		token: cfg("token", ""),
		lan_iface: cfg("lan_iface", ""),
		watchdog_seconds: cfg_int("watchdog_seconds", 20),
		version: trim(readfile("/usr/share/vpnexit/VERSION"))
	};
}

// -------------------------------------------------------------------- state

function state_read() {
	let raw = readfile(STATE);
	if (!length(raw)) return { state: "idle" };
	try {
		let s = json(raw);
		if (type(s) == "object" && s != null) return s;
	} catch (e) { }
	return { state: "idle" };
}

function state_write(st) {
	ensure_dir(RUN);
	fs.writefile(STATE, sprintf("%J", st));
}

function state_patch(patch) {
	let st = state_read();
	for (let k in patch) st[k] = patch[k];
	state_write(st);
	return st;
}

// ------------------------------------------------------------- system facts

function default_route() {
	let r = run("ip -4 route show default");
	let line = split(trim(r.out), "\n")[0] ?? "";
	let gw = null, dev = null;
	let m = match(line, /via\s+([0-9.]+)/);
	if (m) gw = m[1];
	m = match(line, /dev\s+(\S+)/);
	if (m) dev = m[1];
	return { gw: gw, dev: dev };
}

function iface_cidr(dev) {
	if (!length(dev)) return "";
	let r = run("ip -4 -o addr show dev " + shellq(dev));
	let m = match(r.out, /inet\s+([0-9.]+\/[0-9]+)/);
	return m ? m[1] : "";
}

function iface_exists(dev) {
	if (!length(dev)) return false;
	return fs.stat("/sys/class/net/" + dev) != null;
}

function net_list() {
	let out = [];
	let r = run("ls /sys/class/net");
	for (let n in split(trim(r.out), "\n")) if (length(trim(n))) push(out, trim(n));
	return out;
}

function ppp_ifaces() {
	let out = [];
	for (let n in net_list()) if (index(n, "ppp") == 0) push(out, n);
	return out;
}

function new_iface_since(before) {
	for (let n in ppp_ifaces()) {
		let seen = false;
		for (let b in before) if (b == n) seen = true;
		if (!seen) return n;
	}
	return "";
}

function iface_v4(dev) {
	if (!length(dev)) return "";
	let r = run("ip -4 -o addr show dev " + shellq(dev));
	// Point-to-point devices (tun, ppp) print "inet 10.8.0.6 peer 10.8.0.5/32":
	// the prefix belongs to the peer, so the address must be matched on its own.
	let m = match(r.out, /inet\s+([0-9.]+)(\/|\s)/);
	return m ? m[1] : "";
}

function iface_bytes(dev) {
	if (!length(dev)) return { rx: 0, tx: 0 };
	let rx = intval(trim(readfile("/sys/class/net/" + dev + "/statistics/rx_bytes")), 0);
	let tx = intval(trim(readfile("/sys/class/net/" + dev + "/statistics/tx_bytes")), 0);
	return { rx: rx, tx: tx };
}

function lan_iface() {
	let v = cfg("lan_iface", "");
	if (length(v)) return first_word(v);
	let c = cursor().get("network", "lan", "device") ?? cursor().get("network", "lan", "ifname");
	if (c != null && length("" + c)) return first_word(c);
	if (fs.stat("/sys/class/net/br-lan")) return "br-lan";
	return "lan";
}

function mask4(cidr) {
	let p = split(cidr ?? "", "/");
	if (length(p) != 2) return null;
	let bits = intval(p[1], -1);
	if (bits < 0 || bits > 32) return null;
	let parts = split(p[0], ".");
	if (length(parts) != 4) return null;
	let n = intval(parts[0], 0) * 16777216 + intval(parts[1], 0) * 65536
		+ intval(parts[2], 0) * 256 + intval(parts[3], 0);
	// ucode has no unsigned shift operators, so the network address is derived
	// with plain arithmetic (n - n % block_size).
	let size = 1;
	for (let i = bits; i < 32; i++) size = size * 2;
	let host = n - (n % size);
	let a = int(host / 16777216); host -= a * 16777216;
	let b = int(host / 65536); host -= b * 65536;
	let c = int(host / 256); host -= c * 256;
	return sprintf("%d.%d.%d.%d/%d", a, b, c, host, bits);
}

function resolve4(host) {
	if (match(host ?? "", /^[0-9.]+$/)) return host;
	let r = run("nslookup " + shellq(host));
	let out = [];
	for (let line in split(r.out, "\n")) {
		let m = match(line, /Address:\s*([0-9.]+)/);
		if (!m) continue;
		if (index(out, m[1]) < 0) push(out, m[1]);
		if (length(out) >= 4) break;
	}
	return length(out) ? out[0] : "";
}

// ---------------------------------------------------------------- swanctl io

function sas_parse() {
	let r = run("swanctl --list-sas");
	let text = clean(r.out);
	let st = { ike: false, child: false, vip: "", remote: "", rx: 0, tx: 0, uptime: 0, raw: text };
	for (let line in split(text, "\n")) {
		if (match(line, /^vpnexit: #[0-9]+, ESTABLISHED/)) { st.ike = true; continue; }
		if (index(line, "INSTALLED") >= 0 && index(line, "reqid") >= 0) { st.child = true; continue; }
		let m = match(line, /local\s+'[^']*'\s+@\s+[0-9.]+\[[0-9]+\](\s+\[([0-9.]+)\])?/);
		if (m && !length(st.vip) && m[2]) { st.vip = m[2]; continue; }
		m = match(line, /remote\s+'[^']*'\s+@\s+([0-9.]+)\[/);
		if (m) { st.remote = m[1]; continue; }
		m = match(line, /^\s+in\s+\S+,\s+([0-9]+)\s+bytes,\s+([0-9]+)\s+packets/);
		if (m) { st.rx = intval(m[1], 0); continue; }
		m = match(line, /^\s+out\s+\S+,\s+([0-9]+)\s+bytes,\s+([0-9]+)\s+packets/);
		if (m) { st.tx = intval(m[1], 0); continue; }
		m = match(line, /established\s+([0-9]+)s ago/);
		if (m && st.uptime == 0) st.uptime = intval(m[1], 0);
	}
	return st;
}

// ------------------------------------------------------------ profile store

// ucode's chr() only produces single bytes, so code points above 0x7f are
// encoded by hand.
function u8(cp) {
	if (cp < 128) return chr(cp);
	if (cp < 2048) return chr(192 + int(cp / 64)) + chr(128 + cp % 64);
	if (cp < 65536) return chr(224 + int(cp / 4096)) + chr(128 + int((cp % 4096) / 64)) + chr(128 + cp % 64);
	return chr(240 + int(cp / 262144)) + chr(128 + int((cp % 262144) / 4096))
		+ chr(128 + int((cp % 4096) / 64)) + chr(128 + cp % 64);
}

function flag_emoji(cc) {
	cc = uc(cc ?? "");
	if (length(cc) != 2 || match(cc, /[^A-Z]/)) return u8(0x1F310);
	return u8(0x1F1E6 + (ord(substr(cc, 0, 1)) - 65)) + u8(0x1F1E6 + (ord(substr(cc, 1, 1)) - 65));
}

const COUNTRY = {
	hongkong: "HK", honghonk: "HK", hk: "HK", netherlands: "NL", holland: "NL", nl: "NL",
	usa: "US", unitedstates: "US", us: "US", america: "US", argentina: "AR", australia: "AU",
	belarus: "BY", brazil: "BR", canada: "CA", finland: "FI", france: "FR", germany: "DE",
	deutschland: "DE", india: "IN", indonesia: "ID", iraq: "IQ", israel: "IL", japan: "JP",
	kazahstan: "KZ", kazakhstan: "KZ", ksa: "SA", saudiarabia: "SA", saudi: "SA", malaysia: "MY",
	mexico: "MX", russia: "RU", singapore: "SG", southafrica: "ZA", spain: "ES",
	switzerland: "CH", turkiye: "TR", turkey: "TR", uae: "AE", emirates: "AE",
	unitedkingdom: "GB", uk: "GB", britain: "GB", england: "GB", ukraine: "UA",
	albania: "AL", austria: "AT", belgium: "BE", bulgaria: "BG", croatia: "HR", cyprus: "CY",
	czechia: "CZ", czech: "CZ", denmark: "DK", estonia: "EE", greece: "GR", hungary: "HU",
	iceland: "IS", ireland: "IE", italy: "IT", latvia: "LV", lithuania: "LT", luxembourg: "LU",
	malta: "MT", moldova: "MD", montenegro: "ME", norway: "NO", poland: "PL", portugal: "PT",
	romania: "RO", serbia: "RS", slovakia: "SK", slovenia: "SI", sweden: "SE", armenia: "AM",
	azerbaijan: "AZ", georgia: "GE", china: "CN", taiwan: "TW", southkorea: "KR", korea: "KR",
	thailand: "TH", vietnam: "VN", philippines: "PH", pakistan: "PK", bangladesh: "BD",
	srilanka: "LK", nepal: "NP", mongolia: "MN", newzealand: "NZ", chile: "CL", colombia: "CO",
	peru: "PE", venezuela: "VE", ecuador: "EC", bolivia: "BO", paraguay: "PY", uruguay: "UY",
	costarica: "CR", panama: "PA", guatemala: "GT", cuba: "CU", jamaica: "JM", egypt: "EG",
	morocco: "MA", algeria: "DZ", tunisia: "TN", libya: "LY", sudan: "SD", nigeria: "NG",
	ghana: "GH", kenya: "KE", ethiopia: "ET", tanzania: "TZ", uganda: "UG", zimbabwe: "ZW",
	zambia: "ZM", mozambique: "MZ", angola: "AO", cameroon: "CM", senegal: "SN", somalia: "SO",
	madagascar: "MG", mauritius: "MU", lebanon: "LB", jordan: "JO", kuwait: "KW", qatar: "QA",
	bahrain: "BH", oman: "OM", yemen: "YE", syria: "SY", afghanistan: "AF", uzbekistan: "UZ",
	kyrgyzstan: "KG", tajikistan: "TJ", turkmenistan: "TM"
};

function country_from_key(key) {
	let parts = [];
	for (let p in split(lc(key ?? ""), "-")) if (length(p)) push(parts, p);
	let prefixes = ["free", "premium", "trial", "vip", "basic"];
	while (length(parts) && index(prefixes, parts[0]) >= 0) shift(parts);
	if (!length(parts)) return "";
	for (let start = 0; start < length(parts); start++) {
		let cand = "";
		for (let i = start; i < length(parts); i++) cand += parts[i];
		if (COUNTRY[cand]) return COUNTRY[cand];
	}
	return COUNTRY[parts[length(parts) - 1]] ?? "";
}

function ucfirst(s) {
	s = "" + s;
	if (!length(s)) return s;
	return uc(substr(s, 0, 1)) + substr(s, 1);
}

function normalise_location(key, raw) {
	if (type(raw) != "object" || raw == null) return null;
	if (!boolval(raw.published, true)) return null;
	if (type(raw.ikev2) != "array") return null;
	let servers = [];
	for (let i = 0; i < length(raw.ikev2); i++) {
		let e = raw.ikev2[i];
		if (type(e) != "object" || e == null) continue;
		if (!boolval(e.published, true)) continue;
		let host = trim("" + (e.server ?? ""));
		let ip = trim("" + (e.ip ?? ""));
		if (!length(host) && !length(ip)) continue;
		push(servers, {
			host: length(host) ? host : ip,
			ip: ip,
			user: trim("" + (e.username ?? "")),
			pass: "" + (e.password ?? ""),
			local_id: trim("" + (e.local_id ?? e.username ?? ""))
		});
	}
	if (!length(servers)) return null;
	let cc = country_from_key(key);
	if (!length(cc)) {
		let f = uc(trim("" + (raw.country ?? "")));
		if (length(f) == 3) f = substr(f, 0, 2);
		if (length(f) == 2 && !match(f, /[^A-Z]/)) cc = f;
	}
	let title = trim("" + (raw.title_en ?? ""));
	if (!length(title)) title = ucfirst(replace(key, /[-_]/g, " "));
	return {
		key: key,
		title: title,
		country: cc,
		flag: flag_emoji(cc),
		premium: boolval(raw.premium, false),
		position: intval(raw.position, 999),
		servers: servers
	};
}

function locations_load() {
	let raw = readfile(LOCS);
	if (length(raw)) {
		try {
			let d = json(raw);
			if (type(d) == "object" && d != null && type(d.items) == "array") return d;
		} catch (e) { }
	}
	return { items: [], fetched_at: 0, count: 0 };
}

function locations_save(items) {
	ensure_dir(DATA);
	let obj = { items: items, count: length(items), fetched_at: now() };
	fs.writefile(LOCS, sprintf("%J", obj));
	return obj;
}

function find_location(key) {
	for (let it in locations_load().items) if (it.key == key) return it;
	return null;
}

// -------------------------------------------------------------- feed access

function url_host(url) {
	let m = match(url ?? "", /^https?:\/\/([^\/:]+)/);
	return m ? m[1] : "";
}

// Some ISPs answer a TLS reset for the feed host. When the tunnel is up the same
// request succeeds through it, so the marked path is used as a fallback.
function fetch_via_tunnel(url, outfile) {
	let host = url_host(url);
	if (!length(host)) return { rc: -1, out: "bad url" };
	let ips = resolve4(host);
	if (!length(ips)) return { rc: -1, out: "cannot resolve " + host };
	let mark = cfg("mark", "0x1a1");
	run("nft delete table inet vxprobe");
	run("nft add table inet vxprobe");
	run("nft add chain inet vxprobe out '{ type route hook output priority mangle; policy accept; }'");
	run(sprintf("nft add rule inet vxprobe out ip daddr %s meta mark set %s", ips, mark));
	let r = run(sprintf("uclient-fetch -q -O %s --timeout=30 %s", shellq(outfile), shellq(url)));
	run("nft delete table inet vxprobe");
	log(sprintf("refresh: tried %s through the tunnel, rc=%d", ips, r.rc));
	return r;
}

// Last resort: fetch the feed on a remote host that is reachable from the
// router but not behind the same ISP filtering, then pull the body over SSH.
// relay_list is "user@host:port,user@host:port"; relay_pass is used by sshpass.
function relay_fetch(url, outfile) {
	let pass = cfg("relay_pass", "");
	let list = cfg("relay_list", "");
	if (!length(pass) || !length(list)) return { rc: -1, out: "no relay configured" };
	for (let item in split(list, ",")) {
		item = trim(item);
		if (!length(item)) continue;
		// Parsed by hand: ucode's regex engine has no non-capturing groups.
		let user = "root", host = item, port = 22;
		let at = index(host, "@");
		if (at > 0) { user = substr(host, 0, at); host = substr(host, at + 1); }
		let colon = rindex(host, ":");
		if (colon > 0) { port = intval(substr(host, colon + 1), 22); host = substr(host, 0, colon); }
		if (!length(host)) continue;
		log(sprintf("refresh: trying relay %s:%d", host, port));
		let remote = sprintf("curl -fsS --max-time 30 %s", shellq(url));
		let inner = sprintf(
			"sshpass -p %s ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s > %s",
			shellq(pass), port, shellq(user), shellq(host), shellq(remote), shellq(outfile));
		let r = run("sh -c " + shellq(inner));
		if (r.rc != 0) continue;
		let body = readfile(outfile);
		if (length(body) < 200) continue;
		try {
			let d = json(body);
			if (type(d) == "object" && d != null) {
				log(sprintf("refresh: fetched through relay %s (%d bytes)", host, length(body)));
				return { rc: 0, out: "relay " + host };
			}
		} catch (e) { }
	}
	return { rc: -1, out: "all relays failed" };
}

function refresh() {
	let url = cfg("feed_url", "");
	if (!length(url)) return { ok: false, error: "no feed url configured" };
	ensure_dir(RUN);
	let tmp = RUN + "/feed.json";
	let r = run(sprintf("uclient-fetch -q -O %s --timeout=25 %s", shellq(tmp), shellq(url)));
	if (r.rc != 0 && state_read().state == "connected") {
		log(sprintf("refresh: direct fetch failed (%d), retrying through the tunnel", r.rc));
		r = fetch_via_tunnel(url, tmp);
	}
	if (r.rc != 0) {
		log("refresh: tunnel path failed, trying the relay servers");
		r = relay_fetch(url, tmp);
	}
	if (r.rc != 0) {
		log(sprintf("refresh: fetch failed (%d) %s", r.rc, trim(r.out)));
		return { ok: false, error: "feed download failed: " + trim(r.out) };
	}
	let body = readfile(tmp);
	fs.unlink(tmp);
	let doc;
	try { doc = json(body); } catch (e) { return { ok: false, error: "feed is not valid JSON" }; }
	if (type(doc) != "object" || doc == null) return { ok: false, error: "feed root is not an object" };

	let items = [], skipped = 0;
	for (let key in doc) {
		let loc = normalise_location(key, doc[key]);
		if (loc == null) { skipped++; continue; }
		push(items, loc);
	}
	if (!length(items)) return { ok: false, error: "feed contained no usable profiles" };
	sort(items, function (a, b) {
		if (a.premium != b.premium) return a.premium ? 1 : -1;
		if (a.position != b.position) return a.position - b.position;
		return (a.key < b.key) ? -1 : 1;
	});
	let saved = locations_save(items);
	log(sprintf("refresh: %d locations, %d skipped", length(items), skipped));
	return { ok: true, count: length(items), skipped: skipped, fetched_at: saved.fetched_at };
}

// ------------------------------------------------------------ trust anchors

function safe_name(host) {
	return replace(host, /[^A-Za-z0-9.-]/g, "_");
}

// strongSwan validates the peer against the CA store, but these peers only send
// their leaf certificate inside IKE_AUTH. The chain is therefore learned over
// TLS from the same host, the leaf name is verified, and the issuers are stored
// as individual files under x509ca (the pem plugin reads one cert per file).
function learn_chain(host) {
	if (!length(host)) return false;
	ensure_dir(CHAINS);
	let cache = sprintf("%s/%s.pem", CHAINS, safe_name(host));
	let st = fs.stat(cache);
	if (st && (now() - st.mtime) < 604800 && st.size > 0) return true;

	let r = run(sprintf("openssl s_client -showcerts -servername %s -connect %s </dev/null 2>/dev/null",
		shellq(host), shellq(host + ":443")));
	if (r.rc != 0 || !length(r.out)) {
		log("trust: no TLS chain for " + host);
		return false;
	}
	let blocks = [];
	for (let part in split(r.out, "-----END CERTIFICATE-----")) {
		let s = index(part, "-----BEGIN CERTIFICATE-----");
		if (s >= 0) push(blocks, substr(part, s) + "-----END CERTIFICATE-----\n");
	}
	if (!length(blocks)) return false;

	// The first block is the leaf: verify it actually belongs to this host
	// before trusting anything that arrived on the wire.
	let leaf = RUN + "/leaf.pem";
	fs.writefile(leaf, blocks[0]);
	let v = run(sprintf("openssl x509 -in %s -noout -checkhost %s", shellq(leaf), shellq(host)));
	if (v.rc != 0) {
		log("trust: certificate does not match " + host);
		fs.unlink(leaf);
		return false;
	}
	fs.writefile(cache, join("", blocks));

	let prefix = sprintf("/etc/swanctl/x509ca/vpnx-%s", safe_name(host));
	for (let i = 1; i < length(blocks); i++) {
		fs.writefile(sprintf("%s-%02d.pem", prefix, i), blocks[i]);
	}
	run("chmod 0644 /etc/swanctl/x509ca/vpnx-*.pem 2>/dev/null");
	log(sprintf("trust: learned %d issuer(s) for %s", length(blocks) - 1, host));
	return true;
}

// ---------------------------------------------------------- swanctl config

const IKE_PROPOSALS = "aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024";
// AES-CBC is listed first on purpose: AES-GCM installs a second SAD entry with
// an AEAD attribute that some vendor kernels handle badly.
const ESP_PROPOSALS = "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1";

function swan_quote(v) { return "\"" + replace("" + (v ?? ""), /["\\]/g, function (m) { return "\\" + m; }) + "\""; }

// IKEv2, either EAP-MSCHAPv2 with a server certificate or a pre-shared key.
function conn_text_ikev2(srv) {
	let addr = length(srv.ip) ? srv.ip : srv.host;
	let remote_id = length(srv.remote_id) ? srv.remote_id : srv.host;
	let local_id = length(srv.local_id) ? srv.local_id : srv.user;
	let psk = length(srv.psk ?? "") > 0;
	let lines = [
		"# Managed by vpnexit - regenerated on every switch.",
		"connections {",
		"  " + CONN + " {",
		"    version = 2",
		"    local_addrs = %any",
		"    remote_addrs = " + addr,
		"    proposals = " + IKE_PROPOSALS,
		"    local {",
		psk ? "      auth = psk" : "      auth = eap-mschapv2",
		"      id = " + swan_quote(local_id),
		psk ? "" : "      eap_id = " + swan_quote(srv.user),
		"    }",
		"    remote {",
		psk ? "      auth = psk" : "      auth = pubkey",
		"      id = " + swan_quote(remote_id),
		"    }",
		"    vips = 0.0.0.0",
		"    dpd_delay = 30s",
		"    dpd_timeout = 120s",
		"    children {",
		"      " + CHILD + " {",
		"        local_ts = 0.0.0.0/0",
		"        remote_ts = 0.0.0.0/0",
		"        esp_proposals = " + ESP_PROPOSALS,
		"        start_action = none",
		"        dpd_action = restart",
		"        close_action = none",
		"      }",
		"    }",
		"  }",
		"}",
		""
	];
	let out = [];
	for (let l in lines) if (length(l)) push(out, l);
	return join("\n", out);
}

// L2TP over IPsec: IKEv1 in transport mode, UDP/1701 only. xl2tpd then runs
// PPP inside the transport SA and produces a pppN interface.
function conn_text_l2tp(srv) {
	let addr = length(srv.ip) ? srv.ip : srv.host;
	let lines = [
		"# Managed by vpnexit - L2TP/IPsec transport (regenerated on every switch).",
		"connections {",
		"  " + CONN + " {",
		"    version = 1",
		"    local_addrs = %any",
		"    remote_addrs = " + addr,
		"    proposals = aes256-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024",
		"    local {",
		"      auth = psk",
		"      id = %any",
		"    }",
		"    remote {",
		"      auth = psk",
		"      id = %any",
		"    }",
		"    children {",
		"      " + CHILD + " {",
		"        mode = transport",
		"        local_ts = dynamic[udp/1701]",
		"        remote_ts = dynamic[udp/1701]",
		"        esp_proposals = aes256-sha1,aes128-sha1,3des-sha1",
		"        start_action = trap",
		"        dpd_action = restart",
		"        close_action = none",
		"      }",
		"    }",
		"  }",
		"}",
		""
	];
	return join("\n", lines);
}

function secrets_text(srv) {
	let psk = srv.psk ?? "";
	let lines = ["secrets {"];
	if (length(psk)) {
		push(lines, "  ike-" + CONN + " {");
		push(lines, "    id = " + swan_quote(length(srv.remote_id) ? srv.remote_id : (srv.host ?? "")));
		push(lines, "    secret = " + swan_quote(psk));
		if (length(srv.host) && srv.remote_id && srv.remote_id != srv.host) {
			push(lines, "  }");
			push(lines, "  ike-" + CONN + "2 {");
			push(lines, "    id = " + swan_quote(srv.host));
			push(lines, "    secret = " + swan_quote(psk));
		}
		push(lines, "  }");
	} else {
		let esc = replace("" + (srv.pass ?? ""), /[\\"]/g, function (m) { return "\\" + m; });
		push(lines, "  eap-" + CONN + " {");
		push(lines, "    id = " + swan_quote(length(srv.local_id) ? srv.local_id : srv.user));
		push(lines, "    secret = \"" + esc + "\"");
		if (length(srv.local_id) && srv.local_id != srv.user) {
			push(lines, "  }");
			push(lines, "  eap-" + CONN + "2 {");
			push(lines, "    id = " + swan_quote(srv.user));
			push(lines, "    secret = \"" + esc + "\"");
		}
		push(lines, "  }");
	}
	push(lines, "}");
	return join("\n", lines) + "\n";
}

function write_conn(srv) {
	ensure_dir("/etc/swanctl/conf.d");
	writefile(SWANCTL_CONF, srv.l2tp ? conn_text_l2tp(srv) : conn_text_ikev2(srv), "0644");
	writefile(SWANCTL_SECRETS, secrets_text(srv), "0600");
}

function clear_conn_files() {
	if (fs.stat(SWANCTL_CONF)) fs.unlink(SWANCTL_CONF);
	if (fs.stat(SWANCTL_SECRETS)) fs.unlink(SWANCTL_SECRETS);
}

// -------------------------------------------------------- connection store

const TYPES = ["ikev2", "l2tp", "sstp", "openvpn", "wireguard", "amneziawg", "vless"];

function type_label(t) {
	let m = {
		ikev2: "IKEv2", l2tp: "L2TP/IPsec", sstp: "SSTP", openvpn: "OpenVPN",
		wireguard: "WireGuard", amneziawg: "AmneziaWG", vless: "VLESS / REALITY"
	};
	return m[t] ?? t;
}

// Which client binaries are present.  The panel turns the false entries into
// one-click installs instead of letting a connect fail with "not found".
function caps() {
	return {
		ikev2: has_bin("/usr/sbin/swanctl") && has_bin("/usr/sbin/charon") || has_bin("/usr/sbin/swanctl"),
		l2tp: has_bin("/usr/sbin/xl2tpd") && has_bin("/usr/sbin/swanctl") && has_bin("/usr/sbin/pppd"),
		sstp: has_bin("/usr/bin/sstpc") && has_bin("/usr/sbin/pppd"),
		openvpn: has_bin("/usr/sbin/openvpn"),
		wireguard: has_bin("/usr/bin/wg"),
		amneziawg: has_bin("/usr/bin/awg") || has_bin("/usr/bin/wg"),
		vless: has_bin("/usr/bin/xray")
	};
}

const PKG_FOR_TYPE = {
	ikev2: "strongswan-charon strongswan-swanctl strongswan-mod-eap-mschapv2 strongswan-mod-pem strongswan-mod-openssl",
	l2tp: "strongswan-charon strongswan-swanctl xl2tpd kmod-l2tp ppp-mod-pppol2tp",
	sstp: "sstp-client ppp",
	openvpn: "openvpn-openssl",
	wireguard: "wireguard-tools kmod-wireguard",
	amneziawg: "wireguard-tools kmod-wireguard",
	vless: "xray-core"
};

function missing_packages() {
	let need = [];
	let c = caps();
	for (let t in TYPES) if (!c[t]) push(need, t);
	let out = [];
	for (let t in need) for (let p in split(PKG_FOR_TYPE[t] ?? "", " ")) if (length(p)) {
		if (index(out, p) < 0) push(out, p);
	}
	return { types: need, packages: out };
}

function conns_load() {
	let raw = readfile(CONNFILE);
	if (length(raw)) {
		try {
			let d = json(raw);
			if (type(d) == "object" && d != null && type(d.items) == "array") return d;
		} catch (e) { }
	}
	return { items: [], active: "" };
}

function conns_save(doc) {
	ensure_dir(DATA);
	fs.writefile(CONNFILE, sprintf("%J", doc));
	run("chmod 600 " + shellq(CONNFILE));
	return doc;
}

function find_conn(id) {
	for (let c in conns_load().items) if (c.id == id) return c;
	return null;
}

function new_id() {
	let r = run("dd if=/dev/urandom bs=8 count=1 2>/dev/null | md5sum");
	let h = trim(r.out);
	if (length(h) < 8) h = sprintf("%08x%s", now(), "");
	return substr(h, 0, 8);
}

function conn_runtime_dir(id) {
	let d = RUNDIR + "/" + replace(id ?? "", /[^A-Za-z0-9_-]/g, "_");
	ensure_dir(d);
	run("chmod 700 " + shellq(d));
	return d;
}

function conn_endpoint(c) {
	let s = c.config ?? {};
	if (c.type == "vless") return (s.host ?? "") + ":" + (s.port ?? 443);
	if (c.type == "wireguard" || c.type == "amneziawg") return s.endpoint ?? "";
	if (length(s.server ?? "")) return s.server + (length(s.port ?? "") ? ":" + s.port : "");
	return s.host ?? "";
}

// A feed location is exposed to the same connect path as a manual connection:
// it is materialised as an IKEv2 connection with a candidate server list.
function loc_conn(key, index) {
	let loc = find_location(key);
	if (loc == null) return null;
	let idx = intval(index, 0);
	if (idx < 0 || idx >= length(loc.servers)) idx = 0;
	let s = loc.servers[idx];
	return {
		id: "loc:" + key + ":" + idx,
		type: "ikev2",
		name: loc.title + (length(loc.country) ? " (" + loc.country + ")" : ""),
		flag: loc.flag,
		source: "feed",
		config: {
			server: s.host, ip: s.ip, username: s.user, password: s.pass,
			local_id: s.local_id, remote_id: s.host
		},
		candidates: loc.servers
	};
}

function resolve_target(id) {
	if (index(id ?? "", "loc:") == 0) {
		let p = split(id, ":");
		return loc_conn(p[1] ?? "", intval(p[2], 0));
	}
	return find_conn(id);
}

// ------------------------------------------------------------------ parsers
// One tiny INI reader covers WireGuard/AmneziaWG configuration files, which is
// also the format Amnezia exports for its WireGuard-based protocols.
function ini_parse(text) {
	let out = [], cur = null;
	for (let raw in split(replace(text ?? "", /\r/g, ""), "\n")) {
		let line = trim(replace(raw, /(^|\s)#.*$/, ""));
		if (!length(line)) continue;
		let m = match(line, /^\[(.+)\]$/);
		if (m) { cur = { section: lc(trim(m[1])), kv: {} }; push(out, cur); continue; }
		let i = index(line, "=");
		if (i <= 0) continue;
		if (cur == null) { cur = { section: "", kv: {} }; push(out, cur); }
		cur.kv[lc(trim(substr(line, 0, i)))] = trim(substr(line, i + 1));
	}
	return out;
}

function wg_parse(text) {
	let blocks = ini_parse(text);
	let res = { iface: {}, peers: [], error: "" };
	for (let b in blocks) {
		if (b.section == "interface") {
			for (let k in b.kv) res.iface[k] = b.kv[k];
		} else if (b.section == "peer") {
			push(res.peers, b.kv);
		}
	}
	if (!length(res.iface.privatekey ?? "")) res.error = "the configuration has no [Interface] PrivateKey";
	else if (!length(res.peers)) res.error = "the configuration has no [Peer] section";
	return res;
}

// "172.16.0.2/32, fd00::2/128" -> [{addr, family}]
function split_addresses(v) {
	let out = [];
	for (let part in split(v ?? "", ",")) {
		part = trim(part);
		if (!length(part)) continue;
		push(out, part);
	}
	return out;
}

function vless_parse(uri) {
	uri = trim(uri ?? "");
	if (index(uri, "vless://") != 0) return { error: "not a vless:// URL" };
	let rest = substr(uri, 8);
	let hash = index(rest, "#");
	if (hash >= 0) rest = substr(rest, 0, hash);
	let q = index(rest, "?");
	let main = q >= 0 ? substr(rest, 0, q) : rest;
	let query = q >= 0 ? substr(rest, q + 1) : "";
	let at = index(main, "@");
	if (at <= 0) return { error: "URL has no uuid@host" };
	let uuid = substr(main, 0, at);
	let hostport = substr(main, at + 1);
	let host = hostport, port = 443;
	// IPv6 literals keep their brackets.
	if (match(hostport, /^\[/)) {
		let close = index(hostport, "]");
		if (close > 0) {
			host = substr(hostport, 0, close + 1);
			if (substr(hostport, close + 1, 1) == ":") port = intval(substr(hostport, close + 2), 443);
		}
	} else {
		let colon = rindex(hostport, ":");
		if (colon > 0) { host = substr(hostport, 0, colon); port = intval(substr(hostport, colon + 1), 443); }
	}
	let p = {};
	for (let kv in split(query, "&")) {
		if (!length(kv)) continue;
		let i = index(kv, "=");
		if (i < 0) continue;
		p[lc(substr(kv, 0, i))] = urldecode(substr(kv, i + 1));
	}
	host = replace(replace(host, /^\[/, ""), /\]$/, "");
	if (!length(uuid) || !length(host)) return { error: "URL is missing the uuid or the host" };
	return {
		uuid: uuid, host: host, port: port,
		flow: p.flow ?? "", security: p.security ?? "none", sni: p.sni ?? p.host ?? host,
		fp: p.fp ?? "chrome", pbk: p.pbk ?? "", sid: p.sid ?? "", spx: p.spx ?? "/", pqv: p.pqv ?? "",
		net: p.type ?? "tcp", path: p.path ?? "/", host_header: p.host ?? "",
		service: p.serviceName ?? "", alpn: p.alpn ?? "", allow_insecure: boolval(p.allowinsecure, false),
		raw: uri
	};
}

// Minimal .ovpn inspection: the panel shows the endpoint before connecting.
function ovpn_summary(text) {
	let remote = "", proto = "udp", port = 1194, dev = "tun";
	for (let raw in split(replace(text ?? "", /\r/g, ""), "\n")) {
		let line = trim(raw);
		if (!length(line) || substr(line, 0, 1) == "#" || substr(line, 0, 1) == ";") continue;
		let f = split(line, " ");
		if (f[0] == "remote" && !length(remote)) { remote = f[1] ?? ""; if (f[2]) port = intval(f[2], port); }
		if (f[0] == "proto" && f[1]) proto = lc(f[1]);
		if (f[0] == "dev" && f[1]) dev = f[1];
	}
	return { remote: remote, port: port, proto: proto, dev: dev };
}

// ------------------------------------------------------------------ drivers
// Every driver implements the same four calls, so the panel and the watchdog
// never need to know which protocol is active.

function wait_child(seconds) {
	for (let i = 0; i < seconds; i++) {
		let s = sas_parse();
		if (s.child) return s;
		sleep(1000);
	}
	return sas_parse();
}

function swan_stop() {
	run("swanctl --terminate --ike " + CONN);
	for (let i = 0; i < 6; i++) {
		let q = sas_parse();
		if (!q.ike && !q.child) break;
		sleep(500);
	}
}

function kill_pidfile(path) {
	let pid = intval(trim(readfile(path)), 0);
	if (pid > 1) {
		run(sprintf("kill %d 2>/dev/null", pid));
		sleep(400);
		run(sprintf("kill -9 %d 2>/dev/null", pid));
	}
	if (fs.stat(path)) fs.unlink(path);
}

// Kill processes whose command line contains $pattern.  BusyBox on this
// firmware ships pgrep and killall but no pkill, and matching on the command
// line keeps us from touching an unrelated instance of the same daemon.
function kill_match(pattern) {
	let r = run(sprintf("ps w | grep -F %s | grep -v grep | awk '{print $1}'", shellq(pattern)));
	for (let line in split(trim(r.out), "\n")) {
		let pid = intval(trim(line), 0);
		if (pid > 1) run(sprintf("kill %d 2>/dev/null", pid));
	}
	return true;
}

// Start a long running client in its own session so it survives the CGI
// request that started it, and record its pid for the teardown path.
function spawn_bg(cmd, logpath, pidpath) {
	let full = sprintf("setsid sh -c %s >>%s 2>&1 & echo $! > %s",
		shellq(cmd), shellq(logpath), shellq(pidpath));
	run("sh -c " + shellq(full));
	return intval(trim(readfile(pidpath)), 0);
}

function log_tail(path, lines) {
	let r = run(sprintf("tail -n %d %s", lines ?? 6, shellq(path)));
	return trim(r.out);
}

function wait_iface(name, seconds) {
	for (let i = 0; i < seconds * 2; i++) {
		if (iface_exists(name) && length(iface_v4(name))) return true;
		sleep(500);
	}
	return false;
}

function wait_ppp(before, seconds) {
	for (let i = 0; i < seconds * 2; i++) {
		let n = new_iface_since(before);
		if (length(n) && length(iface_v4(n))) return n;
		sleep(500);
	}
	return new_iface_since(before);
}

// -------------------------------------------------------------------- IKEv2

function ike_srv(c, alt) {
	let s = alt ?? c.config;
	return {
		host: trim("" + (s.server ?? s.host ?? "")),
		ip: trim("" + (s.ip ?? "")),
		user: trim("" + (s.username ?? s.user ?? "")),
		pass: "" + (s.password ?? s.pass ?? ""),
		local_id: trim("" + (s.local_id ?? "")),
		remote_id: trim("" + (s.remote_id ?? "")),
		psk: "" + (s.psk ?? "")
	};
}

function ike_ok(srv) {
	if (!length(srv.host)) return "server address is required";
	if (length(srv.psk)) return "";
	if (!length(srv.user) || !length(srv.pass)) return "username and password are required (or a pre-shared key)";
	return "";
}

function ike_prepare(c) {
	let srv = ike_srv(c);
	let err = ike_ok(srv);
	if (length(err)) return { ok: false, error: err };
	if (!length(srv.psk)) learn_chain(srv.host);
	write_conn(srv);
	return { ok: true };
}

function ike_up(c) {
	let list = [];
	if (type(c.candidates) == "array" && length(c.candidates)) {
		let idx = 0;
		let cfgp = c.config ?? {};
		for (let i = 0; i < length(c.candidates); i++) {
			if ((c.candidates[i].host ?? "") == (cfgp.server ?? "")) idx = i;
		}
		for (let k = 0; k < length(c.candidates); k++) push(list, c.candidates[(idx + k) % length(c.candidates)]);
	} else {
		push(list, null);
	}
	swan_stop();
	run("swanctl --load-creds");
	let lastErr = "", used = null, sa = null;
	for (let i = 0; i < length(list) && i < 3; i++) {
		let srv = ike_srv(c, list[i] ?? undefined);
		if (length(ike_ok(srv))) { lastErr = ike_ok(srv); continue; }
		if (i > 0) log("connect: trying alternate server " + srv.host);
		if (!length(srv.psk)) learn_chain(srv.host);
		write_conn(srv);
		run("swanctl --load-creds");
		let lc = run("swanctl --load-conns");
		if (lc.rc != 0) { lastErr = clean(lc.out); continue; }
		run("swanctl --initiate --child " + CHILD + " --timeout 15");
		let w = wait_child(10);
		if (w.child && length(w.vip)) { sa = w; used = srv; break; }
		lastErr = "peer did not establish a CHILD_SA";
		run("swanctl --terminate --ike " + CONN);
	}
	if (sa == null) {
		run("swanctl --terminate --ike " + CONN);
		return { ok: false, error: "IKEv2 handshake failed: " + (clean(lastErr) || "no CHILD_SA") };
	}
	return { ok: true, iface: "", vip: sa.vip, remote: sa.remote, xfrm: true, server: used.host };
}

function ike_down() {
	swan_stop();
	clear_conn_files();
}

function ike_probe() {
	let s = sas_parse();
	if (!s.child) return { up: false };
	return { up: true, iface: "", vip: s.vip, remote: s.remote, rx: s.rx, tx: s.tx, uptime: s.uptime, xfrm: true };
}

// -------------------------------------------------------------- L2TP/IPsec

function l2tp_prepare(c) {
	let s = c.config ?? {};
	let srv = { host: trim("" + (s.server ?? "")), psk: "" + (s.psk ?? ""), l2tp: true };
	if (!length(srv.host)) return { ok: false, error: "server address is required" };
	if (!length(srv.psk)) return { ok: false, error: "the IPsec pre-shared key is required" };
	write_conn(srv);
	let d = conn_runtime_dir(c.id);
	let lac = [
		"[global]",
		"port = 1701",
		"access control = no",
		"",
		"[lac vpnexit]",
		"lns = " + srv.host,
		"name = " + (s.username ?? ""),
		"pppoptfile = " + d + "/options",
		"ppp debug = no",
		"length bit = yes",
		"redial = no",
		""
	];
	writefile(d + "/xl2tpd.conf", join("\n", lac), "0600");
	let opts = [
		"ipcp-accept-local",
		"ipcp-accept-remote",
		"noauth",
		"refuse-eap",
		"noccp",
		"mtu " + cfg_int("tunnel_mtu", 1400),
		"mru " + cfg_int("tunnel_mtu", 1400),
		"user " + shellq(s.username ?? ""),
		"password " + shellq(s.password ?? ""),
		// No "lock" here: OpenWrt's pppd is built without it and refuses the
		// whole options file ("unrecognized option 'lock'").
		""
	];
	writefile(d + "/options", join("\n", opts), "0600");
	return { ok: true };
}

function l2tp_up(c) {
	let d = conn_runtime_dir(c.id);
	let before = ppp_ifaces();
	swan_stop();
	run("swanctl --load-creds");
	let lc = run("swanctl --load-conns");
	if (lc.rc != 0) return { ok: false, error: "cannot load the IPsec connection: " + clean(lc.out) };
	run("swanctl --initiate --child " + CHILD + " --timeout 15");
	let sa = wait_child(10);
	if (!sa.child) return { ok: false, error: "IPsec transport did not come up" };

	run("mkdir -p /var/run/xl2tpd");
	kill_pidfile(d + "/xl2tpd.pid");
	kill_match("xl2tpd -c " + d + "/xl2tpd.conf");
	spawn_bg(sprintf("xl2tpd -c %s -D -p %s", shellq(d + "/xl2tpd.conf"), shellq(d + "/xl2tpd.pid")),
		d + "/xl2tpd.log", d + "/xl2tpd.pid");
	sleep(1000);
	let ctl = "/var/run/xl2tpd/l2tp-control";
	if (!fs.stat(ctl)) return { ok: false, error: "xl2tpd did not create its control socket" };
	fs.writefile(ctl, "c vpnexit\n");
	let dev = wait_ppp(before, 25);
	if (!length(dev)) {
		return { ok: false, error: "L2TP did not bring up a ppp interface: " + log_tail(d + "/xl2tpd.log", 4) };
	}
	if (!length(iface_v4(dev))) sleep(1500);
	return { ok: true, iface: dev, vip: iface_v4(dev), xfrm: false };
}

function l2tp_down(c) {
	let d = RUNDIR + "/" + replace(c.id ?? "", /[^A-Za-z0-9_-]/g, "_");
	kill_match("xl2tpd -c " + d + "/xl2tpd.conf");
	kill_pidfile(d + "/xl2tpd.pid");
	swan_stop();
	clear_conn_files();
}

function l2tp_probe() {
	let st = state_read();
	let dev = st.iface ?? "";
	let s = sas_parse();
	if (!s.child) return { up: false };
	if (!length(dev) || !iface_exists(dev)) return { up: false };
	let b = iface_bytes(dev);
	return { up: true, iface: dev, vip: iface_v4(dev), rx: b.rx, tx: b.tx, uptime: s.uptime };
}

// --------------------------------------------------------------------- SSTP

function sstp_prepare(c) {
	let s = c.config ?? {};
	if (!length(s.server ?? "")) return { ok: false, error: "server address is required" };
	if (!length(s.username ?? "")) return { ok: false, error: "username is required" };
	return { ok: true };
}

function sstp_up(c) {
	let s = c.config ?? {};
	let d = conn_runtime_dir(c.id);
	let port = intval(s.port, 443);
	let mtu = cfg_int("tunnel_mtu", 1400);
	let before = ppp_ifaces();
	let args = sprintf("sstpc --user %s --password %s --log-level 2 --cert-warn %s:%d ipparam vpnexit nodefaultroute noauth refuse-eap mtu %d mru %d",
		shellq(s.username ?? ""), shellq(s.password ?? ""), shellq(s.server ?? ""), port, mtu, mtu);
	if (boolval(s.insecure, true)) run("true");
	kill_pidfile(d + "/sstpc.pid");
	spawn_bg(args, d + "/sstpc.log", d + "/sstpc.pid");
	let dev = wait_ppp(before, 30);
	if (!length(dev)) {
		return { ok: false, error: "SSTP did not bring up a ppp interface: " + log_tail(d + "/sstpc.log", 5) };
	}
	if (!length(iface_v4(dev))) sleep(1000);
	return { ok: true, iface: dev, vip: iface_v4(dev), xfrm: false };
}

function sstp_down(c) {
	let d = RUNDIR + "/" + replace(c.id ?? "", /[^A-Za-z0-9_-]/g, "_");
	kill_pidfile(d + "/sstpc.pid");
	kill_match("sstpc --user");
}

function sstp_probe() {
	let st = state_read();
	let dev = st.iface ?? "";
	if (!length(dev) || !iface_exists(dev)) return { up: false };
	let b = iface_bytes(dev);
	return { up: true, iface: dev, vip: iface_v4(dev), rx: b.rx, tx: b.tx, uptime: 0 };
}

// ------------------------------------------------------------------ OpenVPN

function ovpn_prepare(c) {
	let s = c.config ?? {};
	let raw = replace(s.raw ?? "", /\r/g, "");
	if (!length(trim(raw))) return { ok: false, error: "paste the .ovpn file contents" };
	if (!match(raw, /(^|\n)\s*(client|remote)\b/)) return { ok: false, error: "the pasted text does not look like an OpenVPN client profile" };
	let d = conn_runtime_dir(c.id);
	let lines = [];
	for (let line in split(raw, "\n")) {
		let t = trim(line);
		if (match(t, /^(daemon|route-nopull|dev|dev-type|writepid|log|log-append)\b/)) continue;
		push(lines, line);
	}
	push(lines, "");
	push(lines, "# ---- managed by vpnexit ----");
	push(lines, "client");
	push(lines, "dev-type tun");
	push(lines, "dev " + OVPNIFACE);
	push(lines, "nobind");
	push(lines, "persist-tun");
	push(lines, "persist-key");
	push(lines, "route-nopull");
	push(lines, "verb 3");
	push(lines, "ping 10");
	push(lines, "ping-restart 60");
	if (length(s.username ?? "") || length(s.password ?? "")) {
		writefile(d + "/auth.txt", (s.username ?? "") + "\n" + (s.password ?? "") + "\n", "0600");
		push(lines, "auth-user-pass " + d + "/auth.txt");
	}
	writefile(d + "/client.conf", join("\n", lines) + "\n", "0600");
	return { ok: true, endpoint: ovpn_summary(raw).remote };
}

function ovpn_up(c) {
	let d = conn_runtime_dir(c.id);
	run("ip link del " + OVPNIFACE + " 2>/dev/null");
	kill_pidfile(d + "/openvpn.pid");
	kill_match(d + "/client.conf");
	spawn_bg(sprintf("openvpn --config %s --writepid %s", shellq(d + "/client.conf"), shellq(d + "/openvpn.pid")),
		d + "/openvpn.log", d + "/openvpn.pid");
	if (!wait_iface(OVPNIFACE, 30)) {
		kill_pidfile(d + "/openvpn.pid");
		return { ok: false, error: "OpenVPN did not come up: " + log_tail(d + "/openvpn.log", 5) };
	}
	return { ok: true, iface: OVPNIFACE, vip: iface_v4(OVPNIFACE), xfrm: false };
}

function ovpn_down(c) {
	let d = RUNDIR + "/" + replace(c.id ?? "", /[^A-Za-z0-9_-]/g, "_");
	kill_pidfile(d + "/openvpn.pid");
	kill_match(d + "/client.conf");
	sleep(300);
	run("ip link del " + OVPNIFACE + " 2>/dev/null");
}

function ovpn_probe() {
	if (!iface_exists(OVPNIFACE)) return { up: false };
	let v4 = iface_v4(OVPNIFACE);
	if (!length(v4)) return { up: false };
	let b = iface_bytes(OVPNIFACE);
	return { up: true, iface: OVPNIFACE, vip: v4, rx: b.rx, tx: b.tx, uptime: 0 };
}

// ------------------------------------------------------ WireGuard/AmneziaWG
//
// AmneziaWG is not "WireGuard with a different name": the handshake headers,
// paddings and junk packets are changed, and a plain WireGuard client is
// silently dropped by an AmneziaWG server.  The kernel module is not in the
// OpenWrt feed, so the panel runs the userspace implementation
// (amneziawg-go) and pushes the obfuscation parameters through its UAPI socket.
// That needs socat.
//
// Order of preference:
//   amneziawg kernel module + awg   -> native, fastest
//   amneziawg-go + socat            -> real obfuscation, userspace
//   wg only                         -> plain WireGuard, clearly reported

function awg_go_bin() {
	if (has_bin("/usr/sbin/amneziawg-go")) return "/usr/sbin/amneziawg-go";
	if (has_bin("/usr/bin/amneziawg-go")) return "/usr/bin/amneziawg-go";
	return "";
}

function awg_mode(c) {
	if (c.type != "amneziawg") return "kernel";
	if (has_bin("/usr/bin/awg")) return "kernel-awg";
	if (length(awg_go_bin()) && has_bin("/usr/bin/socat")) return "userspace";
	return "fallback";
}

function wg_tool(c) {
	if (c.type == "amneziawg" && awg_mode(c) == "kernel-awg") return "/usr/bin/awg";
	return "/usr/bin/wg";
}

function wg_degraded(c) {
	if (c.type != "amneziawg") return "";
	if (awg_mode(c) != "fallback") return "";
	return "amneziawg-go is not installed - running as plain WireGuard, the obfuscation parameters are ignored";
}

function wg_parse_cfg(c) {
	return wg_parse((c.config ?? {}).raw ?? "");
}

// The UAPI speaks hex, the configuration files speak base64.
function wg_hex(v) {
	let d = RUNDIR + "/hex.tmp";
	fs.writefile(d, trim(v ?? ""));
	let r = run("openssl base64 -d -A < " + shellq(d) + " | hexdump -v -e '1/1 \"%02x\"'");
	fs.unlink(d);
	return trim(r.out);
}

// UAPI block for the userspace daemon.  Key names are the ones amneziawg-go
// parses in device/uapi.go.
function awg_uapi(p, mode) {
	let lines = ["set=1", "private_key=" + wg_hex(p.iface.privatekey)];
	if (length(p.iface.listenport ?? "")) push(lines, "listen_port=" + p.iface.listenport);
	if (mode == "userspace" || mode == "kernel-awg") {
		for (let k in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"]) {
			if (length(p.iface[k] ?? "")) push(lines, k + "=" + p.iface[k]);
		}
	}
	push(lines, "replace_peers=true");
	for (let peer in p.peers) {
		push(lines, "public_key=" + wg_hex(peer.publickey ?? ""));
		if (length(peer.presharedkey ?? "")) push(lines, "preshared_key=" + wg_hex(peer.presharedkey));
		if (length(peer.endpoint ?? "")) push(lines, "endpoint=" + peer.endpoint);
		for (let a in split_addresses(peer.allowedips ?? "")) push(lines, "allowed_ip=" + a);
		if (length(peer.persistentkeepalive ?? "")) push(lines, "persistent_keepalive_interval=" + peer.persistentkeepalive);
	}
	return join("\n", lines) + "\n";
}

function wg_prepare(c) {
	let p = wg_parse_cfg(c);
	if (length(p.error)) return { ok: false, error: p.error };
	if (!length(p.peers[0].endpoint ?? "")) return { ok: false, error: "the [Peer] section has no Endpoint" };
	let d = conn_runtime_dir(c.id);
	let mode = awg_mode(c);

	if (mode == "userspace") {
		writefile(d + "/awg.uapi", awg_uapi(p, mode), "0600");
	} else {
		let lines = ["[Interface]", "PrivateKey = " + p.iface.privatekey];
		if (length(p.iface.listenport ?? "")) push(lines, "ListenPort = " + p.iface.listenport);
		if (mode == "kernel-awg") {
			for (let k in ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"]) {
				if (length(p.iface[k] ?? "")) push(lines, uc(k) + " = " + p.iface[k]);
			}
		}
		for (let peer in p.peers) {
			push(lines, "");
			push(lines, "[Peer]");
			push(lines, "PublicKey = " + (peer.publickey ?? ""));
			if (length(peer.presharedkey ?? "")) push(lines, "PresharedKey = " + peer.presharedkey);
			if (length(peer.allowedips ?? "")) push(lines, "AllowedIPs = " + peer.allowedips);
			if (length(peer.endpoint ?? "")) push(lines, "Endpoint = " + peer.endpoint);
			if (length(peer.persistentkeepalive ?? "")) push(lines, "PersistentKeepalive = " + peer.persistentkeepalive);
		}
		push(lines, "");
		writefile(d + "/wg.conf", join("\n", lines), "0600");
	}

	let addrs = split_addresses(p.iface.address ?? "");
	writefile(d + "/meta.json", sprintf("%J", {
		addrs: addrs, mtu: intval(p.iface.mtu, 0), mode: mode,
		tool: wg_tool(c), degraded: wg_degraded(c),
		obfuscated: (length(p.iface.jc ?? "") || length(p.iface.h1 ?? "")),
		endpoint: p.peers[0].endpoint ?? ""
	}), "0600");
	return { ok: true, endpoint: p.peers[0].endpoint ?? "", degraded: wg_degraded(c) };
}

function wg_up(c) {
	let d = conn_runtime_dir(c.id);
	let meta;
	try { meta = json(readfile(d + "/meta.json")); } catch (e) { return { ok: false, error: "run save first" }; }
	let mode = meta.mode ?? "kernel";

	run("ip link del " + WGIFACE + " 2>/dev/null");

	if (mode == "userspace") {
		let bin = awg_go_bin();
		kill_pidfile(d + "/awg.pid");
		kill_match(bin + " -f " + WGIFACE);
		spawn_bg(sprintf("%s -f %s", bin, WGIFACE), d + "/awg.log", d + "/awg.pid");
		let sock = "/var/run/amneziawg/" + WGIFACE + ".sock";
		let ready = false;
		for (let i = 0; i < 25; i++) {
			if (fs.stat(sock)) { ready = true; break; }
			sleep(200);
		}
		if (!ready) return { ok: false, error: "amneziawg-go did not create its socket: " + log_tail(d + "/awg.log", 4) };

		for (let a in meta.addrs ?? []) run(sprintf("ip addr add %s dev %s", shellq(a), WGIFACE));
		let mtu = intval(meta.mtu, 0);
		if (mtu <= 0) mtu = cfg_int("tunnel_mtu", 1400);
		run(sprintf("ip link set mtu %d up dev %s", mtu, WGIFACE));

		let r = run(sprintf("socat -t 4 - UNIX-CONNECT:%s < %s", shellq(sock), shellq(d + "/awg.uapi")));
		if (index(r.out, "errno=0") < 0) {
			return { ok: false, error: "the obfuscated configuration was rejected: " + clean(r.out) };
		}
		if (!wait_iface(WGIFACE, 8)) {
			return { ok: false, error: "the interface has no address - add one to the [Interface] Address line" };
		}
		return { ok: true, iface: WGIFACE, vip: iface_v4(WGIFACE), xfrm: false, degraded: meta.degraded ?? "" };
	}

	if (!has_bin(meta.tool ?? "/usr/bin/wg")) return { ok: false, error: "neither wg nor awg is installed" };
	let kind = mode == "kernel-awg" ? "amneziawg" : "wireguard";
	let add = run(sprintf("ip link add %s type %s", WGIFACE, kind));
	if (add.rc != 0) return { ok: false, error: "cannot create the interface: " + clean(add.out) };
	let set = run(sprintf("%s setconf %s %s", meta.tool, WGIFACE, shellq(d + "/wg.conf")));
	if (set.rc != 0) {
		run("ip link del " + WGIFACE + " 2>/dev/null");
		return { ok: false, error: "the peer configuration was rejected: " + clean(set.out) };
	}
	for (let a in meta.addrs ?? []) run(sprintf("ip addr add %s dev %s", shellq(a), WGIFACE));
	let mtu = intval(meta.mtu, 0);
	if (mtu <= 0) mtu = cfg_int("tunnel_mtu", 1400);
	run(sprintf("ip link set mtu %d up dev %s", mtu, WGIFACE));
	if (!wait_iface(WGIFACE, 8)) {
		return { ok: false, error: "the interface has no address - add one to the [Interface] Address line" };
	}
	return { ok: true, iface: WGIFACE, vip: iface_v4(WGIFACE), xfrm: false, degraded: meta.degraded ?? "" };
}

function wg_down(c) {
	let d = RUNDIR + "/" + replace(c.id ?? "", /[^A-Za-z0-9_-]/g, "_");
	kill_pidfile(d + "/awg.pid");
	if (length(awg_go_bin())) kill_match(awg_go_bin() + " -f " + WGIFACE);
	run("ip link del " + WGIFACE + " 2>/dev/null");
}

function wg_probe() {
	if (!iface_exists(WGIFACE)) return { up: false };
	let v4 = iface_v4(WGIFACE);
	if (!length(v4)) return { up: false };
	let b = iface_bytes(WGIFACE);
	return { up: true, iface: WGIFACE, vip: v4, rx: b.rx, tx: b.tx, uptime: 0 };
}


// ---------------------------------------------------------- VLESS / REALITY
// Xray is the client here, not sing-box: this server uses the post-quantum
// REALITY variant, where the URL carries pqv (an ML-DSA-65 key) that has to be
// verified by the client. sing-box has no equivalent and fails with
// "reality verification failed".
//
// Xray has no tun inbound, so the marked LAN traffic is handed to a local
// dokodemo-door socket with TPROXY instead of being routed into an interface.
// That also means no masquerade is needed: xray dials the server itself.

const XRAY_PROXY_PORT = 12345;
const XRAY_HTTP_PORT = 18081;
const TPROXY_TABLE = 100;

function xc_outbound(v) {
	let rs = {
		serverName: v.sni,
		fingerprint: length(v.fp) ? v.fp : "chrome",
		publicKey: v.pbk,
		shortId: v.sid
	};
	if (length(v.spx)) rs.spiderX = v.spx;
	// pqv is the post-quantum public key of the server; without it the
	// handshake is refused by the peer.
	if (length(v.pqv)) rs.mldsa65Verify = v.pqv;

	let users = { id: v.uuid, encryption: "none" };
	if (length(v.flow)) users.flow = v.flow;

	let stream = { network: "tcp" };
	if (v.security == "reality") {
		stream.security = "reality";
		stream.realitySettings = rs;
	} else if (v.security == "tls") {
		// Xray 26 removed allowInsecure on purpose; a TLS profile therefore
		// needs a certificate the router can validate.
		stream.security = "tls";
		stream.tlsSettings = { serverName: v.sni };
	} else {
		stream.security = "none";
	}
	if (v.net == "ws") {
		stream.network = "ws";
		stream.wsSettings = { path: length(v.path) ? v.path : "/" };
		if (length(v.host_header)) stream.wsSettings.headers = { Host: v.host_header };
	} else if (v.net == "grpc") {
		stream.network = "grpc";
		stream.grpcSettings = { serviceName: v.service };
	}

	return {
		tag: "proxy",
		protocol: "vless",
		settings: { vnext: [{ address: v.host, port: v.port, users: [users] }] },
		streamSettings: stream
	};
}

function xc_config(v) {
	// routeOnly keeps the sniffed destination from being rewritten, which is
	// what TPROXY needs; the http inbound exists only for the health check.
	return {
		log: { loglevel: "warning" },
		inbounds: [
			{
				tag: "tproxy-in", listen: "127.0.0.1", port: XRAY_PROXY_PORT, protocol: "dokodemo-door",
				settings: { network: "tcp,udp", followRedirect: true },
				streamSettings: { sockopt: { tproxy: "tproxy" } },
				sniffing: { enabled: true, destOverride: ["http", "tls"], routeOnly: true }
			},
			{ tag: "http-in", listen: "127.0.0.1", port: XRAY_HTTP_PORT, protocol: "http" }
		],
		outbounds: [xc_outbound(v), { tag: "direct", protocol: "freedom" }]
	};
}

function vless_prepare(c) {
	let v = vless_parse((c.config ?? {}).raw ?? "");
	if (length(v.error ?? "")) return { ok: false, error: v.error };
	if (v.security == "reality" && !length(v.pbk))
		return { ok: false, error: "the URL has no pbk, so REALITY cannot be verified" };
	if (v.security == "reality" && !length(v.sid))
		return { ok: false, error: "the URL has no sid (short id)" };
	let d = conn_runtime_dir(c.id);
	writefile(d + "/xray.json", sprintf("%J", xc_config(v)), "0600");
	let chk = run(sprintf("xray run -test -c %s", shellq(d + "/xray.json")));
	if (chk.rc != 0) return { ok: false, error: "xray rejected the configuration: " + clean(chk.out) };
	return { ok: true, endpoint: v.host + ":" + v.port };
}

// Exit IP as seen through the local http inbound. BusyBox wget ignores
// http_proxy for https, so the check uses plain http.
function http_inbound_ip(seconds) {
	let r = run(sprintf("http_proxy=http://127.0.0.1:%d wget -q -O - --timeout=%d http://icanhazip.com",
		XRAY_HTTP_PORT, seconds ?? 6));
	let ip = trim(r.out ?? "");
	if (match(ip, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) return ip;
	return "";
}

function vless_up(c) {
	let d = conn_runtime_dir(c.id);
	kill_pidfile(d + "/xray.pid");
	kill_match(d + "/xray.json");
	sleep(200);
	spawn_bg(sprintf("xray run -c %s", shellq(d + "/xray.json")), d + "/xray.log", d + "/xray.pid");
	let ip = "";
	for (let i = 0; i < 8 && !length(ip); i++) {
		sleep(700);
		ip = http_inbound_ip(5);
	}
	if (!length(ip)) {
		kill_pidfile(d + "/xray.pid");
		return { ok: false, error: "the VLESS handshake failed: " + log_tail(d + "/xray.log", 4) };
	}
	return { ok: true, iface: "", vip: "", tproxy: true, port: XRAY_PROXY_PORT, exit_ip: ip };
}

function vless_down(c) {
	let d = RUNDIR + "/" + replace(c.id ?? "", /[^A-Za-z0-9_-]/g, "_");
	kill_pidfile(d + "/xray.pid");
	kill_match(d + "/xray.json");
}

function vless_probe() {
	let st = state_read();
	let pidfile = RUNDIR + "/" + replace(st.conn_id ?? "", /[^A-Za-z0-9_-]/g, "_") + "/xray.pid";
	let pid = intval(trim(readfile(pidfile)), 0);
	if (pid <= 0) return { up: false };
	if (run(sprintf("kill -0 %d 2>/dev/null", pid)).rc != 0) return { up: false };
	return { up: true, iface: "", vip: "", tproxy: true, port: XRAY_PROXY_PORT, rx: 0, tx: 0, uptime: 0 };
}

// --------------------------------------------------------------- dispatchers

function drv_prepare(c) {
	let t = c.type;
	if (t == "ikev2") return ike_prepare(c);
	if (t == "l2tp") return l2tp_prepare(c);
	if (t == "sstp") return sstp_prepare(c);
	if (t == "openvpn") return ovpn_prepare(c);
	if (t == "wireguard" || t == "amneziawg") return wg_prepare(c);
	if (t == "vless") return vless_prepare(c);
	return { ok: false, error: "unknown protocol " + t };
}

function drv_up(c) {
	let t = c.type;
	if (t == "ikev2") return ike_up(c);
	if (t == "l2tp") return l2tp_up(c);
	if (t == "sstp") return sstp_up(c);
	if (t == "openvpn") return ovpn_up(c);
	if (t == "wireguard" || t == "amneziawg") return wg_up(c);
	if (t == "vless") return vless_up(c);
	return { ok: false, error: "unknown protocol " + t };
}

function drv_down(c) {
	if (c == null) return;
	let t = c.type;
	if (t == "ikev2") return ike_down(c);
	if (t == "l2tp") return l2tp_down(c);
	if (t == "sstp") return sstp_down(c);
	if (t == "openvpn") return ovpn_down(c);
	if (t == "wireguard" || t == "amneziawg") return wg_down(c);
	if (t == "vless") return vless_down(c);
}

function drv_probe(c) {
	if (c == null) return { up: false };
	let t = c.type;
	if (t == "ikev2") return ike_probe();
	if (t == "l2tp") return l2tp_probe();
	if (t == "sstp") return sstp_probe();
	if (t == "openvpn") return ovpn_probe();
	if (t == "wireguard" || t == "amneziawg") return wg_probe();
	if (t == "vless") return vless_probe();
	return { up: false };
}

// ------------------------------------------------------------------ routing
// The mark + policy route is protocol independent.  What changes is the shape
// of the route (an XFRM tunnel keeps the uplink route and is matched by policy,
// a tun/wg/ppp interface becomes the table default) and the NAT rule.

function table_exists(spec) {
	return run("nft list table " + spec).rc == 0;
}

// filter and nat for forwarded LAN traffic
function routing_ruleset(o) {
	let mark = cfg("mark", "0x1a1");
	let mtu = cfg_int("tunnel_mtu", 1400);
	let mss = o.xfrm ? (mtu - 80) : (mtu - 40);
	if (mss < 1200) mss = 1200;
	let lan_cidr = mask4(iface_cidr(o.lan)) ?? "192.168.1.0/24";
	let wan_cidr = mask4(iface_cidr(o.wan)) ?? "";
	let excl = ["127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", lan_cidr];
	if (length(o.vip)) push(excl, o.vip + "/32");
	if (length(wan_cidr)) push(excl, wan_cidr);
	if (length(o.server_ip)) push(excl, o.server_ip + "/32");

	let t = [];
	push(t, "table inet vpnexit {");
	push(t, "\tset exclude4 {");
	push(t, "\t\ttype ipv4_addr");
	push(t, "\t\tflags interval");
	push(t, "\t\tauto-merge");
	push(t, sprintf("\t\telements = { %s }", join(", ", excl)));
	push(t, "\t}");
	push(t, "\tchain vpx_mark {");
	push(t, "\t\ttype filter hook prerouting priority mangle; policy accept;");
	push(t, sprintf("\t\tiifname != \"%s\" return", o.lan));
	push(t, "\t\tip daddr @exclude4 return");
	push(t, sprintf("\t\tmeta mark set %s counter", mark));
	push(t, "\t}");
	push(t, "\tchain vpx_mss {");
	push(t, "\t\ttype filter hook postrouting priority mangle; policy accept;");
	if (o.xfrm) {
		push(t, sprintf("\t\tmeta mark %s tcp flags syn tcp option maxseg size set %d", mark, mss));
	} else {
		push(t, sprintf("\t\toifname \"%s\" meta mark %s tcp flags syn tcp option maxseg size set %d", o.iface, mark, mss));
	}
	push(t, "\t}");
	// DNS is tunneled to avoid ISP filtering, but only for public resolvers:
	// the router's own upstream usually lives on the LAN (the ISP router) and
	// marking those queries sent them into the tunnel where nothing answers.
	push(t, "\tchain vpx_dnsout {");
	push(t, "\t\ttype route hook output priority mangle; policy accept;");
	push(t, "\t\tudp dport 53 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8 } return");
	push(t, "\t\ttcp dport 53 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8 } return");
	push(t, sprintf("\t\tudp dport 53 meta mark set %s counter", mark));
	push(t, sprintf("\t\ttcp dport 53 meta mark set %s counter", mark));
	push(t, "\t}");
	push(t, "\tchain vpx_dnsredirect {");
	push(t, "\t\ttype nat hook prerouting priority dstnat; policy accept;");
	push(t, sprintf("\t\tiifname \"%s\" udp dport 53 redirect to :53", o.lan));
	push(t, sprintf("\t\tiifname \"%s\" tcp dport 53 redirect to :53", o.lan));
	push(t, "\t}");
	if (o.block_v6) {
		push(t, "\tchain vpx_v6 {");
		push(t, "\t\ttype filter hook forward priority filter; policy accept;");
		push(t, sprintf("\t\tiifname \"%s\" oifname \"%s\" meta nfproto ipv6 drop", o.lan, o.wan));
		push(t, "\t}");
	}
	push(t, "}");
	push(t, "table ip vpnexit_nat {");
	push(t, "\tchain vpx_nat {");
	push(t, "\t\ttype nat hook postrouting priority srcnat; policy accept;");
	if (o.xfrm) {
		push(t, sprintf("\t\toifname \"%s\" meta mark %s counter snat ip to %s", o.wan, mark, o.vip));
	} else {
		push(t, sprintf("\t\toifname \"%s\" meta mark %s counter masquerade", o.iface, mark));
	}
	push(t, "\t}");
	push(t, "}");
	return join("\n", t) + "\n";
}

// fw4 drops anything that is forwarded to an interface it does not know, so a
// tunnel interface gets a throw-away zone while it is in use.
function zone_active() { return cursor().get("firewall", "vpnexit", "name") != null; }

function zone_ensure(dev) {
	if (!length(dev)) return false;
	let cur = cursor().get("firewall", "vpnexit", "device");
	if (cur == dev) return true;
	let c = cursor();
	c.set("firewall", "vpnexit", "zone");
	c.set("firewall", "vpnexit", "name", "vpnexit");
	c.set("firewall", "vpnexit", "input", "REJECT");
	c.set("firewall", "vpnexit", "output", "ACCEPT");
	c.set("firewall", "vpnexit", "forward", "ACCEPT");
	c.set("firewall", "vpnexit", "masq", "0");
	c.set("firewall", "vpnexit", "mtu_fix", "0");
	c.set("firewall", "vpnexit", "device", dev);
	c.set("firewall", "vpnexit_fwd", "forwarding");
	c.set("firewall", "vpnexit_fwd", "src", "lan");
	c.set("firewall", "vpnexit_fwd", "dest", "vpnexit");
	c.commit("firewall");
	run("/etc/init.d/firewall reload >/dev/null 2>&1");
	log("routing: firewall zone opened for " + dev);
	return true;
}

function zone_remove() {
	if (!zone_active()) return;
	cursor().delete("firewall", "vpnexit");
	cursor().delete("firewall", "vpnexit_fwd");
	cursor().commit("firewall");
	run("/etc/init.d/firewall reload >/dev/null 2>&1");
	log("routing: firewall zone removed");
}

// TPROXY variant: the packets are not routed into a device, they are handed to
// a local socket. Only the mark and the local route are needed, and no NAT rule
// at all, because the proxy dials the server with the router's own address.
function routing_tproxy_apply(port) {
	let lan = lan_iface();
	let dr = default_route();
	if (!dr.dev) return { ok: false, error: "cannot determine the WAN interface" };
	let smark = cfg("mark", "0x1a1");
	let lan_cidr = mask4(iface_cidr(lan)) ?? "192.168.1.0/24";
	let wan_cidr = mask4(iface_cidr(dr.dev)) ?? "";
	let st = state_read();
	let server = st.server_ip ?? "";
	if (!length(server) && length(st.server ?? "")) {
		let host = split(st.server, ":")[0] ?? "";
		server = resolve4(host);
	}
	let excl = ["127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", lan_cidr];
	if (length(wan_cidr)) push(excl, wan_cidr);
	if (length(server)) push(excl, server + "/32");

	let t = [];
	push(t, "table inet vpnexit {");
	push(t, "\tset exclude4 {");
	push(t, "\t\ttype ipv4_addr");
	push(t, "\t\tflags interval");
	push(t, "\t\tauto-merge");
	push(t, sprintf("\t\telements = { %s }", join(", ", excl)));
	push(t, "\t}");
	push(t, "\tchain vpx_tproxy {");
	push(t, "\t\ttype filter hook prerouting priority mangle; policy accept;");
	push(t, sprintf("\t\tiifname != \"%s\" return", lan));
	push(t, "\t\tip daddr @exclude4 return");
	push(t, "\t\tudp dport 53 return");
	push(t, "\t\ttcp dport 53 return");
	push(t, sprintf("\t\tmeta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%d meta mark set %s counter", port, smark));
	push(t, "\t}");
	push(t, "\tchain vpx_dnsredirect {");
	push(t, "\t\ttype nat hook prerouting priority dstnat; policy accept;");
	push(t, sprintf("\t\tiifname \"%s\" udp dport 53 redirect to :53", lan));
	push(t, sprintf("\t\tiifname \"%s\" tcp dport 53 redirect to :53", lan));
	push(t, "\t}");
	if (cfg_bool("block_ipv6", true)) {
		push(t, "\tchain vpx_v6 {");
		push(t, "\t\ttype filter hook forward priority filter; policy accept;");
		push(t, sprintf("\t\tiifname \"%s\" oifname \"%s\" meta nfproto ipv6 drop", lan, dr.dev));
		push(t, "\t}");
	}
	push(t, "}");

	ensure_dir(RUN);
	let path = RUN + "/last.nft";
	fs.writefile(path, join("\n", t) + "\n");
	let chk = run("nft -c -f " + shellq(path));
	if (chk.rc != 0) return { ok: false, error: "ruleset rejected: " + clean(chk.out) };
	let batch = "";
	if (table_exists("inet vpnexit")) batch += "delete table inet vpnexit\n";
	fs.writefile(RUN + "/apply.nft", batch + join("\n", t) + "\n");
	let ap = run("nft -f " + shellq(RUN + "/apply.nft"));
	if (ap.rc != 0) return { ok: false, error: "cannot apply rules: " + clean(ap.out) };

	// A TRANSPARENT socket is only reachable when the packet is marked and the
	// mark sends it to the local table.
	for (let i = 0; i < 4; i++)
		run(sprintf("ip rule del fwmark %s lookup %d", smark, TPROXY_TABLE));
	let ar = run(sprintf("ip rule add fwmark %s lookup %d priority %d", smark, TPROXY_TABLE, cfg_int("rule_priority", 1000)));
	if (ar.rc != 0) return { ok: false, error: "cannot add the tproxy rule: " + clean(ar.out) };
	run(sprintf("ip route replace local 0.0.0.0/0 dev lo table %d", TPROXY_TABLE));
	log(sprintf("routing: tproxy on 127.0.0.1:%d for %s", port, lan));
	return { ok: true, tproxy: true };
}

function routing_apply(iface, vip, tproxy_port) {
	if (intval(tproxy_port, 0) > 0) return routing_tproxy_apply(intval(tproxy_port, 0));
	let xfrm = !length(iface);
	if (!xfrm && !iface_exists(iface)) return { ok: false, error: "interface " + iface + " is not up" };
	if (xfrm && !length(vip)) return { ok: false, error: "tunnel has no address yet" };
	let lan = lan_iface();
	let dr = default_route();
	if (!dr.dev) return { ok: false, error: "cannot determine the WAN interface" };
	let st = state_read();
	let server = st.server_ip ?? "";
	if (!length(server) && length(st.server ?? "")) server = resolve4(st.server);
	let rules = routing_ruleset({
		lan: lan, wan: dr.dev, gw: dr.gw, iface: iface, vip: vip,
		xfrm: xfrm, server_ip: server, block_v6: cfg_bool("block_ipv6", true)
	});
	ensure_dir(RUN);
	let path = RUN + "/last.nft";
	fs.writefile(path, rules);
	let chk = run("nft -c -f " + shellq(path));
	if (chk.rc != 0) {
		log("routing: invalid ruleset: " + clean(chk.out));
		return { ok: false, error: "ruleset rejected: " + clean(chk.out) };
	}
	let batch = "";
	if (table_exists("inet vpnexit")) batch += "delete table inet vpnexit\n";
	if (table_exists("ip vpnexit_nat")) batch += "delete table ip vpnexit_nat\n";
	batch += rules;
	fs.writefile(RUN + "/apply.nft", batch);
	let ap = run("nft -f " + shellq(RUN + "/apply.nft"));
	if (ap.rc != 0) {
		log("routing: apply failed: " + clean(ap.out));
		return { ok: false, error: "cannot apply rules: " + clean(ap.out) };
	}

	if (!xfrm) zone_ensure(iface);

	let table = cfg_int("table", 417);
	let prio = cfg_int("rule_priority", 1000);
	let mark = cfg("mark", "0x1a1");
	let route;
	if (xfrm) {
		route = length(dr.gw)
			? sprintf("ip route replace default via %s dev %s table %d", dr.gw, dr.dev, table)
			: sprintf("ip route replace default dev %s table %d", dr.dev, table);
	} else {
		route = sprintf("ip route replace default dev %s table %d", iface, table);
	}
	let rr = run(route);
	if (rr.rc != 0) {
		log("routing: cannot add table route: " + clean(rr.out));
		return { ok: false, error: "cannot add route: " + clean(rr.out) };
	}
	for (let i = 0; i < 4; i++)
		run(sprintf("ip rule del fwmark %s lookup %d priority %d", mark, table, prio));
	let ar = run(sprintf("ip rule add fwmark %s lookup %d priority %d", mark, table, prio));
	if (ar.rc != 0) return { ok: false, error: "cannot add ip rule: " + clean(ar.out) };
	log(sprintf("routing: active (%s -> %s, iface %s, vip %s)", lan, dr.dev, length(iface) ? iface : "xfrm", vip));
	return { ok: true, vip: vip, iface: iface };
}

function routing_clear() {
	let table = cfg_int("table", 417);
	let prio = cfg_int("rule_priority", 1000);
	let mark = cfg("mark", "0x1a1");
	run("nft delete table inet vpnexit");
	run("nft delete table ip vpnexit_nat");
	run("nft delete table inet vpnexit_probe");
	for (let i = 0; i < 4; i++) {
		run(sprintf("ip rule del fwmark %s lookup %d priority %d", mark, table, prio));
		run(sprintf("ip rule del fwmark %s lookup %d", mark, TPROXY_TABLE));
	}
	run(sprintf("ip route flush table %d", table));
	run(sprintf("ip route flush table %d", TPROXY_TABLE));
	zone_remove();
}

// The state decides which shape the rules should have: an interface tunnel uses
// the default route in table 417, a TPROXY proxy only needs the mark + local
// route. Both are checked here so the watchdog can repair either one.
function routing_active() {
	let st = state_read();
	if (!table_exists("inet vpnexit")) return false;
	if (intval(st.tproxy, 0) > 0) {
		if (run(sprintf("ip rule show | grep -q 'fwmark %s lookup %d'", cfg("mark", "0x1a1"), TPROXY_TABLE)).rc != 0) return false;
		if (run(sprintf("ip route show table %d | grep -q local", TPROXY_TABLE)).rc != 0) return false;
		return true;
	}
	if (!length(st.iface ?? "") && !length(st.vip ?? "")) return false;
	if (run(sprintf("ip rule show | grep -q 'fwmark %s lookup %d'", cfg("mark", "0x1a1"), cfg_int("table", 417))).rc != 0) return false;
	if (run(sprintf("ip route show table %d | grep -q default", cfg_int("table", 417))).rc != 0) return false;
	return true;
}

// ------------------------------------------------------------------ selftest
// Declared before the connect flow on purpose: ucode resolves function symbols
// at compile time, so a call that appears earlier in the file would see null.

function probe_ip(marked) {
	if (marked) {
		run("nft delete table inet vpnexit_probe");
		run("nft add table inet vpnexit_probe");
		run("nft add chain inet vpnexit_probe out '{ type route hook output priority mangle; policy accept; }'");
		run("nft add rule inet vpnexit_probe out ip daddr 1.1.1.1 meta mark set " + cfg("mark", "0x1a1"));
	}
	// Some OpenWrt builds have a uclient-fetch TLS stack that cannot complete
	// the 1.1.1.1 HTTPS probe.  Keep it as the preferred check, but fall back
	// to the plain-HTTP endpoint so health checks still work on BusyBox-only
	// images.  The mark applies to both commands and is removed afterwards.
	let r = run("uclient-fetch -q -O - --timeout=12 " + shellq(PROBE));
	let m = match(r.out, /ip=([0-9.]+)/);
	if (!m) {
		r = run("wget -q -O - --timeout=12 http://icanhazip.com");
		m = match(trim(r.out ?? ""), /^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/);
	}
	if (marked) run("nft delete table inet vpnexit_probe");
	return m ? (m[1] ?? m[0]) : "";
}

function selftest_internal() {
	let st = state_read();
	if (st.state != "connected" && st.state != "connecting") return { ok: false, detail: "tunnel is down" };
	let c = resolve_target(st.conn_id ?? "");
	if (c == null) return { ok: false, detail: "the connected profile is gone" };
	let down_rules = false;
	if (cfg_bool("share_lan", true) && !routing_active()) {
		let rr = routing_apply(st.iface ?? "", st.vip ?? "", st.tproxy ?? 0);
		if (!rr.ok) return { ok: false, detail: rr.error };
		down_rules = true;
	}
	// The proxy path cannot be checked with a marked probe: TPROXY only matches
	// forwarded LAN traffic, so the exit is measured through the local http
	// inbound instead and compared with the same endpoint used directly.
	if (intval(st.tproxy, 0) > 0) {
		let via = http_inbound_ip(8);
		let plain = trim(run("wget -q -O - --timeout=6 http://icanhazip.com").out);
		if (down_rules) routing_clear();
		if (!length(via)) return { ok: false, detail: "no answer through the proxy", direct: plain };
		if (length(plain) && plain == via) return { ok: false, detail: "traffic still leaves through the router uplink", direct: plain };
		return { ok: true, ip: via, direct: plain, detail: "exit verified" };
	}
	let direct = probe_ip(false);
	let marked = probe_ip(true);
	if (down_rules) routing_clear();
	if (!length(marked)) return { ok: false, detail: "no answer through the tunnel", direct: direct };
	if (length(direct) && direct == marked) return { ok: false, detail: "traffic still leaves through the router uplink", direct: direct };
	return { ok: true, ip: marked, direct: direct, detail: "exit verified" };
}

// charon writes the DNS servers it received into /etc/resolv.conf, replacing the
// symlink OpenWrt uses. It also appends "  # by strongSwan" to the address line,
// which makes busybox nslookup and dnsmasq reject the entry - the router then
// resolves nothing while ICMP keeps working. Restore the symlink after every
// connect and on each watchdog tick.
function fix_resolv() {
	let target = "/tmp/resolv.conf.d/resolv.conf.auto";
	if (!fs.stat(target)) return;
	let cur = trim(run("readlink /etc/resolv.conf").out);
	if (length(cur) && index(cur, "resolv.conf.auto") >= 0) return;
	run("ln -sfn " + target + " /etc/resolv.conf");
	run("/etc/init.d/dnsmasq reload");
	log("resolver: restored /etc/resolv.conf -> " + target);
}

// ------------------------------------------------------------ connect flow

function connect_impl(c, verify) {
	let prev = state_read();
	if (length(prev.conn_id ?? "") && prev.conn_id != c.id) {
		let pc = resolve_target(prev.conn_id);
		if (pc != null) {
			log("connect: tearing down the previous tunnel (" + (pc.name ?? pc.type) + ")");
			drv_down(pc);
		}
	}
	routing_clear();
	state_patch({
		state: "connecting", conn_id: c.id, type: c.type, name: c.name ?? "",
		flag: c.flag ?? "", source: c.source ?? "manual", iface: "", vip: "",
		exit_ip: "", error: "", degraded: "", server_ip: "", checked_at: now()
	});
	log(sprintf("connect: %s (%s)", c.name ?? c.id, c.type));

	let prep = drv_prepare(c);
	if (!prep.ok) {
		log("connect: prepare failed: " + prep.error);
		state_patch({ state: "error", error: prep.error, checked_at: now() });
		return { ok: false, error: prep.error };
	}
	let up = drv_up(c);
	if (!up.ok) {
		log("connect: up failed: " + up.error);
		state_patch({ state: "error", error: up.error, checked_at: now() });
		return { ok: false, error: up.error };
	}
	state_patch({
		state: "connected", iface: up.iface ?? "", vip: up.vip ?? "",
		xfrm: up.xfrm ? 1 : 0, tproxy: up.tproxy ? (up.port ?? 0) : 0,
		degraded: up.degraded ?? "", exit_ip: up.exit_ip ?? "",
		server: up.server ?? conn_endpoint(c), server_ip: up.remote ?? "",
		since: now(), misses: 0, attempts: 0, checked_at: now()
	});
	if (length(up.degraded ?? "")) log("connect: warning " + up.degraded);

	let routing = { active: false };
	if (cfg_bool("share_lan", true)) {
		let rr = routing_apply(up.iface ?? "", up.vip ?? "", up.tproxy ? (up.port ?? 0) : 0);
		routing.active = rr.ok;
		if (!rr.ok) log("connect: routing failed: " + rr.error);
	}
	fix_resolv();

	let test = { ok: false, detail: "not tested" };
	if (verify && cfg_bool("share_lan", true)) test = selftest_internal();
	let warn = "";
	if (verify && cfg_bool("share_lan", true) && !test.ok) warn = test.detail ?? "self-test failed";
	state_patch({ exit_ip: test.ip ?? "", error: "", warning: warn, checked_at: now() });
	log(sprintf("connect: up, iface %s, vip %s, exit %s", up.iface ?? "xfrm", up.vip ?? "-", test.ip ?? "-"));
	return { ok: true, iface: up.iface ?? "", vip: up.vip ?? "", exit_ip: test.ip ?? "", warning: warn, routing: routing.active };
}

function disconnect_impl() {
	log("disconnect");
	let st = state_read();
	let c = length(st.conn_id ?? "") ? resolve_target(st.conn_id) : null;
	routing_clear();
	if (c != null) drv_down(c);
	else ike_down();
	fix_resolv();
	state_patch({ state: "idle", conn_id: "", name: "", type: "", flag: "", source: "", server: "", iface: "", vip: "", exit_ip: "", error: "", warning: "", degraded: "", server_ip: "", rx: 0, tx: 0, uptime: 0, checked_at: now() });
	return { ok: true };
}

// --------------------------------------------------------------------- lock
// One connect/disconnect at a time: the panel can be open in two tabs and the
// supervisor may fire at the same moment, which would otherwise race on the
// nftables table and the tunnel.

// The worker PID is stored by the API process ($$ of the spawned shell), so a
// simple SIG 0 test tells us whether an operation is really still running.
function worker_alive() {
	if (!fs.stat(RUN + "/lock")) return false;
	let pid = intval(trim(readfile(RUN + "/lock/pid")), 0);
	if (pid <= 0) return false;
	return run(sprintf("kill -0 %d 2>/dev/null", pid)).rc == 0;
}
function lock_acquire() {
	let dir = RUN + "/lock";
	for (let i = 0; i < 20; i++) {
		if (run("mkdir " + shellq(dir) + " 2>/dev/null").rc == 0) return true;
		// Never wait for a lock whose owner is gone: the web server kills long
		// running requests, which used to leave the directory behind.
		if (worker_alive() != true) { run("rm -rf " + shellq(dir)); continue; }
		sleep(300);
	}
	return false;
}

function lock_release() { run("rm -rf " + shellq(RUN + "/lock")); }



// Connecting can take longer than uhttpd's script timeout, so the API hands the
// work to a detached worker and answers immediately; the panel polls /status.
function start_worker(id) {
	run("rm -rf " + shellq(RUN + "/lock"));
	run("mkdir -p " + shellq(RUN + "/lock"));
	let c = resolve_target(id);
	state_patch({
		state: "connecting", conn_id: id, type: c ? c.type : "", name: c ? (c.name ?? "") : "",
		flag: c ? (c.flag ?? "") : "", iface: "", vip: "", error: "", rx: 0, tx: 0, uptime: 0, checked_at: now()
	});
	let cmd = sprintf("setsid %s %s job-connect %s >/dev/null 2>&1 & echo $!",
		"/usr/bin/ucode", "/usr/share/vpnexit/vpnexit.uc", shellq(id));
	let r = run(cmd);
	let pid = intval(trim(r.out), 0);
	if (pid <= 0) return false;
	fs.writefile(RUN + "/lock/pid", "" + pid);
	return true;
}

function do_connect(id, verify) {
	if (!lock_acquire()) return { ok: false, error: "busy: another operation is running" };
	let r;
	try {
		let c = resolve_target(id);
		if (c == null) r = { ok: false, error: "unknown connection " + id };
		else r = connect_impl(c, verify);
	} catch (e) { r = { ok: false, error: "" + e }; }
	lock_release();
	return r;
}

function do_disconnect() {
	if (!lock_acquire()) return { ok: false, error: "busy: another operation is running" };
	let r;
	try { r = disconnect_impl(); }
	catch (e) { r = { ok: false, error: "" + e }; }
	lock_release();
	return r;
}

// -------------------------------------------------------------------- status

function status_obj() {
	let st = state_read();
	let out = {
		state: st.state ?? "idle",
		conn_id: st.conn_id ?? "",
		type: st.type ?? "",
		type_label: length(st.type ?? "") ? type_label(st.type) : "",
		name: st.name ?? "",
		iface: st.iface ?? "",
		vip: st.vip ?? "",
		exit_ip: st.exit_ip ?? "",
		error: st.error ?? "",
		warning: st.warning ?? "",
		degraded: st.degraded ?? "",
		server: st.server ?? "",
		uptime: intval(st.uptime, 0),
		rx: intval(st.rx, 0),
		tx: intval(st.tx, 0),
		routing: { active: routing_active(), share_lan: cfg_bool("share_lan", true) },
		since: intval(st.since, 0)
	};
	if (st.source == "feed" && length(st.conn_id ?? "")) {
		let p = split(st.conn_id, ":");
		let loc = find_location(p[1] ?? "");
		if (loc != null) {
			out.location = { key: loc.key, title: loc.title, country: loc.country, flag: loc.flag, premium: loc.premium };
			out.server_index = intval(p[2], 0);
		}
	}
	if (out.state == "connected" && !out.routing.active && out.routing.share_lan) out.warning = "routing rules are missing";
	if (out.state == "connected" && !out.routing.share_lan) out.warning = "LAN sharing is disabled in settings";
	return out;
}

function conn_view(c) {
	let st = state_read();
	let active = st.conn_id == c.id;
	let p = active ? drv_probe(c) : { up: false };
	return {
		id: c.id, type: c.type, type_label: type_label(c.type), name: c.name ?? "",
		endpoint: conn_endpoint(c), share_lan: c.share_lan !== false,
		degraded: c.type == "amneziawg" ? wg_degraded(c) : "",
		active: active, up: !!p.up, vip: p.vip ?? "", rx: p.rx ?? 0, tx: p.tx ?? 0,
		created: c.created ?? 0
	};
}

function connections_list() {
	let out = [];
	for (let c in conns_load().items) push(out, conn_view(c));
	return out;
}

// ----------------------------------------------------------------- watchdog

function supervise_once() {
	let st = state_read();

	// A connect/disconnect worker owns the tunnel while it runs.
	if (worker_alive()) return;

	if (st.state == "error") {
		if (!cfg_bool("auto_reconnect", true)) return;
		if (!length(st.conn_id ?? "")) return;
		let wait = cfg_int("retry_seconds", 120);
		if (now() - intval(st.checked_at, 0) < wait) return;
		log("watchdog: retrying after failure");
		let rr = do_connect(st.conn_id, false);
		if (!rr.ok) state_patch({ state: "error", error: rr.error ?? "retry failed", checked_at: now() });
		return;
	}

	if (st.state != "connected" && st.state != "connecting") return;
	let c = resolve_target(st.conn_id ?? "");
	if (c == null) {
		routing_clear();
		state_patch({ state: "error", error: "the connected profile was deleted", checked_at: now() });
		return;
	}

	let p = drv_probe(c);
	if (p.up) {
		fix_resolv();
		let vip = length(p.vip ?? "") ? p.vip : (st.vip ?? "");
		let patch = { state: "connected", vip: vip, iface: p.iface ?? st.iface ?? "", uptime: p.uptime ?? 0, rx: p.rx ?? 0, tx: p.tx ?? 0, checked_at: now(), attempts: 0, misses: 0 };
		if (cfg_bool("share_lan", true) && !routing_active()) {
			let rr = routing_apply(p.iface ?? "", vip, st.tproxy ?? 0);
			if (!rr.ok) log("watchdog: routing restore failed: " + (rr.error ?? "unknown"));
			if (rr.ok) log("watchdog: routing rules restored");
		}
		state_patch(patch);
		return;
	}

	// The tunnel disappeared: either the peer dropped it or the WAN flapped.
	// A single miss can just be a rekey in progress, so require two in a row.
	let misses = intval(st.misses, 0) + 1;
	if (misses < 2) {
		state_patch({ misses: misses, checked_at: now() });
		return;
	}

	let attempts = intval(st.attempts, 0) + 1;
	let max = cfg_int("reconnect_attempts", 5);
	log(sprintf("watchdog: tunnel lost (attempt %d/%d)", attempts, max));
	routing_clear();

	if (!cfg_bool("auto_reconnect", true) || attempts > max) {
		state_patch({ state: "error", error: "tunnel lost", attempts: attempts, checked_at: now(), vip: "", rx: 0, tx: 0 });
		return;
	}

	state_patch({ state: "connecting", attempts: attempts, misses: 0, checked_at: now() });
	let r = do_connect(st.conn_id, false);
	if (!r.ok) state_patch({ state: "error", error: r.error ?? "reconnect failed", attempts: attempts, checked_at: now() });
}

function supervise() {
	ensure_dir(RUN);
	ensure_dir(DATA);
	ensure_dir(CHAINS);
	ensure_dir(RUNDIR);
	let st = state_read();
	if (st.state == "connecting") state_patch({ state: "idle" });
	log("supervisor started");
	let last_refresh_check = 0;
	while (true) {
		let hours = cfg_int("refresh_hours", 24);
		if (hours > 0 && now() - last_refresh_check > 600) {
			last_refresh_check = now();
			let meta = locations_load();
			if (now() - intval(meta.fetched_at, 0) > hours * 3600) {
				let r = refresh();
				if (!r.ok) log("refresh failed: " + (r.error ?? "?"));
			}
		}
		try {
			supervise_once();
		} catch (e) {
			log("watchdog error: " + e);
		}
		sleep(cfg_int("watchdog_seconds", 20) * 1000);
	}
}

// ------------------------------------------------------------ dependencies

function deps_install() {
	let m = missing_packages();
	if (!length(m.packages)) return { ok: true, installed: [], note: "everything is already installed" };
	let r = run("sh /usr/share/vpnexit/install-deps.sh " + join(" ", m.types));
	let after = caps();
	let still = [];
	for (let t in missing_packages().types) push(still, t);
	return {
		ok: length(still) == 0,
		installed: m.packages,
		missing_types: still,
		caps: after,
		log: clean(r.out)
	};
}

// -------------------------------------------------------------- manual test
// "Test" brings the profile up, verifies the exit, then puts the previous
// tunnel back.  It is the only call that connects and disconnects inside one
// request, and it is therefore limited to the admin API.

function test_impl(id) {
	let prev = state_read();
	let c = resolve_target(id);
	if (c == null) return { ok: false, error: "unknown connection " + id };
	if (!lock_acquire()) return { ok: false, error: "busy: another operation is running" };
	let res;
	try {
		let conn = connect_impl(c, true);
		if (!conn.ok) res = { ok: false, error: conn.error };
		else {
			let t = selftest_internal();
			res = {
				ok: t.ok, exit_ip: t.ip ?? "", direct_ip: t.direct ?? "",
				detail: t.detail ?? "", vip: conn.vip, iface: conn.iface,
				degraded: conn.degraded ?? ""
			};
		}
		// Always leave the box as it was before the test.
		disconnect_impl();
		if (length(prev.conn_id ?? "") && prev.conn_id != id && prev.state == "connected") {
			let pc = resolve_target(prev.conn_id);
			if (pc != null) connect_impl(pc, false);
		}
	} catch (e) { res = { ok: false, error: "" + e }; }
	lock_release();
	return res;
}

// ------------------------------------------------------------------- HTTP API

function jbody() {
	let raw = fs.stdin.read("all") ?? "";
	if (!length(trim(raw))) return {};
	try {
		let d = json(raw);
		if (type(d) == "object" && d != null) return d;
	} catch (e) { }
	return {};
}

function respond(obj, code) {
	if (code && code != 200) print(sprintf("Status: %d %s\r\n", code, code == 401 ? "Unauthorized" : "Error"));
	print("Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n");
	print(sprintf("%J", obj));
}

function conn_from_body(b) {
	let t = trim("" + (b.type ?? ""));
	let found = false;
	for (let x in TYPES) if (x == t) found = true;
	if (!found) return { error: "unknown protocol " + t };
	let cfg = {};
	if (type(b.config) == "object" && b.config != null) {
		for (let k in b.config) {
			let v = b.config[k];
			if (type(v) == "string" || type(v) == "int" || type(v) == "bool" || type(v) == "double")
				cfg[k] = "" + v;
		}
	}
	// Raw payloads get their own normalisation so a pasted file is usable as is.
	if (t == "vless" && length(cfg.raw ?? "")) {
		let v = vless_parse(cfg.raw);
		if (length(v.error ?? "")) return { error: v.error };
		cfg.host = v.host; cfg.port = "" + v.port; cfg.uuid = v.uuid;
	}
	if (t == "wireguard" || t == "amneziawg") {
		let p = wg_parse(cfg.raw ?? "");
		if (length(p.error)) return { error: p.error };
		cfg.endpoint = p.peers[0] ? (p.peers[0].endpoint ?? "") : "";
	}
	if (t == "openvpn") {
		if (!length(trim(cfg.raw ?? ""))) return { error: "paste the .ovpn file contents" };
		cfg.endpoint = ovpn_summary(cfg.raw).remote;
	}
	let name = trim("" + (b.name ?? ""));
	if (!length(name)) name = type_label(t) + " connection";
	return {
		id: trim("" + (b.id ?? "")),
		type: t,
		name: name,
		config: cfg,
		share_lan: b.share_lan == null ? true : boolval(b.share_lan, true)
	};
}

function api() {
	let path = getenv("PATH_INFO") ?? "";
	let method = getenv("REQUEST_METHOD") ?? "GET";
	path = replace(path, /^\/+/, "");
	if (index(path, "api/") == 0) path = substr(path, 4);
	path = replace(path, /\/+$/, "");

	if (path == "health") {
		respond({ ok: true, service: "vpnexit", version: settings_obj().version, state: (state_read().state ?? "idle") });
		return;
	}

	// uhttpd does not forward arbitrary request headers to CGI scripts, so the
	// token is accepted from a cookie (panel), the query string (curl) or the
	// X-Auth-Token header when another web server sits in front.
	let token = getenv("HTTP_X_AUTH_TOKEN") ?? "";
	if (!length(token)) {
		let m = match(getenv("HTTP_COOKIE") ?? "", /(^|;[ \t]*)vpnexit=([^;]+)/);
		if (m) token = urldecode(m[2]);
	}
	if (!length(token)) {
		let m = match(getenv("QUERY_STRING") ?? "", /(^|&)t=([^&]+)/);
		if (m) token = urldecode(m[2]);
	}
	let expected = cfg("token", "");
	if (!length(expected) || length(token) != length(expected) || token != expected) {
		respond({ ok: false, error: "unauthorized" }, 401);
		return;
	}

	// The backend lives outside the web root, so it cannot be opened directly;
	// this endpoint exposes it for inspection (and for `raw=1` downloads).
	if (path == "source" && method == "GET") {
		let file = "/usr/share/vpnexit/vpnexit.uc";
		let text = readfile(file);
		if (!length(text)) { respond({ ok: false, error: "source not found" }, 404); return; }
		if (index(getenv("QUERY_STRING") ?? "", "raw=1") >= 0) {
			print("Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\n");
			print(text);
			return;
		}
		respond({ ok: true, path: file, bytes: length(text), text: text });
		return;
	}
	if (path == "status" && method == "GET") { respond({ ok: true, status: status_obj() }); return; }
	if (path == "caps" && method == "GET") {
		respond({ ok: true, caps: caps(), missing: missing_packages(), types: TYPES });
		return;
	}
	if (path == "connections" && method == "GET") {
		respond({ ok: true, items: connections_list(), active: state_read().conn_id ?? "" });
		return;
	}
	if (path == "locations" && method == "GET") {
		let q = getenv("QUERY_STRING") ?? "";
		if (index(q, "refresh=1") >= 0) {
			let r = refresh();
			if (!r.ok) { respond({ ok: false, error: r.error }); return; }
		}
		let d = locations_load();
		respond({ ok: true, items: d.items, count: d.count, fetched_at: d.fetched_at });
		return;
	}
	if (path == "log") {
		let q = getenv("QUERY_STRING") ?? "";
		let n = 120;
		let m = match(q, /lines=([0-9]+)/);
		if (m) n = intval(m[1], 120);
		let r = run(sprintf("tail -n %d %s", n, shellq(LOGFILE)));
		respond({ ok: true, text: r.out });
		return;
	}
	if (path == "settings") {
		if (method == "GET") { respond({ ok: true, settings: settings_obj() }); return; }
		let b = jbody();
		if (b.share_lan != null) cfg_set("share_lan", b.share_lan ? "1" : "0");
		if (b.block_ipv6 != null) cfg_set("block_ipv6", b.block_ipv6 ? "1" : "0");
		if (b.auto_reconnect != null) cfg_set("auto_reconnect", b.auto_reconnect ? "1" : "0");
		if (b.tunnel_mtu != null) {
			let mtu = intval(b.tunnel_mtu, 1400);
			if (mtu < 1200) mtu = 1200;
			if (mtu > 1420) mtu = 1420;
			cfg_set("tunnel_mtu", mtu);
		}
		if (b.feed_url != null && length(trim("" + b.feed_url))) cfg_set("feed_url", trim("" + b.feed_url));
		if (b.token != null && length(trim("" + b.token)) >= 8) cfg_set("token", trim("" + b.token));
		// Re-apply routing so MTU / IPv6 changes take effect immediately.
		let st = state_read();
		if (st.state == "connected" && cfg_bool("share_lan", true)) routing_apply(st.iface ?? "", st.vip ?? "", st.tproxy ?? 0);
		if (st.state == "connected" && !cfg_bool("share_lan", true)) routing_clear();
		respond({ ok: true, settings: settings_obj() });
		return;
	}
	if (path == "connections-save" && method == "POST") {
		let b = jbody();
		let c = conn_from_body(b);
		if (length(c.error ?? "")) { respond({ ok: false, error: c.error }); return; }
		let doc = conns_load();
		let existing = null;
		if (length(c.id)) existing = find_conn(c.id);
		if (existing == null) {
			c.id = new_id();
			c.created = now();
			// Keep order stable: newest last, the panel sorts on its own.
			push(doc.items, c);
		} else {
			c.created = existing.created ?? now();
			let items = [];
			for (let it in doc.items) push(items, it.id == c.id ? c : it);
			doc.items = items;
		}
		conns_save(doc);
		let prep = drv_prepare(c);
		log(sprintf("save: %s (%s) %s", c.name, c.type, prep.ok ? "ok" : "invalid: " + prep.error));
		respond({ ok: true, item: conn_view(c), valid: prep.ok, error: prep.ok ? "" : prep.error });
		return;
	}
	if (path == "connections-delete" && method == "POST") {
		let b = jbody();
		let id = trim("" + (b.id ?? ""));
		let doc = conns_load();
		let keep = [], victim = null;
		for (let it in doc.items) { if (it.id == id) victim = it; else push(keep, it); }
		if (victim == null) { respond({ ok: false, error: "unknown connection" }); return; }
		let st = state_read();
		if (st.conn_id == id) disconnect_impl();
		doc.items = keep;
		conns_save(doc);
		log("delete: " + (victim.name ?? id));
		respond({ ok: true });
		return;
	}
	if (path == "connection-connect" && method == "POST") {
		let b = jbody();
		let id = trim("" + (b.id ?? ""));
		if (!length(id)) { respond({ ok: false, error: "missing id" }); return; }
		if (resolve_target(id) == null) { respond({ ok: false, error: "unknown connection " + id }); return; }
		if (worker_alive()) { respond({ ok: false, error: "busy: a connection attempt is already running" }); return; }
		if (!start_worker(id)) { respond({ ok: false, error: "cannot start the connect worker" }); return; }
		respond({ ok: true, async: true, id: id, state: "connecting" });
		return;
	}
	if (path == "connection-test" && method == "POST") {
		let b = jbody();
		let id = trim("" + (b.id ?? ""));
		if (!length(id)) { respond({ ok: false, error: "missing id" }); return; }
		let r = test_impl(id);
		respond(r);
		return;
	}
	if (path == "connect" && method == "POST") {
		// legacy endpoint used by the feed list
		let b = jbody();
		let key = trim("" + (b.key ?? ""));
		if (!length(key)) { respond({ ok: false, error: "missing key" }); return; }
		let loc = find_location(key);
		if (loc == null) { respond({ ok: false, error: "unknown location " + key }); return; }
		let idx = intval(b.index, 0);
		if (idx < 0 || idx >= length(loc.servers)) idx = 0;
		if (worker_alive()) { respond({ ok: false, error: "busy: a connection attempt is already running" }); return; }
		if (!start_worker("loc:" + key + ":" + idx)) { respond({ ok: false, error: "cannot start the connect worker" }); return; }
		respond({ ok: true, async: true, key: key, index: idx, state: "connecting" });
		return;
	}
	if (path == "disconnect" && method == "POST") { respond(do_disconnect()); return; }
	if (path == "refresh" && method == "POST") {
		let r = refresh();
		if (!r.ok) { respond({ ok: false, error: r.error }); return; }
		respond({ ok: true, count: r.count, skipped: r.skipped, fetched_at: r.fetched_at });
		return;
	}
	if (path == "selftest" && method == "POST") {
		let r = selftest_internal();
		if (r.ok) state_patch({ exit_ip: r.ip, checked_at: now() });
		respond({ ok: r.ok, result: r });
		return;
	}
	if (path == "deps-install" && method == "POST") { respond(deps_install()); return; }
	respond({ ok: false, error: "unknown endpoint: " + path }, 404);
}

// ---------------------------------------------------------------------- CLI

function main() {
	ensure_dir(RUN);
	ensure_dir(DATA);
	ensure_dir(RUNDIR);
	let argv = ARGV ?? [];
	let cmd = argv[0] ?? "status";

	if (cmd == "api") { api(); return; }
	if (cmd == "supervise") { supervise(); return; }
	if (cmd == "refresh") { print(sprintf("%J", refresh()) + "\n"); return; }
	if (cmd == "relay-test") {
		let out = RUN + "/relay.json";
		let r = relay_fetch(cfg("feed_url", ""), out);
		print(sprintf("%J", { rc: r.rc, note: r.out, bytes: length(readfile(out)) }) + "\n");
		return;
	}
	if (cmd == "status") {
		let st = state_read();
		let c = length(st.conn_id ?? "") ? resolve_target(st.conn_id) : null;
		if (c != null && (st.state == "connected" || st.state == "connecting")) {
			let p = drv_probe(c);
			state_patch({ uptime: p.uptime ?? 0, rx: p.rx ?? 0, tx: p.tx ?? 0, vip: length(p.vip ?? "") ? p.vip : (st.vip ?? ""), iface: p.iface ?? st.iface ?? "" });
		}
		print(sprintf("%J", status_obj()) + "\n");
		return;
	}
	if (cmd == "locations") {
		let d = locations_load();
		print(sprintf("%J", { count: d.count, fetched_at: d.fetched_at, items: d.items }) + "\n");
		return;
	}
	if (cmd == "connections") { print(sprintf("%J", connections_list()) + "\n"); return; }
	if (cmd == "conn-save") {
		// Scripted provisioning: vpnexit conn-save /tmp/conn.json
		let file = argv[1] ?? "";
		let body = {};
		try { body = json(readfile(file)); } catch (e) { print(sprintf("%J", { ok: false, error: "cannot read " + file }) + "\n"); return; }
		let c = conn_from_body(body ?? {});
		if (length(c.error ?? "")) { print(sprintf("%J", { ok: false, error: c.error }) + "\n"); return; }
		let doc = conns_load();
		let existing = length(c.id) ? find_conn(c.id) : null;
		if (existing == null) { c.id = new_id(); c.created = now(); push(doc.items, c); }
		else {
			c.created = existing.created ?? now();
			let items = [];
			for (let it in doc.items) push(items, it.id == c.id ? c : it);
			doc.items = items;
		}
		conns_save(doc);
		let prep = drv_prepare(c);
		print(sprintf("%J", { ok: true, id: c.id, valid: prep.ok, error: prep.ok ? "" : prep.error }) + "\n");
		return;
	}
	if (cmd == "conn-delete") {
		let id = argv[1] ?? "";
		let doc = conns_load();
		let keep = [];
		for (let it in doc.items) if (it.id != id) push(keep, it);
		doc.items = keep;
		conns_save(doc);
		print(sprintf("%J", { ok: true, id: id }) + "\n");
		return;
	}
	if (cmd == "connect") {
		let id = argv[1] ?? "";
		if (!length(id)) { print("usage: vpnexit connect <connection-id|loc:key:index> [--no-verify]\n"); return; }
		print(sprintf("%J", do_connect(id, !(argv[2] == "--no-verify"))) + "\n");
		return;
	}
	if (cmd == "job-connect") {
		// Detached worker started by the panel: owns the lock until it is done.
		let id = argv[1] ?? "";
		let r = { ok: false, error: "no id" };
		if (length(id)) {
			try {
				let c = resolve_target(id);
				if (c == null) r = { ok: false, error: "unknown connection " + id };
				else r = connect_impl(c, true);
			} catch (e) { r = { ok: false, error: "" + e }; }
		}
		lock_release();
		return;
	}
	if (cmd == "test") {
		let id = argv[1] ?? "";
		print(sprintf("%J", test_impl(id)) + "\n");
		return;
	}
	if (cmd == "disconnect") { print(sprintf("%J", do_disconnect()) + "\n"); return; }
	if (cmd == "selftest") { print(sprintf("%J", selftest_internal()) + "\n"); return; }
	if (cmd == "token") { print(cfg("token", "") + "\n"); return; }
	if (cmd == "routing") { print(sprintf("%J", { active: routing_active() }) + "\n"); return; }
	if (cmd == "caps") { print(sprintf("%J", { caps: caps(), missing: missing_packages() }) + "\n"); return; }
	print("vpnexit: unknown command " + cmd + "\n");
}

main();
