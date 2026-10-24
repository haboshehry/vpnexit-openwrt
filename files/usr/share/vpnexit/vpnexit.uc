#!/usr/bin/ucode
// vpnexit - IKEv2 exit switcher and LAN sharing controller for OpenWrt.
//
// The daemon side is deliberately small: it renders swanctl configuration,
// starts/tears down one CHILD_SA and installs a handful of nftables/ip rules.
// It never touches the system default route, so the router itself keeps using
// its own uplink while LAN clients are steered through the tunnel.

const fs = require("fs");
const uci = require("uci");

const DATA = "/etc/vpnexit";
const RUN = "/var/run/vpnexit";
const LOGFILE = RUN + "/log";
const STATE = RUN + "/state.json";
const LOCS = DATA + "/locations.json";
const CHAINS = DATA + "/chains";
const SWANCTL_CONF = "/etc/swanctl/conf.d/vpnexit.conf";
const SWANCTL_SECRETS = "/etc/swanctl/conf.d/vpnexit-secrets.conf";
const CONN = "vpnexit";
const CHILD = "vpnexit";
const PROBE = "https://1.1.1.1/cdn-cgi/trace";

// ---------------------------------------------------------------- utilities

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
	let r = run("ip -4 -o addr show dev " + shellq(dev));
	let m = match(r.out, /inet\s+([0-9.]+\/[0-9]+)/);
	return m ? m[1] : "";
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

function refresh() {
	let url = cfg("feed_url", "");
	if (!length(url)) return { ok: false, error: "no feed url configured" };
	ensure_dir(RUN);
	let tmp = RUN + "/feed.json";
	let r = run(sprintf("uclient-fetch -q -O %s --timeout=25 %s", shellq(tmp), shellq(url)));
	if (r.rc != 0) {
		log(sprintf("refresh: fetch failed (%d) %s", r.rc, trim(r.out)));
		return { ok: false, error: "feed download failed" };
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
	let blocks = [], tail = "";
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

function conn_text(srv) {
	let addr = length(srv.ip) ? srv.ip : srv.host;
	let ident = length(srv.local_id) ? srv.local_id : srv.user;
	let lines = [
		"# Managed by vpnexit - regenerated on every switch.",
		"connections {",
		"  " + CONN + " {",
		"    version = 2",
		"    local_addrs = %any",
		"    remote_addrs = " + addr,
		"    proposals = " + IKE_PROPOSALS,
		"    local {",
		"      auth = eap-mschapv2",
		"      id = " + ident,
		"      eap_id = " + srv.user,
		"    }",
		"    remote {",
		"      auth = pubkey",
		"      id = " + srv.host,
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
	return join("\n", lines);
}

function secrets_text(srv) {
	let esc = replace("" + (srv.pass ?? ""), /[\\"]/g, function (m) { return "\\" + m; });
	let lines = ["secrets {", "  eap-" + CONN + " {"];
	push(lines, "    id = " + (length(srv.local_id) ? srv.local_id : srv.user));
	push(lines, "    secret = \"" + esc + "\"");
	if (length(srv.local_id) && srv.local_id != srv.user) {
		push(lines, "  }");
		push(lines, "  eap-" + CONN + "2 {");
		push(lines, "    id = " + srv.user);
		push(lines, "    secret = \"" + esc + "\"");
	}
	push(lines, "  }");
	push(lines, "}");
	return join("\n", lines) + "\n";
}

function write_conn(srv) {
	ensure_dir("/etc/swanctl/conf.d");
	writefile(SWANCTL_CONF, conn_text(srv), "0644");
	writefile(SWANCTL_SECRETS, secrets_text(srv), "0600");
}

function clear_conn_files() {
	if (fs.stat(SWANCTL_CONF)) fs.unlink(SWANCTL_CONF);
	if (fs.stat(SWANCTL_SECRETS)) fs.unlink(SWANCTL_SECRETS);
}

// ---------------------------------------------------------------- routing

function table_exists(spec) {
	return run("nft list table " + spec).rc == 0;
}

function routing_ruleset(vip, lan, wan, gw, server_ip, block_v6) {
	let mark = cfg("mark", "0x1a1");
	let mtu = cfg_int("tunnel_mtu", 1400);
	let mss = mtu - 40;
	let lan_cidr = mask4(iface_cidr(lan)) ?? "192.168.1.0/24";
	let wan_cidr = mask4(iface_cidr(wan)) ?? "";
	let excl = ["127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", lan_cidr, vip + "/32"];
	if (length(wan_cidr)) push(excl, wan_cidr);
	if (length(server_ip)) push(excl, server_ip + "/32");

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
	push(t, sprintf("\t\tiifname != \"%s\" return", lan));
	push(t, "\t\tip daddr @exclude4 return");
	push(t, sprintf("\t\tmeta mark set %s counter", mark));
	push(t, "\t}");
	push(t, "\tchain vpx_mss {");
	push(t, "\t\ttype filter hook postrouting priority mangle; policy accept;");
	push(t, sprintf("\t\tmeta mark %s tcp flags syn tcp option maxseg size set %d", mark, mss));
	push(t, "\t}");
	if (block_v6) {
		push(t, "\tchain vpx_v6 {");
		push(t, "\t\ttype filter hook forward priority filter; policy accept;");
		push(t, sprintf("\t\tiifname \"%s\" oifname \"%s\" meta nfproto ipv6 drop", lan, wan));
		push(t, "\t}");
	}
	push(t, "}");
	push(t, "table ip vpnexit_nat {");
	push(t, "\tchain vpx_nat {");
	push(t, "\t\ttype nat hook postrouting priority srcnat; policy accept;");
	push(t, sprintf("\t\toifname \"%s\" meta mark %s counter snat ip to %s", wan, mark, vip));
	push(t, "\t}");
	push(t, "}");
	return join("\n", t) + "\n";
}

function routing_apply(vip) {
	if (!length(vip)) return { ok: false, error: "tunnel has no address yet" };
	let lan = lan_iface();
	let dr = default_route();
	if (!dr.dev) return { ok: false, error: "cannot determine the WAN interface" };
	let server = state_read().server_ip ?? "";
	let block_v6 = cfg_bool("block_ipv6", true);
	let rules = routing_ruleset(vip, lan, dr.dev, dr.gw, server, block_v6);
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

	let table = cfg_int("table", 417);
	let prio = cfg_int("rule_priority", 1000);
	let mark = cfg("mark", "0x1a1");
	let route = length(dr.gw)
		? sprintf("ip route replace default via %s dev %s table %d", dr.gw, dr.dev, table)
		: sprintf("ip route replace default dev %s table %d", dr.dev, table);
	let rr = run(route);
	if (rr.rc != 0) {
		log("routing: cannot add table route: " + clean(rr.out));
		return { ok: false, error: "cannot add route: " + clean(rr.out) };
	}
	for (let i = 0; i < 4; i++)
		run(sprintf("ip rule del fwmark %s lookup %d priority %d", mark, table, prio));
	let ar = run(sprintf("ip rule add fwmark %s lookup %d priority %d", mark, table, prio));
	if (ar.rc != 0) return { ok: false, error: "cannot add ip rule: " + clean(ar.out) };
	log(sprintf("routing: active (%s -> %s via %s, vip %s)", lan, dr.dev, dr.gw ?? "-", vip));
	return { ok: true, vip: vip };
}

function routing_clear() {
	let table = cfg_int("table", 417);
	let prio = cfg_int("rule_priority", 1000);
	let mark = cfg("mark", "0x1a1");
	run("nft delete table inet vpnexit");
	run("nft delete table ip vpnexit_nat");
	run("nft delete table inet vpnexit_probe");
	for (let i = 0; i < 4; i++)
		run(sprintf("ip rule del fwmark %s lookup %d priority %d", mark, table, prio));
	run(sprintf("ip route flush table %d", table));
}

function routing_active(vip) {
	if (!length(vip)) return false;
	if (!table_exists("inet vpnexit")) return false;
	if (run(sprintf("ip rule show | grep -q 'fwmark %s lookup %d'", cfg("mark", "0x1a1"), cfg_int("table", 417))).rc != 0) return false;
	if (run(sprintf("ip route show table %d | grep -q default", cfg_int("table", 417))).rc != 0) return false;
	return true;
}

// ------------------------------------------------------------ connect flow

// ------------------------------------------------------------------ selftest
// Declared before do_connect() on purpose: ucode resolves function symbols at
// compile time, so a call that appears earlier in the file would see null.

function probe_ip(marked) {
	if (marked) {
		run("nft delete table inet vpnexit_probe");
		run("nft add table inet vpnexit_probe");
		run("nft add chain inet vpnexit_probe out '{ type route hook output priority mangle; policy accept; }'");
		run("nft add rule inet vpnexit_probe out ip daddr 1.1.1.1 meta mark set " + cfg("mark", "0x1a1"));
	}
	let r = run("uclient-fetch -q -O - --timeout=12 " + shellq(PROBE));
	if (marked) run("nft delete table inet vpnexit_probe");
	let m = match(r.out, /ip=([0-9.]+)/);
	return m ? m[1] : "";
}

function selftest_internal() {
	let st = state_read();
	if (!length(st.vip ?? "")) return { ok: false, detail: "tunnel is down" };
	let temporary = false;
	if (!routing_active(st.vip)) {
		let rr = routing_apply(st.vip);
		if (!rr.ok) return { ok: false, detail: rr.error };
		temporary = true;
	}
	let direct = probe_ip(false);
	let marked = probe_ip(true);
	if (temporary) routing_clear();
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

function wait_child(seconds) {
	for (let i = 0; i < seconds; i++) {
		let s = sas_parse();
		if (s.child && length(s.vip)) return s;
		sleep(1000);
	}
	return sas_parse();
}

function teardown(keep_state) {
	routing_clear();
	run("swanctl --terminate --ike " + CONN);
	// Give charon time to delete the SAD/policies before anything reconnects.
	for (let i = 0; i < 6; i++) {
		let q = sas_parse();
		if (!q.ike && !q.child) break;
		sleep(500);
	}
}

function connect_impl(key, index, verify) {
	let loc = find_location(key);
	if (!loc) return { ok: false, error: "unknown location " + key };
	let idx = intval(index, 0);
	if (idx < 0 || idx >= length(loc.servers)) idx = 0;
	let srv = loc.servers[idx];
	if (!length(srv.user) || !length(srv.pass)) return { ok: false, error: "profile has no credentials" };

	log(sprintf("connect: %s (%s)", key, srv.host));
	state_patch({ state: "connecting", key: key, index: idx, error: "", exit_ip: "", server_host: srv.host, checked_at: now() });

	learn_chain(srv.host);
	write_conn(srv);
	run("swanctl --load-creds");
	let lc = run("swanctl --load-conns");
	if (lc.rc != 0) {
		let msg = clean(lc.out);
		log("connect: cannot load connection: " + msg);
		state_patch({ state: "error", error: "cannot load connection" });
		return { ok: false, error: msg };
	}

	run("swanctl --terminate --ike " + CONN);
	routing_clear();

	// charon needs a moment to tear down the previous SA; initiating while it is
	// still deleting produces "existing duplicate CHILD_SA" and the whole
	// connect would be reported as failed.
	for (let i = 0; i < 10; i++) {
		let q = sas_parse();
		if (!q.ike && !q.child) break;
		sleep(500);
	}

	let r = run("swanctl --initiate --child " + CHILD + " --timeout 30");
	let s = wait_child(12);
	if (!s.child || !length(s.vip)) {
		// One controlled retry: peers occasionally reject the first attempt while
		// the previous SA is still expiring on their side.
		run("swanctl --terminate --ike " + CONN);
		sleep(2000);
		r = run("swanctl --initiate --child " + CHILD + " --timeout 30");
		s = wait_child(12);
	}
	if (!s.child || !length(s.vip)) {
		let msg = clean(r.out);
		let m = match(msg, /\n[^\n]*(failed|error|no trusted|unable)[^\n]*/);
		log("connect: handshake failed: " + msg);
		run("swanctl --terminate --ike " + CONN);
		state_patch({ state: "error", error: (m ? trim(m[0]) : "handshake failed") });
		return { ok: false, error: "handshake failed: " + (m ? trim(m[0]) : "no CHILD_SA") };
	}

	state_patch({ vip: s.vip, server_ip: s.remote, since: now(), checked_at: now() });
	let routing = { active: false };
	if (cfg_bool("share_lan", true)) {
		let rr = routing_apply(s.vip);
		routing.active = rr.ok;
		if (!rr.ok) log("connect: routing failed: " + rr.error);
	}

	let test = { ok: false, detail: "not tested" };
	if (verify) test = selftest_internal();

	let err = "";
	if (verify && !test.ok) err = test.detail ?? "self-test failed";
	state_patch({
		state: "connected", exit_ip: test.ip ?? "", error: err,
		attempts: 0, checked_at: now(), vip: s.vip
	});
	fix_resolv();
	log(sprintf("connect: up, vip %s, exit %s", s.vip, test.ip ?? "-"));
	return { ok: true, vip: s.vip, exit_ip: test.ip ?? "", warning: err };
}

function disconnect_impl() {
	log("disconnect");
	teardown();
	fix_resolv();
	clear_conn_files();
	state_patch({ state: "idle", vip: "", exit_ip: "", error: "", checked_at: now() });
	return { ok: true };
}

// --------------------------------------------------------------------- lock
// One connect/disconnect at a time: the panel can be open in two tabs and the
// supervisor may fire at the same moment, which would otherwise race on the
// nftables table and the swanctl connection.

function lock_acquire() {
	let dir = RUN + "/lock";
	for (let i = 0; i < 40; i++) {
		if (run("mkdir " + shellq(dir) + " 2>/dev/null").rc == 0) return true;
		let st = fs.stat(dir);
		if (st && (now() - st.mtime) > 180) { run("rmdir " + shellq(dir) + " 2>/dev/null"); continue; }
		sleep(500);
	}
	return false;
}

function lock_release() { run("rmdir " + shellq(RUN + "/lock") + " 2>/dev/null"); }

function do_connect(key, index, verify) {
	if (!lock_acquire()) return { ok: false, error: "busy: another operation is running" };
	let r;
	try { r = connect_impl(key, index, verify); }
	catch (e) { r = { ok: false, error: "" + e }; }
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
		vip: st.vip ?? "",
		exit_ip: st.exit_ip ?? "",
		error: st.error ?? "",
		warning: "",
		uptime: intval(st.uptime, 0),
		rx: intval(st.rx, 0),
		tx: intval(st.tx, 0),
		routing: { active: routing_active(st.vip ?? ""), share_lan: cfg_bool("share_lan", true) },
		since: intval(st.since, 0)
	};
	let loc = st.key ? find_location(st.key) : null;
	if (loc != null) {
		out.location = { key: loc.key, title: loc.title, country: loc.country, flag: loc.flag, premium: loc.premium };
	}
	if (length(st.server_host ?? "")) out.server = { host: st.server_host, index: intval(st.index, 0) };
	if (out.state == "connected" && !out.routing.active && out.routing.share_lan) {
		out.warning = "routing rules are missing";
	}
	if (out.state == "connected" && !out.routing.share_lan) {
		out.warning = "LAN sharing is disabled in settings";
	}
	return out;
}

// ----------------------------------------------------------------- watchdog

function supervise_once() {
	let st = state_read();
	if (st.state != "connected" && st.state != "connecting") return;

	let s = sas_parse();
	if (s.child) {
		fix_resolv();
		let vip = length(s.vip) ? s.vip : (st.vip ?? "");
		let patch = { state: "connected", vip: vip, uptime: s.uptime, rx: s.rx, tx: s.tx, checked_at: now(), attempts: 0 };
		if (cfg_bool("share_lan", true) && length(vip) && !routing_active(vip)) {
			let rr = routing_apply(vip);
			patch.routing_ok = rr.ok;
			if (rr.ok) log("watchdog: routing rules restored");
		}
		state_patch(patch);
		return;
	}

	// The child disappeared: either the peer dropped it or the WAN flapped.
	let attempts = intval(st.attempts, 0) + 1;
	let max = cfg_int("reconnect_attempts", 5);
	log(sprintf("watchdog: tunnel lost (attempt %d/%d)", attempts, max));
	routing_clear();
	run("swanctl --terminate --ike " + CONN);

	if (!cfg_bool("auto_reconnect", true) || attempts > max) {
		state_patch({ state: "error", error: "tunnel lost", attempts: attempts, checked_at: now(), vip: "", rx: 0, tx: 0 });
		return;
	}

	state_patch({ state: "connecting", attempts: attempts, checked_at: now() });
	let r = do_connect(st.key, intval(st.index, 0), false);
	if (!r.ok) state_patch({ state: "error", error: r.error ?? "reconnect failed", attempts: attempts });
}

function supervise() {
	ensure_dir(RUN);
	ensure_dir(DATA);
	ensure_dir(CHAINS);
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

// ---------------------------------------------------------------------- API

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
		if (st.state == "connected" && length(st.vip ?? "") && cfg_bool("share_lan", true)) routing_apply(st.vip);
		if (st.state == "connected" && !cfg_bool("share_lan", true)) routing_clear();
		respond({ ok: true, settings: settings_obj() });
		return;
	}
	if (path == "connect" && method == "POST") {
		let b = jbody();
		let key = trim("" + (b.key ?? ""));
		if (!length(key)) { respond({ ok: false, error: "missing key" }); return; }
		let r = do_connect(key, intval(b.index, 0), true);
		respond(r);
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
	respond({ ok: false, error: "unknown endpoint: " + path }, 404);
}

// -------------------------------------------------------------------- entry

function main() {
	ensure_dir(RUN);
	ensure_dir(DATA);
	let argv = ARGV ?? [];
	let cmd = argv[0] ?? "status";

	if (cmd == "api") { api(); return; }
	if (cmd == "supervise") { supervise(); return; }
	if (cmd == "refresh") { print(sprintf("%J", refresh()) + "\n"); return; }
	if (cmd == "status") {
		let st = state_read();
		let s = sas_parse();
		if (st.state == "connected" || st.state == "connecting") {
			state_patch({ uptime: s.uptime, rx: s.rx, tx: s.tx, vip: length(s.vip) ? s.vip : (st.vip ?? ""), checked_at: now() });
		}
		print(sprintf("%J", status_obj()) + "\n");
		return;
	}
	if (cmd == "locations") {
		let d = locations_load();
		print(sprintf("%J", { count: d.count, fetched_at: d.fetched_at, items: d.items }) + "\n");
		return;
	}
	if (cmd == "connect") {
		let key = argv[1] ?? "";
		if (!length(key)) { print("usage: vpnexit connect <key> [index]\n"); return; }
		print(sprintf("%J", do_connect(key, intval(argv[2], 0), true)) + "\n");
		return;
	}
	if (cmd == "disconnect") { print(sprintf("%J", do_disconnect()) + "\n"); return; }
	if (cmd == "selftest") { print(sprintf("%J", selftest_internal()) + "\n"); return; }
	if (cmd == "token") { print(cfg("token", "") + "\n"); return; }
	if (cmd == "routing") { print(sprintf("%J", { active: routing_active(state_read().vip ?? "") }) + "\n"); return; }
	print("vpnexit: unknown command " + cmd + "\n");
}

main();
