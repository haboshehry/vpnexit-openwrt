/* vpnexit panel - no framework, no external assets */
(function () {
  "use strict";

  var API = "/cgi-bin/vpnexit/api/";
  var LS_TOKEN = "vpnexit.token";
  var LS_LANG = "vpnexit.lang";

  var T = {
    en: {
      tab_manual: "Connections", tab_feed: "Exit feed", tab_settings: "Settings",
      add: "Add connection", save: "Save", cancel: "Cancel", refresh: "Refresh",
      no_conn: "No connections yet.", feed_empty: "No locations loaded.",
      manual_hint: "Add a profile for each VPN you use, connect it, then share it with the LAN.",
      share_lan: "Share the tunnel with LAN clients",
      block_v6: "Block IPv6 while the tunnel is up",
      auto_reconnect: "Reconnect automatically",
      mtu: "Tunnel MTU", feed_url: "Profile feed URL",
      diag: "Diagnostics", show_log: "Show log",
      connect: "Connect", disconnect: "Disconnect", test: "Test", edit: "Edit",
      delete: "Delete", share: "Share", shared: "Shared", stop: "Remove from LAN",
      connecting: "connecting", connected: "connected", idle: "idle", error: "error",
      exit_ip: "Exit IP", tunnel: "Tunnel", uptime: "Uptime", traffic: "Traffic",
      install_deps: "Install missing clients",
      deps_missing: "Some clients are not installed yet:",
      token_bad: "Wrong token", untested: "not tested",
      paste: "Paste the configuration file here",
      confirm_delete: "Delete this connection?"
    },
    fa: {
      tab_manual: "اتصال‌ها", tab_feed: "لیست خروج", tab_settings: "تنظیمات",
      add: "افزودن اتصال", save: "ذخیره", cancel: "انصراف", refresh: "بروزرسانی",
      no_conn: "هنوز اتصالی اضافه نشده.", feed_empty: "لیستی بارگذاری نشده.",
      manual_hint: "برای هر VPN یک پروفایل بسازید، وصل کنید و با شبکه محلی به اشتراک بگذارید.",
      share_lan: "اشتراک تونل با کاربران شبکه محلی",
      block_v6: "بستن IPv6 هنگام فعال بودن تونل",
      auto_reconnect: "اتصال مجدد خودکار",
      mtu: "MTU تونل", feed_url: "آدرس لیست پروفایل",
      diag: "عیب‌یابی", show_log: "نمایش لاگ",
      connect: "اتصال", disconnect: "قطع", test: "تست", edit: "ویرایش",
      delete: "حذف", share: "اشتراک", shared: "به اشتراک گذاشته شد", stop: "حذف از شبکه",
      connecting: "در حال اتصال", connected: "متصل", idle: "آماده", error: "خطا",
      exit_ip: "IP خروجی", tunnel: "تونل", uptime: "مدت اتصال", traffic: "ترافیک",
      install_deps: "نصب کلاینت‌های نصب‌نشده",
      deps_missing: "این کلاینت‌ها نصب نیستند:",
      token_bad: "توکن اشتباه است", untested: "تست نشده",
      paste: "محتوای فایل کانفیگ را اینجا بچسبانید",
      confirm_delete: "این اتصال حذف شود؟"
    }
  };

  var lang = localStorage.getItem(LS_LANG) || "en";
  function t(k) { return (T[lang] && T[lang][k]) || T.en[k] || k; }

  var TYPES = {
    ikev2: { label: "IKEv2", hint: "EAP-MSCHAPv2 or a pre-shared key" },
    l2tp: { label: "L2TP/IPsec", hint: "IPsec PSK + PPP account" },
    sstp: { label: "SSTP", hint: "Microsoft SSTP over TLS" },
    openvpn: { label: "OpenVPN", hint: "Paste a .ovpn profile" },
    wireguard: { label: "WireGuard", hint: "Paste a wg.conf" },
    amneziawg: { label: "AmneziaWG", hint: "Paste an Amnezia config" },
    vless: { label: "VLESS", hint: "Paste a vless:// URL (REALITY supported)" }
  };

  var FIELDS = {
    ikev2: [
      { k: "server", label: "Server", ph: "vpn.example.com" },
      { k: "remote_id", label: "Remote ID", ph: "optional, defaults to the server" },
      { k: "username", label: "Username" },
      { k: "password", label: "Password", type: "password" },
      { k: "psk", label: "Pre-shared key", ph: "optional - use instead of EAP" }
    ],
    l2tp: [
      { k: "server", label: "Server", ph: "vpn.example.com" },
      { k: "username", label: "Username" },
      { k: "password", label: "Password", type: "password" },
      { k: "psk", label: "IPsec pre-shared key", type: "password" }
    ],
    sstp: [
      { k: "server", label: "Server", ph: "vpn.example.com" },
      { k: "port", label: "Port", ph: "443" },
      { k: "username", label: "Username" },
      { k: "password", label: "Password", type: "password" }
    ],
    openvpn: [
      { k: "raw", label: "Profile", area: true, rows: 12 },
      { k: "username", label: "Username", ph: "optional" },
      { k: "password", label: "Password", type: "password", ph: "optional" }
    ],
    wireguard: [{ k: "raw", label: "wg.conf", area: true, rows: 12 }],
    amneziawg: [{ k: "raw", label: "AmneziaWG config", area: true, rows: 12 }],
    vless: [{ k: "raw", label: "vless:// URL", area: true, rows: 6 }]
  };

  var state = { token: localStorage.getItem(LS_TOKEN) || "", status: null, conns: [], feed: [], caps: {}, editing: null, type: "ikev2" };

  // --------------------------------------------------------------- helpers
  function $(id) { return document.getElementById(id); }
  function esc(s) { return ("" + (s == null ? "" : s)).replace(/[&<>"']/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]; }); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function byteStr(n) {
    n = +n || 0;
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
    return (n / 1073741824).toFixed(2) + " GB";
  }
  function dur(sec) {
    sec = +sec || 0;
    if (!sec) return "-";
    var d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    return m + "m";
  }
  var toastTimer = null;
  function toast(msg, bad) {
    var box = $("toast");
    box.textContent = msg;
    box.className = "toast" + (bad ? " bad" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { box.className = "toast hidden"; }, 4200);
  }

  function api(path, body, method) {
    var opt = { method: method || (body ? "POST" : "GET"), headers: {}, credentials: "same-origin" };
    if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    return fetch(API + path, opt).then(function (r) {
      if (r.status === 401) { askToken(); throw new Error("unauthorized"); }
      return r.json();
    });
  }

  // ------------------------------------------------------------------ gate
  function askToken() {
    $("app").classList.add("hidden");
    $("gate").classList.remove("hidden");
    $("gate-token").focus();
  }
  function useToken(tok) {
    state.token = tok;
    localStorage.setItem(LS_TOKEN, tok);
    document.cookie = "vpnexit=" + encodeURIComponent(tok) + "; path=/; max-age=31536000; SameSite=Strict";
    $("gate").classList.add("hidden");
    $("app").classList.remove("hidden");
    boot();
  }
  $("gate-go").addEventListener("click", function () {
    var tok = $("gate-token").value.trim();
    if (!tok) return;
    api("health").then(function () { useToken(tok); }).catch(function () {
      useToken(tok);
    });
  });
  $("gate-token").addEventListener("keydown", function (e) { if (e.key === "Enter") $("gate-go").click(); });

  // ---------------------------------------------------------------- status
  function renderStatus() {
    var s = state.status || { state: "idle" };
    var dot = $("conn-dot");
    dot.className = "dot " + (s.state === "connected" ? "ok" : s.state === "connecting" ? "wait" : s.state === "error" ? "bad" : "");
    $("conn-label").textContent = t(s.state) || s.state;
    $("st-name").textContent = s.name || "No tunnel";
    var sub = [];
    if (s.type_label) sub.push(s.type_label);
    if (s.server) sub.push(s.server);
    if (s.iface) sub.push(s.iface);
    $("st-sub").textContent = sub.join("  ·  ");
    $("st-ip").textContent = s.exit_ip || "-";
    $("st-vip").textContent = s.vip || "-";
    $("st-up").textContent = dur(s.uptime);
    $("st-rx").textContent = (s.rx || s.tx) ? byteStr(s.rx) + " / " + byteStr(s.tx) : "-";
    var warn = $("st-warn");
    var msg = s.error || s.warning || s.degraded || "";
    if (msg) { warn.textContent = msg; warn.className = "warn"; } else { warn.className = "warn hidden"; }
    $("btn-disconnect").disabled = !s.conn_id;
  }

  function poll() {
    api("status").then(function (r) {
      if (!r.ok) return;
      state.status = r.status;
      renderStatus();
      var fast = r.status.state === "connecting";
      setTimeout(poll, fast ? 2500 : 9000);
    }).catch(function () { setTimeout(poll, 15000); });
  }

  // ------------------------------------------------------------ connection
  function connCard(c) {
    var box = el("div", "card conn" + (c.active && c.up ? " live" : ""));
    var head = el("div", "conn-head");
    var left = el("div", "conn-title");
    left.appendChild(el("span", "badge", c.type_label || c.type));
    left.appendChild(el("span", "name", c.name));
    head.appendChild(left);
    var dot = el("span", "dot " + (c.active && c.up ? "ok" : c.active ? "wait" : ""));
    head.appendChild(dot);
    box.appendChild(head);

    var meta = [];
    if (c.endpoint) meta.push(c.endpoint);
    if (c.vip) meta.push(c.vip);
    box.appendChild(el("div", "muted small", meta.join("  ·  ")));
    if (c.degraded) box.appendChild(el("div", "warn small", c.degraded));

    var acts = el("div", "conn-acts");
    if (c.active && c.up) {
      var off = el("button", "btn danger small", t("disconnect"));
      off.onclick = function () { busy(off, api("disconnect", {}).then(refreshAll)); };
      acts.appendChild(off);
    } else {
      var on = el("button", "btn primary small", t("connect"));
      on.onclick = function () { busy(on, api("connection-connect", { id: c.id }).then(function () { setTimeout(refreshAll, 600); })); };
      acts.appendChild(on);
    }
    var test = el("button", "btn ghost small", t("test"));
    test.onclick = function () {
      busy(test, api("connection-test", { id: c.id }).then(function (r) {
        if (r.ok) toast("exit " + (r.exit_ip || "?") + " - ok");
        else toast(r.error || r.detail || "test failed", true);
        refreshAll();
      }));
    };
    acts.appendChild(test);
    var edit = el("button", "btn ghost small", t("edit"));
    edit.onclick = function () { openModal(c.type, c); };
    acts.appendChild(edit);
    var del = el("button", "btn ghost small danger-text", t("delete"));
    del.onclick = function () {
      if (!confirm(t("confirm_delete"))) return;
      busy(del, api("connections-delete", { id: c.id }).then(refreshAll));
    };
    acts.appendChild(del);
    box.appendChild(acts);
    return box;
  }

  function busy(btn, promise) {
    var old = btn.textContent;
    btn.disabled = true;
    btn.textContent = "...";
    return promise.catch(function (e) { toast("" + (e.message || e), true); })
      .then(function () { btn.disabled = false; btn.textContent = old; });
  }

  function renderConns() {
    var box = $("conn-list");
    box.innerHTML = "";
    state.conns.forEach(function (c) { box.appendChild(connCard(c)); });
    $("conn-empty").classList.toggle("hidden", state.conns.length > 0);
  }

  function renderDeps() {
    var m = (state.caps && state.caps.missing) || { types: [], packages: [] };
    var box = $("deps");
    if (!m.types || !m.types.length) { box.className = "deps hidden"; return; }
    box.className = "deps";
    box.innerHTML = "";
    box.appendChild(el("span", "", t("deps_missing") + " " + m.types.map(function (x) { return TYPES[x] ? TYPES[x].label : x; }).join(", ")));
    var btn = el("button", "btn primary small", t("install_deps"));
    btn.onclick = function () {
      busy(btn, api("deps-install", {}).then(function (r) {
        toast(r.ok ? "installed" : "still missing: " + (r.missing_types || []).join(", "), !r.ok);
        refreshAll();
      }));
    };
    box.appendChild(btn);
  }

  // ------------------------------------------------------------------ feed
  function renderFeed() {
    var q = ($("feed-search").value || "").toLowerCase();
    var box = $("feed-list");
    box.innerHTML = "";
    var items = state.feed.filter(function (it) {
      return !q || (it.title + " " + it.country + " " + it.key).toLowerCase().indexOf(q) >= 0;
    });
    items.forEach(function (it) {
      var c = el("div", "card feed");
      var row = el("div", "row between");
      var left = el("div", "row gap");
      left.appendChild(el("span", "flag", it.flag || ""));
      var meta = el("div");
      meta.appendChild(el("div", "name", it.title + (it.country ? " · " + it.country : "")));
      meta.appendChild(el("div", "muted small", it.servers.length + " server(s)" + (it.premium ? " · premium" : "")));
      left.appendChild(meta);
      row.appendChild(left);
      var btn = el("button", "btn ghost small", t("connect"));
      btn.onclick = function () { busy(btn, api("connect", { key: it.key, index: 0 }).then(function () { setTimeout(refreshAll, 600); })); };
      row.appendChild(btn);
      c.appendChild(row);
      box.appendChild(c);
    });
    $("feed-empty").classList.toggle("hidden", items.length > 0);
  }

  // ---------------------------------------------------------------- modal
  function openModal(type, conn) {
    state.editing = conn || null;
    state.type = type || (conn && conn.type) || "ikev2";
    $("m-title").textContent = conn ? t("edit") : t("add");
    $("m-msg").textContent = "";
    $("modal").classList.remove("hidden");
    renderTypes();
    renderForm();
  }
  function closeModal() { $("modal").classList.add("hidden"); state.editing = null; }

  function renderTypes() {
    var box = $("m-types");
    box.innerHTML = "";
    Object.keys(TYPES).forEach(function (k) {
      var b = el("button", "type" + (k === state.type ? " active" : ""));
      b.appendChild(el("span", "type-name", TYPES[k].label));
      b.appendChild(el("span", "type-hint", TYPES[k].hint));
      b.onclick = function () { state.type = k; renderTypes(); renderForm(); };
      box.appendChild(b);
    });
  }

  function renderForm() {
    var box = $("m-form");
    box.className = "form";
    box.innerHTML = "";
    var defs = FIELDS[state.type] || [];
    var conf = (state.editing && state.editing.type === state.type) ? {} : {};
    var rawCfg = (state.editing && state.editing.config) ? state.editing.config : {};

    var nameRow = el("label", "field");
    nameRow.appendChild(el("span", "", "Name"));
    var nameIn = el("input", "");
    nameIn.id = "f-name";
    nameIn.value = (state.editing && state.editing.name) || "";
    nameIn.placeholder = TYPES[state.type].label;
    nameRow.appendChild(nameIn);
    box.appendChild(nameRow);

    defs.forEach(function (f) {
      var wrap = el("label", "field");
      wrap.appendChild(el("span", "", f.label));
      var inp;
      if (f.area) {
        inp = el("textarea", "mono");
        inp.rows = f.rows || 8;
        inp.placeholder = f.k === "raw" ? t("paste") : (f.ph || "");
      } else {
        inp = el("input", "");
        inp.type = f.type || "text";
        if (f.ph) inp.placeholder = f.ph;
      }
      inp.id = "f-" + f.k;
      inp.value = rawCfg[f.k] || "";
      wrap.appendChild(inp);
      box.appendChild(wrap);
    });
    box.appendChild(el("div", "muted small", "ssh " + (state.type === "vless" ? "vless://uuid@host:443?security=reality&pbk=...&sid=..." : "")));
  }

  function collect() {
    var conf = {};
    (FIELDS[state.type] || []).forEach(function (f) {
      var v = $("f-" + f.k);
      if (v && v.value.trim()) conf[f.k] = v.value.trim();
    });
    var body = { type: state.type, name: $("f-name").value.trim(), config: conf, share_lan: true };
    if (state.editing) body.id = state.editing.id;
    return body;
  }

  $("m-save").addEventListener("click", function () {
    var btn = $("m-save");
    busy(btn, api("connections-save", collect()).then(function (r) {
      if (!r.ok) { $("m-msg").textContent = r.error || "error"; return; }
      if (r.valid === false) { $("m-msg").textContent = r.error || "invalid"; }
      closeModal();
      refreshAll();
      toast(t("save") + " ok");
    }).catch(function (e) { $("m-msg").textContent = "" + (e.message || e); }));
  });
  $("m-cancel").addEventListener("click", closeModal);
  $("m-close").addEventListener("click", closeModal);
  $("btn-add").addEventListener("click", function () { openModal("ikev2", null); });

  // -------------------------------------------------------------- settings
  function renderSettings(s) {
    $("set-share").checked = !!s.share_lan;
    $("set-v6").checked = !!s.block_ipv6;
    $("set-auto").checked = !!s.auto_reconnect;
    $("set-mtu").value = s.tunnel_mtu || 1400;
    $("set-feed").value = s.feed_url || "";
    $("ver").textContent = s.version ? "v" + s.version : "";
  }
  $("btn-save-settings").addEventListener("click", function () {
    var btn = $("btn-save-settings");
    busy(btn, api("settings", {
      share_lan: $("set-share").checked,
      block_ipv6: $("set-v6").checked,
      auto_reconnect: $("set-auto").checked,
      tunnel_mtu: +$("set-mtu").value || 1400,
      feed_url: $("set-feed").value.trim() || undefined
    }).then(function (r) {
      if (r.ok) { renderSettings(r.settings); toast(t("save") + " ok"); }
    }));
  });
  $("btn-log").addEventListener("click", function () {
    var pre = $("log");
    if (!pre.classList.contains("hidden")) { pre.classList.add("hidden"); return; }
    api("log?lines=80").then(function (r) { pre.textContent = r.text || "(empty)"; pre.classList.remove("hidden"); });
  });

  // ----------------------------------------------------------------- tabs
  Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (b) {
    b.addEventListener("click", function () {
      Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (x) { x.classList.remove("active"); });
      Array.prototype.forEach.call(document.querySelectorAll(".tabpane"), function (x) { x.classList.add("hidden"); });
      b.classList.add("active");
      $("tab-" + b.dataset.tab).classList.remove("hidden");
      if (b.dataset.tab === "feed") loadFeed();
    });
  });

  $("btn-disconnect").addEventListener("click", function () {
    busy($("btn-disconnect"), api("disconnect", {}).then(refreshAll));
  });
  $("btn-test").addEventListener("click", function () {
    busy($("btn-test"), api("selftest", {}).then(function (r) {
      toast(r.ok ? "exit " + (r.result.ip || "?") : (r.result.detail || "failed"), !r.ok);
      refreshAll();
    }));
  });
  $("btn-refresh").addEventListener("click", function () {
    busy($("btn-refresh"), api("refresh", {}).then(function (r) {
      toast(r.ok ? r.count + " locations" : (r.error || "failed"), !r.ok);
      loadFeed();
    }));
  });
  $("feed-search").addEventListener("input", renderFeed);
  $("lang").addEventListener("click", function () {
    lang = lang === "en" ? "fa" : "en";
    localStorage.setItem(LS_LANG, lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
    $("lang").textContent = lang === "en" ? "FA" : "EN";
    document.querySelectorAll("[data-i18n]").forEach(function (n) {
      var k = n.getAttribute("data-i18n");
      if (k) n.textContent = t(k);
    });
    refreshAll();
  });

  // ------------------------------------------------------------------ boot
  function loadFeed() {
    api("locations").then(function (r) {
      if (!r.ok) return;
      state.feed = r.items || [];
      renderFeed();
    });
  }

  function refreshAll() {
    return Promise.all([
      api("status").then(function (r) { if (r.ok) { state.status = r.status; renderStatus(); } }),
      api("connections").then(function (r) { if (r.ok) { state.conns = r.items || []; renderConns(); } }),
      api("caps").then(function (r) { if (r.ok) { state.caps = { caps: r.caps, missing: r.missing }; renderDeps(); } }),
      api("settings").then(function (r) { if (r.ok) renderSettings(r.settings); })
    ]).catch(function () { });
  }

  function boot() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
    $("lang").textContent = lang === "en" ? "FA" : "EN";
    refreshAll().then(function () { loadFeed(); poll(); setInterval(refreshAll, 20000); });
  }

  if (state.token) {
    document.cookie = "vpnexit=" + encodeURIComponent(state.token) + "; path=/; max-age=31536000; SameSite=Strict";
    $("app").classList.remove("hidden");
    boot();
  } else {
    askToken();
  }
})();
