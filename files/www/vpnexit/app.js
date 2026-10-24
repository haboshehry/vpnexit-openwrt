/* vpnexit panel – no framework, no external assets */
(function () {
  "use strict";

  var API = "/cgi-bin/vpnexit/api/";
  var LS_TOKEN = "vpnexit.token";
  var LS_LANG = "vpnexit.lang";

  var I18N = {
    en: {
      dir: "ltr",
      brandSub: "OpenWrt · LAN & Wi-Fi sharing",
      idle: "Idle", connected: "Connected", connecting: "Connecting…", error: "Error",
      notConnected: "Not connected",
      notConnectedSub: "Traffic from your devices goes straight to the internet.",
      connectedTo: "Connected to {0}",
      connectedSub: "Every wired and Wi-Fi device now uses this exit.",
      partialSub: "Tunnel is up, but LAN sharing is off.",
      connect: "Connect", disconnect: "Disconnect", reconnect: "Reconnect", selftest: "Self-test",
      exitIp: "Exit IP", tunnelIp: "Tunnel IP", uptime: "Uptime", traffic: "Traffic",
      locations: "Locations", search: "Search country…", refresh: "Update list",
      refreshing: "Updating…", premium: "premium", servers: "{0} server(s)",
      connectShort: "Connect", disconnectShort: "Disconnect",
      empty: "No locations yet. Press Refresh to download the feed.",
      emptyFilter: "Nothing matches your search.",
      activity: "Activity log", show: "Show", hide: "Hide",
      settings: "Settings",
      shareT: "Share with LAN devices", shareD: "Route traffic from every wired and Wi-Fi client through the tunnel.",
      v6T: "Block IPv6 for LAN devices", v6D: "Prevents IPv6 traffic from bypassing the tunnel.",
      autoT: "Auto-reconnect", autoD: "Re-establish the tunnel when the peer drops it.",
      mtuT: "Tunnel MTU", mtuD: "Lower it if large downloads stall.",
      feedT: "Profile feed", feedD: "JSON feed refreshed every day.",
      tokT: "Admin token", tokD: "Required for every change from this page.",
      save: "Save", saved: "Saved", newTok: "New",
      gateTitle: "Admin token", gateHint: "Paste the token printed by the installer.",
      unlock: "Unlock", badToken: "Wrong token.",
      toastConnected: "Connected", toastDisconnected: "Disconnected",
      toastRefreshed: "Feed updated", toastError: "Something went wrong",
      testOk: "Exit verified: {0}", testFail: "Self-test failed",
      foot: "vpnexit · router-side IKEv2 client",
      confirmDisc: "Disconnect the tunnel and stop sharing it with the LAN?",
      updating: "Working…",
      source: "Backend source", openRaw: "Open raw", close: "Close",
      srcHint: "This file lives outside the web root and has no direct URL.",
      chooseServer: "Choose server", pickServer: "Pick the server to connect to.",
      serverN: "Server {0}", busy: "Another operation is still running, try again in a moment."
    },
    fa: {
      dir: "rtl",
      brandSub: "OpenWrt · اشتراک در LAN و وای‌فای",
      idle: "غیرفعال", connected: "متصل", connecting: "در حال اتصال…", error: "خطا",
      notConnected: "متصل نیست",
      notConnectedSub: "ترافیک دستگاه‌های شما مستقیم به اینترنت می‌رود.",
      connectedTo: "متصل به {0}",
      connectedSub: "همه دستگاه‌های کابلی و وای‌فای اکنون از این خروجی استفاده می‌کنند.",
      partialSub: "تونل برقرار است اما اشتراک‌گذاری با LAN خاموش است.",
      connect: "اتصال", disconnect: "قطع", reconnect: "اتصال مجدد", selftest: "تست خودکار",
      exitIp: "IP خروجی", tunnelIp: "IP تونل", uptime: "مدت اتصال", traffic: "ترافیک",
      locations: "موقعیت‌ها", search: "جستجوی کشور…", refresh: "به‌روزرسانی لیست",
      refreshing: "در حال به‌روزرسانی…", premium: "ویژه", servers: "{0} سرور",
      connectShort: "اتصال", disconnectShort: "قطع",
      empty: "فهرستی موجود نیست. دکمه به‌روزرسانی را بزنید.",
      emptyFilter: "موردی با این جستجو پیدا نشد.",
      activity: "گزارش فعالیت", show: "نمایش", hide: "بستن",
      settings: "تنظیمات",
      shareT: "اشتراک با دستگاه‌های LAN", shareD: "ترافیک همه کلاینت‌های کابلی و وای‌فای از تونل عبور کند.",
      v6T: "مسدودکردن IPv6 برای LAN", v6D: "جلوگیری از عبور ترافیک IPv6 از بیرون تونل.",
      autoT: "اتصال خودکار مجدد", autoD: "اگر سرور اتصال را قطع کرد، تونل دوباره برقرار شود.",
      mtuT: "MTU تونل", mtuD: "در صورت گیرکردن دانلودهای بزرگ، کمترش کنید.",
      feedT: "منبع پروفایل‌ها", feedD: "فید JSON که روزانه به‌روزرسانی می‌شود.",
      tokT: "توکن مدیریت", tokD: "برای هر تغییر از این صفحه لازم است.",
      save: "ذخیره", saved: "ذخیره شد", newTok: "جدید",
      gateTitle: "توکن مدیریت", gateHint: "توکنی را که نصب‌کننده چاپ کرده وارد کنید.",
      unlock: "ورود", badToken: "توکن نادرست است.",
      toastConnected: "متصل شد", toastDisconnected: "قطع شد",
      toastRefreshed: "فهرست به‌روز شد", toastError: "خطایی رخ داد",
      testOk: "خروجی تأیید شد: {0}", testFail: "تست خودکار ناموفق بود",
      foot: "vpnexit · کلاینت IKEv2 روی روتر",
      confirmDisc: "تونل قطع و اشتراک‌گذاری با LAN متوقف شود؟",
      updating: "در حال انجام…",
      source: "سورس بک‌اند", openRaw: "نمایش خام", close: "بستن",
      srcHint: "این فایل خارج از ریشهٔ وب است و آدرس مستقیم ندارد.",
      chooseServer: "انتخاب سرور", pickServer: "سروری را که می‌خواهید به آن وصل شوید انتخاب کنید.",
      serverN: "سرور {0}", busy: "یک عملیات دیگر در حال اجراست؛ چند لحظه بعد دوباره تلاش کنید."
    }
  };

  var lang = localStorage.getItem(LS_LANG) || (navigator.language || "en").slice(0, 2);
  if (!I18N[lang]) lang = "en";

  var state = {
    token: localStorage.getItem(LS_TOKEN) || "",
    status: null,
    locations: null,
    busy: false,
    timer: null,
    filter: ""
  };

  function t(key) {
    var s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
    for (var i = 1; i < arguments.length; i++) s = s.replace("{" + (i - 1) + "}", arguments[i]);
    return s;
  }
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 10 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
  }
  function duration(sec) {
    sec = Math.max(0, Math.floor(Number(sec) || 0));
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }
  function toast(msg, kind) {
    var box = $("toasts"), el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(function () { el.remove(); }, 3600);
  }

  // uhttpd only forwards a fixed set of headers to CGI scripts, so the token
  // travels in a cookie as well (it is also kept in localStorage for the UI).
  function setCookie(t) {
    document.cookie = "vpnexit=" + encodeURIComponent(t) + "; path=/; max-age=31536000; SameSite=Strict";
  }
  function dropCookie() {
    document.cookie = "vpnexit=; path=/; max-age=0; SameSite=Strict";
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = { "Accept": "application/json" };
    if (state.token) headers["X-Auth-Token"] = state.token;
    if (opts.body) headers["Content-Type"] = "application/json";
    // uhttpd drops custom headers and cookies for CGI, so the token also
    // travels in the query string (this panel is LAN-only, plain HTTP anyway).
    var url = API + path + (path.indexOf("?") >= 0 ? "&" : "?") + "t=" + encodeURIComponent(state.token || "");
    return fetch(url, {
      method: opts.method || (opts.body ? "POST" : "GET"),
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      cache: "no-store"
    }).then(function (r) {
      return r.text().then(function (txt) {
        var data;
        try { data = JSON.parse(txt); } catch (e) { data = { ok: false, error: txt.slice(0, 200) || ("HTTP " + r.status) }; }
        if (r.status === 401) { openGate(); data.ok = false; data.unauthorized = true; }
        else if (!r.ok && data.ok !== false) { data.ok = false; data.error = "HTTP " + r.status; }
        return data;
      });
    }).catch(function (e) {
      return { ok: false, error: String(e && e.message || e) };
    });
  }

  /* ---------- i18n application ---------- */
  var TEXT_MAP = {
    brandSub: "brandSub", settings: "setTitle", shareT: "setShareT", shareD: "setShareD",
    v6T: "setV6T", v6D: "setV6D", autoT: "setAutoT", autoD: "setAutoD",
    mtuT: "setMtuT", mtuD: "setMtuD", feedT: "setFeedT", feedD: "setFeedD",
    tokT: "setTokT", tokD: "setTokD", save: "saveSettings", gateTitle: "gateTitle",
    gateHint: "gateHint", unlock: "gateBtn", foot: "footNote", activity: "logTitle",
    locations: "locTitle", source: "srcTitle", openRaw: "srcRaw", close: "srcCloseBtn"
  };

  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = I18N[lang].dir;
    for (var k in TEXT_MAP) {
      var el = $(TEXT_MAP[k]);
      if (el) el.textContent = t(k);
    }
    $("langBtn").textContent = lang === "fa" ? "EN" : "FA";
    $("search").placeholder = t("search");
    $("refreshLabel").textContent = t("refresh");
    $("cfgTokenGen").textContent = t("newTok");
    if (state.status) renderStatus();
    if (state.locations) renderLocations();
  }

  /* ---------- rendering ---------- */
  function stateBadge(st) {
    var s = st && st.state || "idle";
    if (s === "connected" && st.routing && st.routing.active === false) return ["badge-busy", t("idle")];
    if (s === "connected") return ["badge-ok", t("connected")];
    if (s === "connecting") return ["badge-busy", t("connecting")];
    if (s === "error") return ["badge-err", t("error")];
    return ["badge-idle", t("idle")];
  }

  function renderStatus() {
    var st = state.status || { state: "idle" };
    var b = stateBadge(st);
    $("connBadge").className = "badge " + b[0];
    $("connBadge").lastElementChild.textContent = b[1];

    var connected = st.state === "connected";
    var loc = st.location || null;

    $("statusFlag").textContent = loc ? (loc.flag || "🌐") : "🌐";
    if (connected && loc) {
      $("statusTitle").textContent = t("connectedTo", loc.title || loc.key);
      $("statusSub").textContent = (st.routing && st.routing.active === false) ? t("partialSub") : t("connectedSub");
    } else if (st.state === "connecting") {
      $("statusTitle").textContent = t("connecting");
      $("statusSub").textContent = loc ? (loc.title || loc.key) : "";
    } else if (st.state === "error") {
      $("statusTitle").textContent = t("error");
      $("statusSub").textContent = st.error || t("notConnectedSub");
    } else {
      $("statusTitle").textContent = t("notConnected");
      $("statusSub").textContent = t("notConnectedSub");
    }

    var pb = $("primaryBtn");
    pb.textContent = connected ? t("disconnect") : t("connect");
    pb.className = "btn " + (connected ? "btn-danger" : "btn-primary");
    pb.disabled = state.busy || st.state === "connecting";
    $("testBtn").hidden = !connected;
    $("testBtn").textContent = t("selftest");
    $("testBtn").disabled = state.busy;

    $("mExit").textContent = st.exit_ip || "—";
    $("mVip").textContent = st.vip || "—";
    $("mUp").textContent = connected && st.uptime ? duration(st.uptime) : "—";
    $("mTraffic").textContent = connected ? (bytes(st.rx) + " ↓ · " + bytes(st.tx) + " ↑") : "—";

    var warn = $("warnBox");
    if (st.warning) { warn.hidden = false; warn.textContent = st.warning; }
    else { warn.hidden = true; warn.textContent = ""; }
  }

  function renderLocations() {
    var box = $("locList");
    var data = state.locations || { items: [] };
    var items = data.items || [];
    var f = state.filter.trim().toLowerCase();
    if (f) {
      items = items.filter(function (it) {
        return (it.title + " " + it.key + " " + (it.country || "")).toLowerCase().indexOf(f) >= 0;
      });
    }
    box.innerHTML = "";
    var empty = $("locEmpty");
    if (!items.length) {
      empty.hidden = false;
      empty.textContent = (state.locations && state.locations.items && state.locations.items.length) ? t("emptyFilter") : t("empty");
    } else {
      empty.hidden = true;
    }

    var activeKey = state.status && state.status.location && state.status.location.key;
    var activeIndex = state.status && state.status.server ? Number(state.status.server.index || 0) : -1;
    var frag = document.createDocumentFragment();
    items.forEach(function (it) {
      (it.servers || []).forEach(function (srv, serverIndex) {
        var row = document.createElement("div");
        var isActive = it.key === activeKey && serverIndex === activeIndex && state.status.state === "connected";
        row.className = "loc-row" + (isActive ? " active" : "");
        row.setAttribute("role", "listitem");
        row.innerHTML =
          '<div class="loc-flag">' + esc(it.flag || "🌐") + "</div>" +
          '<div class="loc-info">' +
            '<div class="loc-name">' + esc(it.title || it.key) +
              ' <span class="pill">' + esc(t("serverN", serverIndex + 1)) + "</span>" +
              (it.premium ? ' <span class="pill">' + esc(t("premium")) + "</span>" : "") +
              (isActive ? ' <span class="dot"></span>' : "") +
            "</div>" +
            '<div class="loc-meta">' + esc((it.country || "") + " · " + (srv.host || "") + (srv.ip ? " · " + srv.ip : "")) + "</div>" +
          "</div>";
        var btn = document.createElement("button");
        btn.className = "btn sm " + (isActive ? "btn-danger" : "btn-ghost");
        btn.textContent = isActive ? t("disconnectShort") : t("connectShort");
        btn.disabled = state.busy;
        btn.addEventListener("click", function () {
          if (isActive) disconnect(); else connect(it.key, serverIndex, btn);
        });
        row.appendChild(btn);
        frag.appendChild(row);
      });
    });
    box.appendChild(frag);

    var meta = $("locMeta");
    if (data.fetched_at) {
      var d = new Date(data.fetched_at * 1000);
      meta.textContent = data.count + " · " + d.toLocaleString(lang === "fa" ? "fa-IR" : undefined);
    } else {
      meta.textContent = "—";
    }
  }

  /* ---------- actions ---------- */
  function setBusy(on, label) {
    state.busy = on;
    document.body.style.cursor = on ? "progress" : "";
    if (label) toast(label);
    renderStatus();
  }

  function loadStatus() {
    return api("status").then(function (r) {
      if (r.ok) { state.status = r.status || r; renderStatus(); }
      return r;
    });
  }

  function loadLocations(force) {
    return api("locations" + (force ? "?refresh=1" : "")).then(function (r) {
      if (r.ok) { state.locations = r; renderLocations(); }
      else if (!r.unauthorized) toast(r.error || t("toastError"), "err");
      return r;
    });
  }

  function loadSettings() {
    return api("settings").then(function (r) {
      if (!r.ok) return r;
      var s = r.settings || {};
      $("cfgShareLan").checked = !!s.share_lan;
      $("cfgBlockV6").checked = !!s.block_ipv6;
      $("cfgAuto").checked = !!s.auto_reconnect;
      $("cfgMtu").value = s.tunnel_mtu || 1400;
      $("cfgFeed").value = s.feed_url || "";
      $("cfgToken").value = s.token || state.token;
      $("footVersion").textContent = s.version ? "v" + s.version : "";
      return r;
    });
  }

  function connect(key, index, btn) {
    if (state.busy) return;
    setBusy(true);
    if (btn) btn.disabled = true;
    state.status = { state: "connecting", location: (state.locations ? state.locations.items : []).filter(function (x) { return x.key === key; })[0] };
    renderStatus();
    api("connect", { body: { key: key, index: index || 0 } }).then(function (r) {
      setBusy(false);
      if (r.ok) {
        toast(t("connecting"), "ok");
        setTimeout(function () { loadStatus(); }, 800);
      } else if (!r.unauthorized) {
        toast((r.error || "").indexOf("busy") === 0 ? t("busy") : (r.error || t("toastError")), "err");
        loadStatus();
      }
      return null;
    }).then(function () { if (state.locations) renderLocations(); });
  }

  function disconnect() {
    if (state.busy) return;
    if (!confirm(t("confirmDisc"))) return;
    setBusy(true);
    api("disconnect", { body: {} }).then(function (r) {
      setBusy(false);
      if (r.ok) toast(t("toastDisconnected"), "ok");
      else if (!r.unauthorized) toast(r.error || t("toastError"), "err");
      return loadStatus();
    }).then(function () { if (state.locations) renderLocations(); });
  }

  function selftest() {
    if (state.busy) return;
    setBusy(true, t("updating"));
    api("selftest", { body: {} }).then(function (r) {
      setBusy(false);
      if (r.ok && r.result && r.result.ok) toast(t("testOk", r.result.ip || "?"), "ok");
      else toast((r.result && r.result.detail) || r.error || t("testFail"), "err");
      return loadStatus();
    });
  }

  function setRefreshing(on) {
    ["refreshBtn", "refreshTop"].forEach(function (id) {
      var el = $(id);
      if (el) el.disabled = on;
    });
    var icons = document.querySelectorAll("#refreshIcon, #refreshTop svg");
    Array.prototype.forEach.call(icons, function (i) {
      i.classList.toggle("spin-icon", on);
    });
    $("refreshLabel").textContent = on ? t("refreshing") : t("refresh");
  }

  // Manual feed refresh: downloads the JSON again and re-renders the list.
  function refreshFeed() {
    if (state.busy) { toast(t("busy"), "err"); return; }
    setRefreshing(true);
    api("refresh", { body: {} }).then(function (r) {
      setRefreshing(false);
      if (r.ok) {
        toast(t("toastRefreshed") + " (" + (r.count || 0) + ")", "ok");
        return loadLocations(false);
      }
      if (!r.unauthorized) toast(r.error || t("toastError"), "err");
      return null;
    }).catch(function () { setRefreshing(false); });
  }

  function openGate() {
    $("gate").hidden = false;
    $("gateErr").hidden = true;
    setTimeout(function () { $("tokenInput").focus(); }, 50);
  }

  function saveSettings() {
    var body = {
      share_lan: $("cfgShareLan").checked,
      block_ipv6: $("cfgBlockV6").checked,
      auto_reconnect: $("cfgAuto").checked,
      tunnel_mtu: Number($("cfgMtu").value) || 1400,
      feed_url: $("cfgFeed").value.trim(),
      token: $("cfgToken").value.trim()
    };
    if (body.token && body.token !== state.token) {
      state.token = body.token;
      localStorage.setItem(LS_TOKEN, state.token);
    }
    api("settings", { body: body }).then(function (r) {
      if (r.ok) { toast(t("saved"), "ok"); $("drawer").hidden = true; loadStatus(); }
      else {
        var e = $("setErr"); e.hidden = false; e.textContent = r.error || t("toastError");
      }
    });
  }

  function openServerPicker(loc) {
    $("srvTitle").textContent = (loc.flag ? loc.flag + " " : "") + (loc.title || loc.key);
    $("srvHint").textContent = t("servers", (loc.servers || []).length) + " — " + t("pickServer");
    var box = $("srvList");
    box.innerHTML = "";
    (loc.servers || []).forEach(function (s, i) {
      var row = document.createElement("div");
      row.className = "loc-row";
      row.innerHTML =
        '<div class="loc-flag" style="font-size:13px;font-weight:700">' + (i + 1) + "</div>" +
        '<div class="loc-info"><div class="loc-name">' + esc(s.host) + "</div>" +
        '<div class="loc-meta">' + esc(s.ip || "") + "</div></div>";
      var b = document.createElement("button");
      b.className = "btn sm btn-primary";
      b.textContent = t("connectShort");
      b.addEventListener("click", function () {
        $("serverModal").hidden = true;
        connect(loc.key, i, null);
      });
      row.appendChild(b);
      box.appendChild(row);
    });
    $("serverModal").hidden = false;
  }

  function openSource() {
    $("sourceModal").hidden = false;
    $("srcCode").textContent = "…";
    $("srcRaw").href = API + "source?raw=1&t=" + encodeURIComponent(state.token || "");
    api("source").then(function (r) {
      if (!r.ok) { $("srcCode").textContent = r.error || t("toastError"); return; }
      $("srcPath").textContent = r.path + " · " + r.bytes + " B — " + t("srcHint");
      $("srcCode").textContent = r.text;
    });
  }

  function toggleLog(show) {
    var box = $("logBox");
    var on = show == null ? box.hidden : show;
    box.hidden = !on;
    $("logToggle").textContent = on ? t("hide") : t("show");
    if (on) {
      api("log?lines=120").then(function (r) {
        box.textContent = (r.ok && r.text) ? r.text : (r.error || "—");
        box.scrollTop = box.scrollHeight;
      });
    }
  }

  /* ---------- wiring ---------- */
  document.addEventListener("DOMContentLoaded", function () {
    applyLang();

    $("langBtn").addEventListener("click", function () {
      lang = lang === "fa" ? "en" : "fa";
      localStorage.setItem(LS_LANG, lang);
      applyLang();
    });

    $("primaryBtn").addEventListener("click", function () {
      var st = state.status || {};
      if (st.state === "connected") disconnect();
      else {
        var first = null;
        if (state.status && state.status.location) first = state.status.location.key;
        if (!first && state.locations && state.locations.items && state.locations.items.length) first = state.locations.items[0].key;
        if (first) connect(first, 0, null); else toast(t("empty"), "err");
      }
    });

    $("testBtn").addEventListener("click", selftest);
    $("refreshBtn").addEventListener("click", refreshFeed);
    $("refreshTop").addEventListener("click", refreshFeed);
    $("search").addEventListener("input", function (e) { state.filter = e.target.value; renderLocations(); });
    $("settingsBtn").addEventListener("click", function () { $("setErr").hidden = true; $("drawer").hidden = false; loadSettings(); });
    $("drawerClose").addEventListener("click", function () { $("drawer").hidden = true; });
    $("drawer").addEventListener("click", function (e) { if (e.target === $("drawer")) $("drawer").hidden = true; });
    $("saveSettings").addEventListener("click", saveSettings);
    $("cfgTokenGen").addEventListener("click", function () {
      var a = new Uint8Array(16);
      (window.crypto || window.msCrypto).getRandomValues(a);
      $("cfgToken").value = Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    });
    $("panicBtn").addEventListener("click", function () { $("drawer").hidden = true; disconnect(); });
    $("logToggle").addEventListener("click", function () { toggleLog(); });
    $("sourceBtn").addEventListener("click", openSource);
    $("srvClose").addEventListener("click", function () { $("serverModal").hidden = true; });
    $("serverModal").addEventListener("click", function (e) {
      if (e.target === $("serverModal")) $("serverModal").hidden = true;
    });
    $("srcClose").addEventListener("click", function () { $("sourceModal").hidden = true; });
    $("srcCloseBtn").addEventListener("click", function () { $("sourceModal").hidden = true; });
    $("sourceModal").addEventListener("click", function (e) {
      if (e.target === $("sourceModal")) $("sourceModal").hidden = true;
    });

    $("gateForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var v = $("tokenInput").value.trim();
      if (!v) return;
      state.token = v;
      localStorage.setItem(LS_TOKEN, v);
      setCookie(v);
      api("status").then(function (r) {
        if (r.unauthorized) {
          state.token = "";
          localStorage.removeItem(LS_TOKEN);
          dropCookie();
          $("gateErr").hidden = false;
          $("gateErr").textContent = t("badToken");
          return;
        }
        $("gate").hidden = true;
        boot();
      });
    });

    function boot() {
      loadSettings();
      loadStatus().then(function (r) {
        if (r.unauthorized) return;
        loadLocations(false);
      });
      if (state.timer) clearInterval(state.timer);
      state.timer = setInterval(function () {
        if (document.hidden) return;
        if (!state.busy) loadStatus();
        if (!$("logBox").hidden) toggleLog(true);
      }, 3000);
    }

    if (!state.token) openGate();
    else { setCookie(state.token); boot(); }
  });
})();
