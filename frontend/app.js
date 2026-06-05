/* ComputerCheck app logic.
   Talks to the Rust core via the global Tauri bridge:
     run_scan({ orgCode })      -> engine JSON string
     history_load()             -> JSON array string
     history_append({ record }) -> void
     history_wipe()             -> void
   In a plain browser (no Tauri) the scan button explains it needs the app. */
(function () {
  "use strict";

  const TAURI = (window.__TAURI__ && window.__TAURI__.core) ? window.__TAURI__.core : null;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const ORG_KEY = "cc_org_code";
  let lastPayload = null;

  // ---- tabs ----------------------------------------------------------------
  function showTab(name) {
    $$(".tab").forEach((t) => t.classList.toggle("on", t.dataset.tab === name));
    $$(".view").forEach((v) => v.classList.toggle("on", v.dataset.view === name));
    if (name === "history") renderHistory();
  }
  $$(".tab").forEach((t) =>
    t.addEventListener("click", () => { if (!t.disabled) showTab(t.dataset.tab); })
  );

  // ---- helpers -------------------------------------------------------------
  const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  function ringColor(score) {
    if (score >= 80) return "var(--ok)";
    if (score >= 55) return "var(--warn)";
    return "var(--bad)";
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
    );
  }
  function fmtDate(iso, ts) {
    try {
      const d = iso ? new Date(iso) : new Date((ts || 0) * 1000);
      return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) +
        " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    } catch (_) { return iso || ""; }
  }
  // YYYYMMDD of the current scan (for download filenames), falling back to today.
  function scanYmd() {
    const s = (lastPayload && lastPayload.scan) || {};
    let d;
    try { d = s.started_at_iso ? new Date(s.started_at_iso) : (s.started_at ? new Date(s.started_at * 1000) : new Date()); }
    catch (_) { d = new Date(); }
    if (isNaN(d.getTime())) d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return "" + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate());
  }
  // Collision-safe stem for the .age exports you collect: org code + date +
  // first 8 of the random device pseudonym. So two same-day files from different
  // devices never share a name. Aggregation still keys on the payload, not this.
  function exportStem() {
    const s = (lastPayload && lastPayload.scan) || {};
    const org = String(s.org_code || "").toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 16);
    const pseudo = String(s.device_pseudonym || "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 8) || "device";
    const parts = ["ComputerCheck"];
    if (org) parts.push(org);
    parts.push(scanYmd(), pseudo);
    return parts.join("-");
  }

  // ---- scan ----------------------------------------------------------------
  const scanBtn = $("#scan-btn");
  const scanStatus = $("#scan-status");
  const progress = $("#progress");

  scanBtn.addEventListener("click", async () => {
    if (!TAURI) {
      scanStatus.textContent = "This needs the ComputerCheck app (download required). Preview cannot scan.";
      return;
    }
    scanBtn.disabled = true;
    progress.classList.remove("hidden");
    scanStatus.textContent = "Scanning… read-only, this stays on your device.";
    const orgCode = (localStorage.getItem(ORG_KEY) || "").trim();
    try {
      const raw = await TAURI.invoke("run_scan", { orgCode: orgCode || null });
      const payload = JSON.parse(raw);
      if (payload.error) throw new Error(payload.error);
      lastPayload = payload;
      // persist a copy in encrypted history
      try { await TAURI.invoke("history_append", { record: raw }); } catch (e) { console.warn("history_append failed", e); }
      renderReport(payload);
      $("#tab-report").disabled = false;
      showTab("report");
    } catch (e) {
      scanStatus.textContent = "Scan failed: " + (e && e.message ? e.message : e);
    } finally {
      scanBtn.disabled = false;
      progress.classList.add("hidden");
    }
  });

  // ---- report --------------------------------------------------------------
  function renderReport(p) {
    $("#report-empty").classList.add("hidden");
    $("#report-body").classList.remove("hidden");

    const score = (p.summary && typeof p.summary.score === "number") ? p.summary.score : 0;
    const ring = $("#score-ring");
    ring.style.setProperty("--p", score);
    ring.style.setProperty("--ring", ringColor(score));
    $("#score-val").textContent = score;

    const s = p.scan || {};
    $("#report-sub").textContent =
      [s.os_name, s.os_version, s.arch].filter(Boolean).join(" · ") + " · " + fmtDate(s.started_at_iso, s.started_at);

    // status chips
    const counts = (p.summary && p.summary.by_status) || {};
    const chips = $("#status-chips");
    chips.innerHTML = "";
    [["PASS", "pass"], ["FAIL", "fail"], ["WARN", "warn"], ["ERROR", "error"], ["SKIP", "skip"]].forEach(([k, cls]) => {
      if (counts[k]) {
        const c = document.createElement("span");
        c.className = "chip " + cls;
        c.textContent = counts[k] + " " + k.toLowerCase();
        chips.appendChild(c);
      }
    });

    const findings = Array.isArray(p.findings) ? p.findings : [];

    // urgent banner if any CRITICAL FAIL
    const critical = findings.filter((f) => f.status === "FAIL" && f.severity === "CRITICAL");
    $("#urgent-banner").classList.toggle("hidden", critical.length === 0);

    // IoC / spyware urgent channel: only when an actual IoC-class hit is present.
    const iocHits = findings.filter((f) => isIoC(f) && (f.status === "FAIL" || f.status === "WARN"));
    $("#ioc-urgent").classList.toggle("hidden", iocHits.length === 0);

    // populate the export panel
    populateExportPanel(p, findings);

    // top fixes: FAIL then WARN, by severity
    const actionable = findings
      .filter((f) => f.status === "FAIL" || f.status === "WARN")
      .sort((a, b) => {
        if (a.status !== b.status) return a.status === "FAIL" ? -1 : 1;
        return (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9);
      });
    const topWrap = $("#top-fixes");
    if (actionable.length === 0) {
      topWrap.innerHTML = '<p class="muted">Nothing urgent. Your device passed the checks that ran.</p>';
    } else {
      topWrap.innerHTML = "";
      actionable.slice(0, 5).forEach((f) => topWrap.appendChild(findingEl(f, true)));
    }

    // all findings
    const allWrap = $("#all-findings");
    allWrap.innerHTML = "";
    findings.forEach((f) => allWrap.appendChild(findingEl(f, false)));
  }

  function findingEl(f, open) {
    const el = document.createElement("div");
    el.className = "finding sev-" + (f.severity || "INFO") + (open ? " open" : "");
    const fix = f.remediation
      ? '<div class="fix"><b>How to fix</b><br>' + esc(f.remediation) + "</div>"
      : "";
    const interim = (f.interim_mitigation && f.status === "FAIL")
      ? '<div class="fix"><b>If you cannot do that yet</b><br>' + esc(f.interim_mitigation) + "</div>"
      : "";
    el.innerHTML =
      '<div class="f-top">' +
        '<span class="st ' + esc(f.status) + '">' + esc(f.status) + "</span>" +
        '<span class="f-title">' + esc(f.title) + "</span>" +
        '<span class="f-sev">' + esc(f.severity) + "</span>" +
      "</div>" +
      '<div class="f-body">' + esc(f.description) + fix + interim + "</div>";
    el.querySelector(".f-top").addEventListener("click", () => el.classList.toggle("open"));
    return el;
  }

  // ---- PDF export in EN / ES / DE (on request only) -----------------------
  $$(".pdf-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!TAURI || !window.__TAURI__.dialog || !lastPayload) return;
      const lang = btn.dataset.pdfLang || "en";
      const status = $("#pdf-status");
      const uiEs = document.documentElement.lang === "es";
      try {
        const dest = await window.__TAURI__.dialog.save({
          defaultPath: "ComputerCheck-" + scanYmd() + "-report-" + lang + ".pdf",
          filters: [{ name: "PDF", extensions: ["pdf"] }],
        });
        if (!dest) return;
        status.textContent = uiEs ? "Generando PDF…" : "Generating PDF…";
        await TAURI.invoke("export_pdf", { payload: JSON.stringify(lastPayload), lang, dest });
        status.textContent = uiEs ? "PDF guardado." : "PDF saved.";
      } catch (e) {
        status.textContent = (uiEs ? "Falló: " : "Failed: ") + (e && e.message ? e.message : e);
      }
    });
  });

  // ---- encrypted export to C-LAB (Phase 2) --------------------------------
  // IoC-class = a finding mapped to a spyware indicator feed. These never go in
  // the routine export; they travel only through the urgent channel, with consent.
  function isIoC(f) {
    const std = f.standards || [];
    return std.indexOf("Citizen Lab IoCs") !== -1 || std.indexOf("Amnesty MVT") !== -1;
  }

  function populateExportPanel(p, findings) {
    const es = document.documentElement.lang === "es";
    const s = p.scan || {};
    $("#exp-org").textContent = s.org_code || (es ? "(ninguno)" : "(none)");
    $("#exp-pseudo").textContent = (s.device_pseudonym || "").slice(0, 12) + "…";
    $("#exp-count").textContent = findings.filter((f) => !isIoC(f)).length;
  }

  async function saveAge(defaultName, payloadObj, statusEl) {
    const es = document.documentElement.lang === "es";
    if (!TAURI || !window.__TAURI__.dialog || !lastPayload) return;
    try {
      const dest = await window.__TAURI__.dialog.save({
        defaultPath: defaultName,
        filters: [{ name: "Encrypted (age)", extensions: ["age"] }],
      });
      if (!dest) return;
      statusEl.textContent = es ? "Cifrando…" : "Encrypting…";
      await TAURI.invoke("export_encrypted", { payload: JSON.stringify(payloadObj), dest });
      statusEl.textContent = es ? "Archivo cifrado creado. Envíalo a C-LAB cuando quieras." : "Encrypted file created. Send it to C-LAB whenever you like.";
    } catch (e) {
      statusEl.textContent = (es ? "Falló: " : "Failed: ") + (e && e.message ? e.message : e);
    }
  }

  const exportBtn = $("#export-btn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (!lastPayload) return;
      const routine = Object.assign({}, lastPayload, {
        export_kind: "routine",
        findings: lastPayload.findings.filter((f) => !isIoC(f)),
      });
      saveAge(exportStem() + ".age", routine, $("#export-status"));
    });
  }

  const iocConsent = $("#ioc-consent"), iocBtn = $("#ioc-send-btn");
  if (iocConsent && iocBtn) {
    iocConsent.addEventListener("change", () => { iocBtn.disabled = !iocConsent.checked; });
    iocBtn.addEventListener("click", () => {
      if (!lastPayload || !iocConsent.checked) return;
      const urgent = Object.assign({}, lastPayload, { export_kind: "urgent" });
      saveAge(exportStem() + "-URGENT.age", urgent, $("#ioc-status"));
    });
  }

  // ---- history -------------------------------------------------------------
  const STATUS_COLORS = { PASS: "var(--ok)", FAIL: "var(--bad)", WARN: "var(--warn)", ERROR: "var(--mid,#8893a0)", SKIP: "var(--dim,#6b7785)" };

  async function renderHistory() {
    if (!TAURI) {
      $("#history-empty").textContent = "History needs the ComputerCheck app.";
      return;
    }
    let arr = [];
    try { arr = JSON.parse(await TAURI.invoke("history_load")); } catch (_) { arr = []; }
    const empty = $("#history-empty"), charts = $("#charts"), list = $("#history-list"), listHead = $("#history-list-head");
    if (!arr.length) {
      empty.classList.remove("hidden"); charts.classList.add("hidden"); listHead.classList.add("hidden"); list.innerHTML = "";
      return;
    }
    empty.classList.add("hidden");
    charts.classList.remove("hidden");
    listHead.classList.remove("hidden");

    // normalize + sort chronologically
    const rows = arr.map((p) => ({
      score: (p.summary && p.summary.score) || 0,
      counts: (p.summary && p.summary.by_status) || {},
      iso: (p.scan && p.scan.started_at_iso) || "",
      ts: (p.scan && p.scan.started_at) || 0,
    })).sort((a, b) => (a.ts || 0) - (b.ts || 0));

    renderKpis(rows);
    $("#chart-score").innerHTML = svgScoreChart(rows);
    $("#score-range").textContent = rows.length + (document.documentElement.lang === "es" ? " análisis" : " scans");
    $("#chart-status").innerHTML = svgStatusChart(rows);
    renderStatusLegend();

    // list newest first, with delta vs previous
    list.innerHTML = "";
    rows.slice().reverse().forEach((r, i, revArr) => {
      const prev = revArr[i + 1];
      let delta = "", dcls = "flat";
      if (prev) {
        const d = r.score - prev.score;
        if (d > 0) { delta = "▲ +" + d; dcls = "up"; }
        else if (d < 0) { delta = "▼ " + d; dcls = "down"; }
        else { delta = "= 0"; dcls = "flat"; }
      } else { delta = document.documentElement.lang === "es" ? "primero" : "first"; }
      const fails = r.counts.FAIL || 0, warns = r.counts.WARN || 0;
      const row = document.createElement("div");
      row.className = "hist-row";
      row.innerHTML =
        '<span class="hs" style="color:' + ringColor(r.score) + '">' + r.score + "</span>" +
        '<div class="hmeta"><div class="hd">' + esc(fmtDate(r.iso, r.ts)) + "</div>" +
        '<div class="mono-dim small">' + fails + " fail · " + warns + " warn</div></div>" +
        '<span class="hdelta ' + dcls + '">' + esc(delta) + "</span>";
      list.appendChild(row);
    });
  }

  function renderKpis(rows) {
    const latest = rows[rows.length - 1];
    const first = rows[0];
    const best = Math.max.apply(null, rows.map((r) => r.score));
    const change = latest.score - first.score;
    const es = document.documentElement.lang === "es";
    const card = (label, value, color) =>
      '<div class="kpi"><div class="kpi-v" style="color:' + (color || "var(--fg,#e8edf1)") + '">' + value + "</div>" +
      '<div class="kpi-l">' + label + "</div></div>";
    const sign = change > 0 ? "+" : "";
    $("#kpis").innerHTML =
      card(es ? "Actual" : "Current", latest.score, ringColor(latest.score)) +
      card(es ? "Mejor" : "Best", best, "var(--ok)") +
      card(es ? "Cambio total" : "Total change", sign + change, change >= 0 ? "var(--ok)" : "var(--bad)") +
      card(es ? "Análisis" : "Scans", rows.length, "var(--accent)");
  }

  // Inline SVG line+area chart of score over time (CSP-safe, no external libs).
  function svgScoreChart(rows) {
    const W = 600, H = 170, padL = 28, padR = 12, padT = 14, padB = 22;
    const iw = W - padL - padR, ih = H - padT - padB;
    const n = rows.length;
    const x = (i) => padL + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (s) => padT + ih - (s / 100) * ih;
    const pts = rows.map((r, i) => [x(i), y(r.score)]);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const area = "M" + x(0).toFixed(1) + " " + y(0).toFixed(1) + " " +
      pts.map((p) => "L" + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ") +
      " L" + x(n - 1).toFixed(1) + " " + y(0).toFixed(1) + " Z";
    let grid = "";
    [0, 25, 50, 75, 100].forEach((g) => {
      const gy = y(g).toFixed(1);
      grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (W - padR) + '" y2="' + gy + '" class="grid"/>' +
        '<text x="' + (padL - 6) + '" y="' + (parseFloat(gy) + 3) + '" class="ax" text-anchor="end">' + g + "</text>";
    });
    let dots = "";
    pts.forEach((p, i) => {
      dots += '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="3.5" fill="' + ringColor(rows[i].score) + '"/>';
    });
    // label last point
    const last = pts[n - 1];
    dots += '<text x="' + last[0].toFixed(1) + '" y="' + (last[1] - 8).toFixed(1) + '" class="ptlab" text-anchor="middle">' + rows[n - 1].score + "</text>";
    return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img">' +
      '<defs><linearGradient id="cc-area" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="var(--accent)" stop-opacity="0.28"/>' +
      '<stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>' +
      grid +
      '<path d="' + area + '" fill="url(#cc-area)"/>' +
      '<path d="' + line + '" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
      dots + "</svg>";
  }

  // Inline SVG stacked bars: status composition per scan.
  function svgStatusChart(rows) {
    const order = ["FAIL", "WARN", "ERROR", "SKIP", "PASS"];
    const W = 600, H = 150, padT = 10, padB = 18;
    const ih = H - padT - padB;
    const n = rows.length;
    const slot = W / n;
    const bw = Math.min(38, slot * 0.6);
    let bars = "";
    rows.forEach((r, i) => {
      const total = order.reduce((s, k) => s + (r.counts[k] || 0), 0) || 1;
      const cx = i * slot + slot / 2;
      let yTop = padT;
      order.forEach((k) => {
        const v = r.counts[k] || 0;
        if (!v) return;
        const h = (v / total) * ih;
        bars += '<rect x="' + (cx - bw / 2).toFixed(1) + '" y="' + yTop.toFixed(1) +
          '" width="' + bw.toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + STATUS_COLORS[k] + '"><title>' +
          k + ": " + v + "</title></rect>";
        yTop += h;
      });
      if (n <= 16) {
        bars += '<text x="' + cx.toFixed(1) + '" y="' + (H - 6) + '" class="ax" text-anchor="middle">' + (i + 1) + "</text>";
      }
    });
    return '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img">' + bars + "</svg>";
  }

  function renderStatusLegend() {
    const labels = { PASS: "pass", FAIL: "fail", WARN: "warn", SKIP: "skip", ERROR: "error" };
    $("#status-legend").innerHTML = ["FAIL", "WARN", "PASS", "SKIP"].map((k) =>
      '<span class="lg"><i style="background:' + STATUS_COLORS[k] + '"></i>' + labels[k] + "</span>"
    ).join("");
  }

  $("#wipe-btn").addEventListener("click", async () => {
    if (!TAURI) return;
    if (!confirm("Permanently delete your local scan history? This cannot be undone.")) return;
    try { await TAURI.invoke("history_wipe"); } catch (e) { console.warn(e); }
    renderHistory();
  });

  // ---- org code persistence ------------------------------------------------
  const orgInput = $("#org-code");
  if (orgInput) {
    orgInput.value = localStorage.getItem(ORG_KEY) || "";
    orgInput.addEventListener("input", () => localStorage.setItem(ORG_KEY, orgInput.value.trim()));
  }

  // ---- bilingual EN/ES (leaf swap; node.js leaves i18n per-tool) ----------
  // Static chrome is bilingual. Dynamic findings come from the engine in
  // English (Phase 1); per-finding ES is a later engine task.
  const LANG_KEY = "argus_lang";
  function applyLang(lang) {
    const es = lang === "es";
    document.documentElement.lang = lang;
    try { localStorage.setItem(LANG_KEY, lang); } catch (_) {}
    $$("[data-en]").forEach((el) => {
      const v = es ? el.dataset.es : el.dataset.en;
      if (v != null) el.textContent = v;
    });
    $$("[data-en-ph]").forEach((el) => {
      const v = es ? el.dataset.esPh : el.dataset.enPh;
      if (v != null) el.placeholder = v;
    });
    $$("[data-set-lang]").forEach((b) => b.classList.toggle("on", b.dataset.setLang === lang));
  }
  $$("[data-set-lang]").forEach((b) =>
    b.addEventListener("click", () => applyLang(b.dataset.setLang))
  );
  applyLang((localStorage.getItem(LANG_KEY) === "es") ? "es" : "en");

  // ---- external links via the shell ---------------------------------------
  $$("[data-extlink]").forEach((a) =>
    a.addEventListener("click", (e) => {
      if (TAURI) { e.preventDefault(); TAURI.invoke("open_url", { url: a.href }).catch(() => {}); }
    })
  );
})();
