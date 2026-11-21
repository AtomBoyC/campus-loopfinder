/* LoopFinder Desktop Console Frontend (100% Offline, Zero External CDNs) */

const state = {
  system: null,
  snap: null,
  lastAudioAt: 0,
  lastRecoveryAt: 0,
  lastSyslogAlertTs: 0,
  currentSnmp: null,
  inventory: [],
  bisect: null,
  audioCtx: null,
  eventSource: null,
};

const $ = (id) => document.getElementById(id);

function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* =========================================================================
   Toast Notifications & Theme Toggle
   ========================================================================= */
function showToast(msg, type = "info", durationMs = 3600) {
  const container = $("toastContainer");
  if (!container) return;
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transition = "opacity 0.25s ease";
    setTimeout(() => el.remove(), 260);
  }, durationMs);
}

function applyTheme(theme) {
  const t = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  localStorage.setItem("loopfinder_theme", t);
  const btn = $("btnThemeToggle");
  if (btn) btn.textContent = t === "dark" ? "☀️ 亮色" : "🌙 暗色";
  if (state.snap?.history) renderChart(state.snap.history);
}

/* =========================================================================
   Web Audio Radar (No external audio files needed — works offline macOS/Win)
   ========================================================================= */
function playTone(type) {
  if (!$("soundEnabled")?.checked) return;
  try {
    if (!state.audioCtx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return;
      state.audioCtx = new AC();
    }
    if (state.audioCtx.state === "suspended") state.audioCtx.resume();
    const ctx = state.audioCtx;
    const now = ctx.currentTime;

    if (type === "danger") {
      [0, 0.16].forEach((offset) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(760, now + offset);
        gain.gain.setValueAtTime(0.08, now + offset);
        gain.gain.exponentialRampToValueAtTime(0.001, now + offset + 0.12);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + offset);
        osc.stop(now + offset + 0.13);
      });
    } else if (type === "syslog") {
      [880, 1174].forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(freq, now + i * 0.11);
        gain.gain.setValueAtTime(0.1, now + i * 0.11);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.11 + 0.14);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + i * 0.11);
        osc.stop(now + i * 0.11 + 0.15);
      });
    } else if (type === "recovered") {
      [523.25, 659.25, 783.99, 1046.5].forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(freq, now + i * 0.09);
        gain.gain.setValueAtTime(0.14, now + i * 0.09);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.09 + 0.25);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + i * 0.09);
        osc.stop(now + i * 0.09 + 0.26);
      });
    }
  } catch (e) {}
}

/* =========================================================================
   API Helpers
   ========================================================================= */
async function apiGet(url) {
  const res = await fetch(url);
  return res.json();
}

async function apiPost(url, data = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return res.json();
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
  if (tabName === "ledger") loadLedger();
  if (tabName === "snmp") loadInventory();
  if (tabName === "ops") loadSerialPorts();
}

/* =========================================================================
   System Init & Interface Loader
   ========================================================================= */
async function loadSystem() {
  const data = await apiGet("/api/system");
  state.system = data;
  $("appVersion").textContent = `v${data.version}`;

  const sel = $("ifaceSelect");
  sel.innerHTML = "";

  const simOpt = document.createElement("option");
  simOpt.value = "__SIMULATION__";
  simOpt.textContent = "✨ [仿真演练模式] 模拟 302 大教研室路由器环路 + 私接 TP-LINK";
  sel.appendChild(simOpt);

  (data.interfaces || []).forEach((iface) => {
    const opt = document.createElement("option");
    opt.value = iface.name;
    const tag = iface.is_wired ? "🔌有线" : (iface.is_wifi ? "📶无线" : "🌐网卡");
    opt.textContent = `${tag} · ${iface.label}`;
    sel.appendChild(opt);
  });

  const caps = data.capabilities || {};
  $("btnGrantBpf").classList.add("hidden");
  $("btnDownloadNpcap").classList.add("hidden");
  if (caps.can_live_capture) {
    const bestWired = (data.interfaces || []).find((i) => i.active && i.is_wired)
      || (data.interfaces || []).find((i) => i.active);
    if (bestWired) sel.value = bestWired.name;
    $("envBanner").classList.add("hidden");
  } else {
    sel.value = "__SIMULATION__";
    if (caps.os === "Darwin") {
      $("envBannerText").textContent = "⚠️ 尚未开启有线抓包权限（点右侧按钮弹窗输入 Mac 开机密码即可立即开启；若只查机房交换机或演练则无需开启）";
      $("btnGrantBpf").classList.remove("hidden");
    } else if (caps.os === "Windows" && !caps.has_npcap) {
      $("envBannerText").textContent = "⚠️ 如需在教研室实时抓包，请先安装 Npcap 驱动（安装时勾选 WinPcap 兼容模式，装完重启软件）；机房 SNMP / Console / 演练模式已可直接用";
      $("btnDownloadNpcap").classList.remove("hidden");
    } else {
      $("envBannerText").textContent = `⚠️ ${caps.hint || "当前无二层原始抓包权限，可直接使用仿真演练模式或弱电间 SNMP 排查。"}`;
    }
    $("envBanner").classList.remove("hidden");
  }
}

/* =========================================================================
   Live SSE Stream + Rendering (Tab 1 + Syslog Live Radar)
   ========================================================================= */
function connectSSE() {
  if (state.eventSource) state.eventSource.close();
  const es = new EventSource("/api/events");
  es.onmessage = (ev) => {
    try {
      const snap = JSON.parse(ev.data);
      renderSnapshot(snap);
    } catch (e) {}
  };
  es.onerror = () => {
    es.close();
    setTimeout(connectSSE, 2000);
  };
  state.eventSource = es;
}

function renderSnapshot(snap) {
  state.snap = snap;
  const now = Date.now();

  $("btnStartCapture").classList.toggle("hidden", snap.running);
  $("btnStopCapture").classList.toggle("hidden", !snap.running);
  $("simControlBar").classList.toggle("hidden", !(snap.running && snap.simulation?.active));
  $("pcapCount").textContent = snap.pcap_count ?? 0;

  if (snap.sensitivity && $("sensitivitySelect").value !== snap.sensitivity) {
    $("sensitivitySelect").value = snap.sensitivity;
  }

  if (snap.simulation?.active) {
    $("btnSimUnplug").classList.toggle("hidden", !snap.simulation.loop_active);
    $("btnSimReplug").classList.toggle("hidden", snap.simulation.loop_active);
  }

  // Mini Topbar Status Pill (visible across all tabs while capture runs)
  const mini = $("miniStatusPill");
  if (snap.running) {
    mini.classList.remove("hidden", "loop", "normal", "warn");
    const bcast = Math.round(snap.latest?.broadcast_pps || 0);
    if (snap.status === "LOOP_DETECTED") {
      mini.classList.add("loop");
      mini.textContent = `🔴 现场环路 (${bcast} pps)`;
    } else if (snap.status === "WARNING") {
      mini.classList.add("warn");
      mini.textContent = `🟡 现场预警 (${bcast} pps)`;
    } else {
      mini.classList.add("normal");
      mini.textContent = `🟢 现场正常 (${bcast} pps)`;
    }
  } else {
    mini.classList.add("hidden");
  }

  // Hero Status
  const hero = $("statusHero");
  hero.classList.remove("status-idle", "status-normal", "status-warning", "status-loop", "status-recovered");
  const badge = $("heroBadge");
  const title = $("heroTitle");
  const reasons = $("heroReasons");

  if (!snap.running) {
    hero.classList.add("status-idle");
    badge.textContent = "待机中";
    title.textContent = snap.last_error
      ? `监测停止：${snap.last_error}`
      : "请选择教研室接入网卡后点击「开始监测」，或直接体验仿真演练";
    reasons.textContent = "支持主动二层探针、重复广播帧爆发识别、私接路由器/ARP冲突捕手与 LLDP 上联交换机自动识别。";
  } else if (snap.status === "LOOP_DETECTED") {
    hero.classList.add("status-loop");
    badge.textContent = "🚨 确认环路";
    title.textContent = "检测到活跃二层环路 / 广播风暴！请使用右侧二分法拔线或排查上联交换机";
    reasons.textContent = (snap.reasons || []).join(" ｜ ") || "持续监测异常流量";
    if (now - state.lastAudioAt > 4500) {
      playTone("danger");
      state.lastAudioAt = now;
    }
  } else if (snap.just_recovered) {
    hero.classList.add("status-recovered");
    badge.textContent = "✅ 环路已断开";
    title.textContent = "风暴瞬间消退！刚刚拔掉的那根网线 / 支路极可能就是环路源头！";
    reasons.textContent = `广播速率已回落至 ${snap.latest.broadcast_pps} pps（历史峰值 ${snap.peak_broadcast_pps} pps）`;
    if (now - state.lastRecoveryAt > 8000) {
      playTone("recovered");
      state.lastRecoveryAt = now;
    }
  } else if (snap.status === "WARNING") {
    hero.classList.add("status-warning");
    badge.textContent = "⚠️ 疑似异常";
    title.textContent = "发现私接小路由器、ARP 冲突或轻度广播异常，建议核查下方清单";
    reasons.textContent = (snap.reasons || []).join(" ｜ ");
  } else {
    hero.classList.add("status-normal");
    badge.textContent = "🟢 网络正常";
    const silentWarn = snap.seconds_since_frame !== null && snap.seconds_since_frame > 8
      ? `（提示：已 ${snap.seconds_since_frame}s 未收到新数据帧，请确认网线是否插紧）`
      : "";
    title.textContent = `正在监听 ${snap.interface}（未检测到二层环路风暴）${silentWarn}`;
    reasons.textContent = snap.probe_mode === "active"
      ? `主动探针 0x88B5 已发送 #${snap.probe_seq} 帧，零回环`
      : "纯被动听诊模式运行中，零额外发包";
  }

  $("heroConfidence").textContent = snap.loop_confidence ?? 0;

  // ARP Conflict Banner
  const conflicts = snap.arp_conflicts || [];
  const cBanner = $("arpConflictBanner");
  if (conflicts.length > 0) {
    cBanner.classList.remove("hidden");
    $("arpConflictList").innerHTML = conflicts.map((c) => `
      <div style="margin-bottom:4px;">
        <strong>IP <code>${esc(c.ip)}</code>${c.is_gateway ? " (疑似网关!)" : ""}</strong>
        同时被多个 MAC 宣称：${esc((c.vendors || []).join(" ↔ "))}
      </div>
    `).join("");
  } else {
    cBanner.classList.add("hidden");
  }

  // KPIs
  const lat = snap.latest || {};
  $("kpiBroadcast").innerHTML = `${Math.round(lat.broadcast_pps || 0)} <small>pps</small>`;
  $("kpiPeakBcast").textContent = Math.round(snap.peak_broadcast_pps || 0);
  $("kpiTotal").textContent = Math.round(lat.total_pps || 0);
  $("kpiDup").innerHTML = `${Math.round(lat.dup_pps || 0)} <small>pps</small>`;
  $("kpiDupRatio").textContent = Math.round(lat.dup_ratio || 0);
  $("kpiArp").textContent = Math.round(lat.arp_pps || 0);
  $("kpiProbeEcho").innerHTML = `${snap.probe_echo_total || 0} <small>次</small>`;
  if (snap.probe_paused_by_safety) {
    $("kpiProbeSub").textContent = "🛡️ 风暴过高已自动暂停发包(防加剧拥塞)";
  } else if (snap.probe_last_rtt_ms !== null && snap.probe_last_rtt_ms !== undefined) {
    $("kpiProbeSub").textContent = `最近回环 RTT: ${snap.probe_last_rtt_ms} ms (近2秒 ${snap.probe_echo_recent} 次)`;
  } else {
    $("kpiProbeSub").textContent = snap.probe_mode === "active"
      ? `已发探针 #${snap.probe_seq || 0} · 源MAC ${snap.probe_mac || "-"}`
      : "当前为纯被动只读模式";
  }

  const rogues = (snap.dhcp_servers || []).filter((s) => s.is_rogue);
  $("kpiRogueCount").innerHTML = `${rogues.length} <small>台</small>`;
  $("kpiRogueSub").textContent = rogues.length > 0
    ? `头号嫌疑: ${rogues[0].server_ip} (${rogues[0].model_hint || rogues[0].vendor})`
    : "白名单外异常 DHCP/ARP 告警";

  // Upstream Switch & STP
  if (snap.upstream_switch) {
    const u = snap.upstream_switch;
    const loc = u.location ? ` · 📍${u.location}` : "";
    $("upstreamText").innerHTML =
      `<span class="pill pill-info">${esc(u.protocol || "LLDP")}</span> `
      + `<strong>${esc(u.sys_name || "未知交换机")}</strong> · 端口 <code>${esc(u.port_id || "-")}</code>`
      + (u.mgmt_ip ? ` · IP <code>${esc(u.mgmt_ip)}</code>` : "")
      + (u.vlan_id ? ` · VLAN ${esc(u.vlan_id)}` : "")
      + esc(loc);
    const btnUp = $("btnInspectUpstream");
    if (u.mgmt_ip) {
      btnUp.classList.remove("hidden");
      btnUp.dataset.ip = u.mgmt_ip;
      btnUp.dataset.sim = snap.simulation?.active ? "1" : "0";
    }
  } else {
    $("upstreamText").textContent = "监听中（网管交换机通常每 30 秒发送一次 LLDP/CDP，无需配置）";
    $("btnInspectUpstream").classList.add("hidden");
  }

  if (snap.stp_info) {
    const s = snap.stp_info;
    $("stpText").innerHTML =
      `根桥 <code>${esc(s.root_mac || "-")}</code> (${esc(s.root_vendor || "")}) · 优先级 ${esc(s.root_priority)} · TC震荡累计 ${snap.stp_tc_total || 0}`;
  } else {
    $("stpText").textContent = "暂未收到 STP BPDU（家用路由器/傻瓜交换机通常不发 BPDU）";
  }

  renderChart(snap.history || []);
  renderDhcpList(snap.dhcp_servers || []);
  renderDupList(snap.dup_clusters || []);
  renderTalkers(snap.top_talkers || []);
  renderEvents(snap.events || []);

  if (snap.syslog) renderSyslogState(snap.syslog);
}

/* =========================================================================
   Live HiDPI Canvas Storm Chart (Theme-aware)
   ========================================================================= */
function renderChart(history) {
  const canvas = $("stormChart");
  if (!canvas) return;
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(300, Math.floor(rect.width));
  const h = 215;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const padL = 48, padR = 14, padT = 16, padB = 24;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  let maxVal = 100;
  history.forEach((pt) => {
    maxVal = Math.max(maxVal, pt.total_pps || 0, pt.broadcast_pps || 0, pt.dup_pps || 0);
  });
  maxVal = Math.ceil(maxVal * 1.15 / 50) * 50;

  ctx.strokeStyle = isLight ? "#e2e8f0" : "#1e293b";
  ctx.fillStyle = isLight ? "#64748b" : "#8ea0bc";
  ctx.font = "11px monospace";
  for (let i = 0; i <= 4; i++) {
    const y = padT + (plotH * i) / 4;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.fillText(String(Math.round(maxVal * (1 - i / 4))), 6, y + 4);
  }

  if (history.length < 2) {
    ctx.fillStyle = isLight ? "#64748b" : "#8ea0bc";
    ctx.font = "13px sans-serif";
    ctx.fillText("等待实时数据...", padL + plotW / 2 - 42, padT + plotH / 2);
    return;
  }

  const drawSeries = (key, color, fillAlpha = 0) => {
    ctx.beginPath();
    history.forEach((pt, idx) => {
      const x = padL + (plotW * idx) / Math.max(1, history.length - 1);
      const y = padT + plotH - (Math.min(maxVal, pt[key] || 0) / maxVal) * plotH;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();

    if (fillAlpha > 0) {
      ctx.lineTo(padL + plotW, padT + plotH);
      ctx.lineTo(padL, padT + plotH);
      ctx.closePath();
      ctx.fillStyle = color.replace(")", `, ${fillAlpha})`).replace("rgb(", "rgba(");
      ctx.fill();
    }
  };

  drawSeries("total_pps", "rgb(148, 163, 184)", 0.06);
  drawSeries("arp_pps", "rgb(56, 189, 248)", 0.08);
  drawSeries("dup_pps", "rgb(245, 158, 11)", 0.12);
  drawSeries("broadcast_pps", "rgb(239, 68, 68)", 0.16);

  ctx.fillStyle = isLight ? "#64748b" : "#8ea0bc";
  ctx.font = "10.5px monospace";
  ctx.fillText(history[0].label || "", padL, h - 6);
  ctx.fillText(history[history.length - 1].label || "", w - padR - 54, h - 6);
}

/* =========================================================================
   Tab 1 Tables
   ========================================================================= */
function renderDhcpList(servers) {
  const wrap = $("dhcpList");
  if (!servers.length) {
    wrap.innerHTML = `<div class="empty-hint">暂未捕获到 DHCP/ARP 异常路由器，可点击上方「📡 扫私接路由」主动探测。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>判定</th><th>网关 IP</th><th>MAC 地址</th><th>厂商</th><th>识别型号(Web)</th><th>来源/下发IP</th></tr></thead>
    <tbody>${servers.map((s) => `
      <tr>
        <td>${s.is_rogue ? `<span class="pill pill-danger">私接非法</span>` : `<span class="pill pill-ok">合法白名单</span>`}</td>
        <td class="mono">${esc(s.server_ip)}</td>
        <td class="mono"><a href="#" class="mac-jump" data-mac="${esc(s.server_mac)}">${esc(s.server_mac)}</a></td>
        <td>${esc(s.vendor)}</td>
        <td><strong>${esc(s.model_hint || s.web_title || "-")}</strong></td>
        <td class="mono">${esc(s.offered_ip || "-")}</td>
      </tr>`).join("")}
    </tbody></table>`;
}

function renderDupList(dups) {
  const wrap = $("dupList");
  if (!dups.length) {
    wrap.innerHTML = `<div class="empty-hint">正常网络无连续重复广播帧；若出现环路，此处立即列出循环反射的源 MAC 与厂商。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>源 MAC</th><th>厂商 / 类型</th><th>重复帧内容</th><th>重复计数</th></tr></thead>
    <tbody>${dups.map((d) => `
      <tr>
        <td class="mono"><a href="#" class="mac-jump" data-mac="${esc(d.src_mac)}">${esc(d.src_mac)}</a></td>
        <td>${esc(d.vendor)} <span class="pill ${d.category === "soho_router" ? "pill-danger" : "pill-info"}">${esc(d.category_label)}</span></td>
        <td>${esc(d.detail)}</td>
        <td class="mono"><strong>${d.count} 次</strong></td>
      </tr>`).join("")}
    </tbody></table>`;
}

function renderTalkers(talkers) {
  const wrap = $("talkerList");
  if (!talkers.length) {
    wrap.innerHTML = `<div class="empty-hint">开始监测后自动统计。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>MAC (点击反查端口)</th><th>厂商</th><th>类型</th><th>广播包</th><th>总包(占比)</th><th>最近 IP</th></tr></thead>
    <tbody>${talkers.map((t) => `
      <tr>
        <td class="mono"><a href="#" class="mac-jump" data-mac="${esc(t.mac)}">${esc(t.mac)}</a></td>
        <td>${esc(t.vendor)}</td>
        <td>${t.category === "soho_router" ? `<span class="pill pill-danger">${esc(t.category_label)}</span>` : `<span class="muted-sm">${esc(t.category_label)}</span>`}</td>
        <td class="mono">${t.broadcast}</td>
        <td class="mono">${t.packets} (${t.share_pct}%)</td>
        <td class="mono">${esc(t.last_ip || "-")}</td>
      </tr>`).join("")}
    </tbody></table>`;
}

function renderEvents(events) {
  const wrap = $("eventList");
  if (!events.length) {
    wrap.innerHTML = `<div class="empty-hint">等待事件记录...</div>`;
    return;
  }
  wrap.innerHTML = events.map((e) => `
    <div class="ev-item ${esc(e.level)}">
      <span class="ev-time">${esc(e.time_str)}</span>
      <span>${esc(e.message)}</span>
    </div>`).join("");
}

/* =========================================================================
   Guided Bisection Wizard (with Undo & History Log)
   ========================================================================= */
function initBisection() {
  const n = Math.max(2, Math.min(48, parseInt($("bisectTotalPorts").value || "8", 10)));
  const all = Array.from({ length: n }, (_, i) => i + 1);
  state.bisect = {
    allPorts: all,
    candidates: [...all],
    step: 1,
    stack: [],
    logs: [],
  };
  renderBisection();
}

function renderBisection() {
  const box = $("bisectBody");
  const undoBtn = $("btnBisectUndo");
  const b = state.bisect;
  if (!b) {
    undoBtn.classList.add("hidden");
    box.innerHTML = `<div class="empty-hint">点击「开始二分法」生成第一步拔线指令（记住：笔记本那根线千万别拔）。</div>`;
    return;
  }
  undoBtn.classList.toggle("hidden", b.stack.length === 0);

  const logHtml = b.logs.length
    ? `<div class="bisect-log">记录：${esc(b.logs.slice(-3).join(" → "))}</div>`
    : "";

  if (b.candidates.length === 1) {
    const culprit = b.candidates[0];
    const safeOthers = (b.allPorts || []).filter((p) => p !== culprit);
    box.innerHTML = `
      <div class="bisect-step-box">
        <div class="bisect-instruction" style="color:var(--success);">🎯 锁定故障支路！共 ${b.step - 1} 步完成定位</div>
        <div>问题网线 / 小路由器位于：<span class="port-chip culprit">第 ${culprit} 号网口</span></div>
        ${safeOthers.length ? `<div class="muted-sm">✅ 其他已排除的网线（#${safeOthers.join(", #")}）现在都可以全部插回恢复上网。</div>` : ""}
        <div class="muted-sm">顺着第 ${culprit} 号网线查到对应桌位，核查是否有双口回插或家用路由器反接 LAN 口；若下面还有二级小交换机，把笔记本插过去点「开始二分法」继续定位。</div>
        ${logHtml}
      </div>`;
    return;
  }

  const mid = Math.ceil(b.candidates.length / 2);
  const unplugSet = b.candidates.slice(0, mid);
  const keepSet = b.candidates.slice(mid);
  const safeSet = (b.allPorts || []).filter((p) => !b.candidates.includes(p));

  const chips = (b.allPorts || b.candidates).map((p) => {
    if (unplugSet.includes(p)) return `<span class="port-chip unplug">拔 #${p}</span>`;
    if (keepSet.includes(p)) return `<span class="port-chip keep">插 #${p}</span>`;
    return `<span class="port-chip safe">正常 #${p}</span>`;
  }).join("");

  const fmtRange = (arr) => arr.length ? `#${arr.join(", #")}` : "无";

  box.innerHTML = `
    <div class="bisect-step-box">
      <div class="bisect-instruction">第 ${b.step} 步（调整好网线后等 5 秒看颜色/听声音）：</div>
      <div style="font-size:12.5px;line-height:1.7;">
        <div>🔴 <strong>这一步拔掉</strong>：<code>${fmtRange(unplugSet)}</code></div>
        <div>🔵 <strong>这一步插上/保持插着</strong>：<code>${fmtRange(keepSet)}</code>${b.step > 1 ? "（之前拔掉的要插回去）" : ""}</div>
        ${safeSet.length ? `<div>🟢 <strong>已排除（全部插回恢复老师上网）</strong>：<code>${fmtRange(safeSet)}</code></div>` : ""}
      </div>
      <div class="bisect-range">${chips}</div>
      <div class="inline-row gap-sm">
        <button class="btn btn-sm btn-success" id="btnBisectCleared">✅ 拔掉后变绿/风暴消失了</button>
        <button class="btn btn-sm btn-danger" id="btnBisectStillLoop">🚨 拔掉后仍然红灯/风暴还在</button>
      </div>
      ${logHtml}
    </div>`;

  $("btnBisectCleared").onclick = () => {
    b.stack.push({ candidates: [...b.candidates], step: b.step, logs: [...b.logs] });
    b.logs.push(`拔#${unplugSet[0]}-#${unplugSet[unplugSet.length - 1]}恢复`);
    b.candidates = unplugSet;
    b.step += 1;
    renderBisection();
  };
  $("btnBisectStillLoop").onclick = () => {
    b.stack.push({ candidates: [...b.candidates], step: b.step, logs: [...b.logs] });
    b.logs.push(`拔#${unplugSet[0]}-#${unplugSet[unplugSet.length - 1]}仍环路`);
    b.candidates = keepSet;
    b.step += 1;
    renderBisection();
  };
}

/* =========================================================================
   Tab 2: Inventory, Concurrent Sweep, Auto-Hop Tracer & Single Switch Scan
   ========================================================================= */
async function loadInventory() {
  const res = await apiGet("/api/inventory");
  state.inventory = res.switches || [];
  $("invCount").textContent = state.inventory.length;

  const buildings = Array.from(new Set(state.inventory.map((s) => s.building).filter(Boolean)));
  const sel = $("batchBuildingFilter");
  const prev = sel.value;
  sel.innerHTML = `<option value="">全部楼栋 (${state.inventory.length}台)</option>`
    + buildings.map((b) => `<option value="${esc(b)}">${esc(b)}</option>`).join("");
  if (buildings.includes(prev)) sel.value = prev;

  const wrap = $("invTableWrap");
  if (!state.inventory.length) {
    wrap.innerHTML = `<div class="empty-hint">资产簿为空，可在上方新增弱电间交换机。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>IP</th><th>设备名</th><th>楼栋 / 角色</th><th>SNMP</th><th>操作</th></tr></thead>
    <tbody>${state.inventory.map((s) => `
      <tr>
        <td class="mono">${esc(s.ip)}</td>
        <td><strong>${esc(s.name)}</strong></td>
        <td>${esc(s.building)} · <span class="muted-sm">${esc(s.role)}</span></td>
        <td class="mono">v${esc(s.snmp_version || "2c")} / ${esc(s.community || "public")}</td>
        <td class="inline-row gap-xs">
          <button class="btn btn-xs btn-primary inv-scan-btn" data-ip="${esc(s.ip)}" data-comm="${esc(s.community)}" data-ver="${esc(s.snmp_version || "2c")}">扫描</button>
          <button class="btn btn-xs btn-ghost inv-del-btn" data-ip="${esc(s.ip)}">删除</button>
        </td>
      </tr>`).join("")}
    </tbody></table>`;

  wrap.querySelectorAll(".inv-scan-btn").forEach((b) => {
    b.onclick = () => {
      $("snmpCommunity").value = b.dataset.comm || "public";
      $("snmpVersion").value = b.dataset.ver || "2c";
      runSnmpScan({ switch_ip: b.dataset.ip, simulate: false });
    };
  });
  wrap.querySelectorAll(".inv-del-btn").forEach((b) => {
    b.onclick = async () => {
      const r = await apiPost("/api/inventory/delete", { ip: b.dataset.ip });
      if (r.ok) {
        showToast(`已移除设备 ${b.dataset.ip}`, "info");
        loadInventory();
      }
    };
  });
}

async function runBatchScan(simulate = false) {
  const building = $("batchBuildingFilter").value;
  const btn = simulate ? $("btnBatchScanSim") : $("btnBatchScan");
  btn.disabled = true;
  const origText = btn.textContent;
  btn.textContent = "⏳ 并发扫描中...";
  try {
    const res = await apiPost("/api/snmp/batch_scan", { building, simulate, sample_interval: 2.0 });
    if (!res.ok) {
      showToast(res.error || "批量巡检失败", "danger");
      return;
    }
    $("batchResultWrap").classList.remove("hidden");
    const rows = (res.switches || []).map((sw) => `
      <tr class="clickable-row batch-row" data-ip="${esc(sw.switch_ip)}">
        <td><strong>${esc(sw.sys_name)}</strong><div class="muted-sm mono">${esc(sw.switch_ip)} · ${esc(sw.vendor)}</div></td>
        <td>${esc(sw.building || "-")}</td>
        <td class="mono">${sw.cpu_pct !== null && sw.cpu_pct !== undefined ? `${sw.cpu_pct}%` : "-"}</td>
        <td><span class="pill ${sw.max_risk >= 65 ? "pill-danger" : (sw.max_risk >= 25 ? "pill-warn" : "pill-ok")}">${sw.max_risk}分</span></td>
        <td class="mono"><strong>${Math.round(sw.max_bcast_pps)} pps</strong></td>
        <td class="mono">${sw.flap_count > 0 ? `<span class="pill pill-danger">⚡ ${sw.flap_count}条</span>` : "0"}</td>
        <td><code>${esc(sw.top_port)}</code><div class="muted-sm">${esc(sw.top_location || "")}</div></td>
      </tr>`).join("");

    const errNote = res.error_count > 0
      ? `<div class="muted-sm" style="margin-top:6px;color:var(--warning);">⚠️ ${res.error_count} 台设备超时未响应：${esc(res.errors.map((e) => `${e.ip}(${e.error})`).join("；"))}</div>`
      : "";

    $("batchResultTable").innerHTML = `<table>
      <thead><tr><th>交换机</th><th>楼栋</th><th>CPU</th><th>最高风险</th><th>峰值广播</th><th>MAC漂移</th><th>头号可疑口 / 教研室</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="empty-hint">无成功扫描结果</td></tr>`}</tbody>
    </table>${errNote}`;

    $("batchResultTable").querySelectorAll(".batch-row").forEach((tr) => {
      tr.onclick = () => loadCachedSnmp(tr.dataset.ip);
    });

    if (res.history) renderSnmpHistory(res.history);
    if (res.switches?.length) {
      await loadCachedSnmp(res.switches[0].switch_ip);
      showToast(`并发巡检完成：共 ${res.scanned_count} 台（耗时 ${res.elapsed_s}s），已打开头号可疑设备`, "success");
    }
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

async function runHopTrace(simulate = false) {
  const start_ip = ($("hopStartIp").value || "10.10.0.1").trim();
  const target_mac = ($("hopTargetMac").value || "").trim();
  const community = ($("snmpCommunity").value || "public").trim();
  const snmp_version = $("snmpVersion").value || "2c";
  const btn = simulate ? $("btnHopTraceSim") : $("btnHopTrace");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "⏳ 逐跳追踪中...";

  try {
    const res = await apiPost("/api/snmp/trace_hops", {
      start_ip,
      target_mac,
      community,
      snmp_version,
      simulate,
    });
    if (!res.ok) {
      showToast(res.error || "逐跳追踪失败", "danger");
      return;
    }
    $("hopTraceResultCard").classList.remove("hidden");
    $("hopTraceStopReason").textContent = res.stop_reason || "";
    const hops = res.hops || [];
    $("hopChainBox").innerHTML = hops.map((h, i) => {
      const isLast = i === hops.length - 1;
      const arrow = isLast ? "" : `<div class="hop-arrow">➜</div>`;
      return `
        <div class="hop-node ${isLast ? "terminal" : ""}" data-ip="${esc(h.switch_ip)}">
          <div class="inline-row" style="justify-content:space-between;margin-bottom:4px;">
            <span class="pill ${isLast ? "pill-danger" : "pill-info"}">第 ${h.hop} 跳</span>
            <span class="mono muted-sm">${esc(h.switch_ip)}</span>
          </div>
          <div><strong>${esc(h.sys_name)}</strong> <span class="muted-sm">(${esc(h.vendor)})</span></div>
          <div style="margin:5px 0;">出口：<code>${esc(h.port)}</code> · 广播 <strong>${Math.round(h.broadcast_pps || 0)} pps</strong></div>
          ${h.location ? `<div style="color:var(--warning);font-weight:600;">📍 ${esc(h.location)}</div>` : ""}
          <div class="muted-sm" style="margin-top:3px;">${esc(h.note || "")}</div>
        </div>${arrow}`;
    }).join("");

    $("hopChainBox").querySelectorAll(".hop-node").forEach((node) => {
      node.onclick = () => loadCachedSnmp(node.dataset.ip);
    });

    if (res.history) renderSnmpHistory(res.history);
    if (hops.length) {
      await loadCachedSnmp(hops[hops.length - 1].switch_ip);
      showToast(res.stop_reason || "自动逐跳追踪完成", "success", 5000);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

async function loadCachedSnmp(ip) {
  const r = await apiGet(`/api/snmp/result?ip=${encodeURIComponent(ip)}`);
  if (r.ok) {
    state.currentSnmp = r.result;
    $("snmpIp").value = r.result.switch_ip;
    renderSnmpResult(r.result);
  }
}

async function runSnmpScan(opts = {}) {
  const ip = (opts.switch_ip ?? $("snmpIp").value).trim();
  const community = ($("snmpCommunity").value || "public").trim();
  const snmp_version = $("snmpVersion").value || "2c";
  const interval = parseFloat($("snmpInterval").value || "2.5");
  const simulate = Boolean(opts.simulate);

  if (ip) $("snmpIp").value = ip;
  const btn = $("btnSnmpScan");
  btn.disabled = true;
  btn.textContent = simulate ? "⏳ 加载仿真数据..." : `⏳ 双采样中 (${interval}s)...`;

  try {
    const res = await apiPost("/api/snmp/scan", {
      switch_ip: ip || "10.10.1.1",
      community,
      snmp_version,
      sample_interval: interval,
      simulate,
    });
    if (!res.ok) {
      showToast(`SNMP 扫描失败：${res.error}`, "danger", 5000);
      return;
    }
    state.currentSnmp = res.result;
    renderSnmpResult(res.result);
    renderSnmpHistory(res.history || []);
    showToast(`已完成 ${res.result.sys_name} (${res.result.vendor}) 扫描`, "success");
  } catch (e) {
    showToast(`请求失败: ${e}`, "danger");
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 开始双采样扫描";
  }
}

function renderSnmpHistory(items) {
  const bar = $("snmpHistoryBar");
  if (!items.length) {
    bar.classList.add("hidden");
    return;
  }
  bar.classList.remove("hidden");
  bar.innerHTML = `<span class="muted-sm" style="align-self:center;">最近已扫设备（点击切换）：</span>`
    + items.map((it) => `
      <button class="btn btn-xs btn-outline snmp-hist-btn" data-ip="${esc(it.switch_ip)}">
        ${esc(it.sys_name)} (${esc(it.switch_ip)}) · ${it.flap_count > 0 ? "⚡漂移" : (it.suspect_count > 0 ? "⚠️异常" : "正常")}
      </button>
    `).join("");

  bar.querySelectorAll(".snmp-hist-btn").forEach((b) => {
    b.onclick = () => loadCachedSnmp(b.dataset.ip);
  });
}

function renderSnmpResult(r) {
  $("snmpEmpty").classList.add("hidden");
  $("snmpResultArea").classList.remove("hidden");
  $("snmpMacLookupResult").classList.add("hidden");
  $("portDetailBox").classList.add("hidden");

  $("snmpSysName").textContent = `${r.sys_name} (${r.switch_ip})`;
  $("snmpVendor").textContent = r.vendor || "网管交换机";
  $("snmpSimBadge").classList.toggle("hidden", !r.simulated);

  const cpuBadge = $("snmpCpuBadge");
  if (r.cpu_pct !== null && r.cpu_pct !== undefined) {
    cpuBadge.classList.remove("hidden", "pill-danger", "pill-warn", "pill-ok");
    cpuBadge.classList.add(r.cpu_pct >= 80 ? "pill-danger" : (r.cpu_pct >= 50 ? "pill-warn" : "pill-ok"));
    cpuBadge.textContent = `CPU ${r.cpu_pct}%`;
  } else {
    cpuBadge.classList.add("hidden");
  }

  $("snmpSummaryText").textContent = `${r.summary} ｜ STP 拓扑变更累计: ${r.stp_top_changes ?? 0}`;

  const matrix = $("portMatrix");
  matrix.innerHTML = (r.ports || []).map((p, idx) => {
    const tag = p.lldp_neighbor ? `↘${p.lldp_neighbor.remote_sys}` : (p.location ? p.location.split("·").pop() : (p.alias || ""));
    return `
      <div class="port-tile ${esc(p.risk_level)}" data-idx="${idx}" title="${esc(p.name)} · 广播 ${p.broadcast_pps} pps">
        <div class="port-tile-name">${esc(p.short_name)}</div>
        <div class="port-tile-pps">${p.oper_status === "up" ? `${Math.round(p.broadcast_pps)} pps` : "DOWN"}</div>
        <div class="port-tile-tag">${esc(tag || `${p.mac_count} MAC`)}</div>
      </div>`;
  }).join("");

  matrix.querySelectorAll(".port-tile").forEach((el) => {
    el.onclick = () => showPortDetail(r, r.ports[parseInt(el.dataset.idx, 10)]);
  });

  const flapWrap = $("snmpFlapList");
  const flaps = r.mac_flaps || [];
  flapWrap.innerHTML = flaps.length ? `<table>
    <thead><tr><th>漂移 MAC</th><th>厂商</th><th>端口 A</th><th>↔ 端口 B</th></tr></thead>
    <tbody>${flaps.map((f) => `
      <tr>
        <td class="mono"><strong>${esc(f.mac)}</strong></td>
        <td>${esc(f.vendor)} ${f.category === "soho_router" ? `<span class="pill pill-danger">小路由器</span>` : ""}</td>
        <td><code>${esc(f.from_port)}</code><div class="muted-sm">${esc(f.from_location || "")}</div></td>
        <td><code>${esc(f.to_port)}</code><div class="muted-sm">${esc(f.to_location || "")}</div></td>
      </tr>`).join("")}
    </tbody></table>` : `<div class="empty-hint">本次双采样间隔内未观测到 MAC 跨端口漂移。</div>`;

  const susWrap = $("snmpSuspectList");
  const suspects = r.suspect_ports || [];
  susWrap.innerHTML = suspects.length ? `<table>
    <thead><tr><th>端口 / 教研室位置</th><th>风险</th><th>广播 PPS</th><th>MAC数</th><th>判定依据 / 下级追踪</th></tr></thead>
    <tbody>${suspects.map((p) => {
      const drillBtn = p.lldp_neighbor?.remote_ip
        ? `<button class="btn btn-xs btn-primary drill-btn" data-ip="${esc(p.lldp_neighbor.remote_ip)}" data-sim="${r.simulated ? "1" : "0"}">↘ 追踪下级 ${esc(p.lldp_neighbor.remote_sys)}</button>`
        : "";
      return `<tr>
        <td><strong><code>${esc(p.name)}</code></strong><div class="muted-sm">${esc(p.location || p.alias || "未录入台账")}</div></td>
        <td><span class="pill ${p.risk_score >= 65 ? "pill-danger" : "pill-warn"}">${p.risk_score}分</span></td>
        <td class="mono"><strong>${Math.round(p.broadcast_pps)}</strong></td>
        <td class="mono">${p.mac_count}</td>
        <td><div>${esc((p.reasons || []).join("；"))}</div>${drillBtn}</td>
      </tr>`;
    }).join("")}
    </tbody></table>` : `<div class="empty-hint">所有物理端口均处于正常状态。</div>`;

  susWrap.querySelectorAll(".drill-btn").forEach((b) => {
    b.onclick = () => runSnmpScan({ switch_ip: b.dataset.ip, simulate: b.dataset.sim === "1" });
  });
}

function showPortDetail(sw, p) {
  const box = $("portDetailBox");
  box.classList.remove("hidden");
  const lldpHtml = p.lldp_neighbor
    ? `<div><strong>LLDP 下联设备：</strong>${esc(p.lldp_neighbor.remote_sys)} · 对端端口 <code>${esc(p.lldp_neighbor.remote_port)}</code> · IP <code>${esc(p.lldp_neighbor.remote_ip || "未知")}</code> `
      + (p.lldp_neighbor.remote_ip ? `<button class="btn btn-xs btn-primary" id="btnDetailDrill">↘ 扫描这台下级交换机</button>` : "")
      + `</div>`
    : "";

  box.innerHTML = `
    <div class="inline-row" style="justify-content:space-between; flex-wrap:wrap; margin-bottom:6px;">
      <strong>端口详情：<code>${esc(p.name)}</code>（${esc(p.oper_status.toUpperCase())} · STP: ${esc(p.stp_state)}）</strong>
      <div class="inline-row gap-xs">
        ${p.broadcast_direction ? `<span class="pill ${p.broadcast_direction.includes("源头") ? "pill-danger" : "pill-info"}">${esc(p.broadcast_direction)}</span>` : ""}
        <span class="pill ${p.risk_score >= 65 ? "pill-danger" : (p.risk_score >= 25 ? "pill-warn" : "pill-ok")}">环路风险 ${p.risk_score} 分</span>
      </div>
    </div>
    <div><strong>台账位置：</strong>${esc(p.location || p.alias || "未录入（可在 Tab 4 补充）")}</div>
    <div class="mono" style="margin:4px 0;">入向广播: <strong>${p.broadcast_pps} pps</strong> ｜ 出向广播: ${p.out_broadcast_pps ?? "-"} pps ｜ 组播: ${p.multicast_pps} pps ｜ 入向流量: ${p.in_mbps} Mbps ｜ 丢包/错包: +${p.discards_delta}/${p.errors_delta} ｜ 学习 MAC 数: ${p.mac_count}</div>
    ${p.reasons?.length ? `<div style="color:var(--danger);"><strong>异常原因：</strong>${esc(p.reasons.join("；"))}</div>` : ""}
    ${lldpHtml}`;

  const drill = $("btnDetailDrill");
  if (drill && p.lldp_neighbor?.remote_ip) {
    drill.onclick = () => runSnmpScan({ switch_ip: p.lldp_neighbor.remote_ip, simulate: Boolean(sw.simulated) });
  }
}

async function lookupMacOnSwitch(macOverride = null) {
  const mac = (macOverride ?? $("snmpMacLookupInput").value).trim();
  if (!mac) return;
  $("snmpMacLookupInput").value = mac;
  $("hopTargetMac").value = mac;
  const box = $("snmpMacLookupResult");
  box.classList.remove("hidden");

  if (!state.currentSnmp) {
    box.innerHTML = `<span>⚠️ 请先在上方点击「开始双采样扫描」或「🚀 自动逐跳定位末端端口」以追踪 MAC <code>${esc(mac)}</code>。</span>`;
    return;
  }
  const res = await apiPost("/api/snmp/lookup_mac", { switch_ip: state.currentSnmp.switch_ip, mac });
  if (!res.ok || !res.found) {
    box.innerHTML = `<span>未找到：${esc(res.message || res.error || "无匹配记录")}</span>`;
    return;
  }
  const drillBtn = res.lldp_neighbor?.remote_ip
    ? `<button class="btn btn-sm btn-primary" id="btnMacDrill">↘ 该口下联 ${esc(res.lldp_neighbor.remote_sys)}，继续向下追踪！</button>`
    : "";
  box.innerHTML = `
    <div>🎯 MAC <code>${esc(res.mac)}</code> (${esc(res.vendor)}) 位于 <strong>${esc(res.sys_name)}</strong> 的 <code>${esc(res.port)}</code> ${res.location ? `（📍<strong>${esc(res.location)}</strong>）` : ""} · 该口学习 ${res.mac_count_on_port} 个 MAC</div>
    ${drillBtn}`;
  const btn = $("btnMacDrill");
  if (btn && res.lldp_neighbor?.remote_ip) {
    btn.onclick = async () => {
      await runSnmpScan({ switch_ip: res.lldp_neighbor.remote_ip, simulate: Boolean(state.currentSnmp?.simulated) });
      lookupMacOnSwitch(mac);
    };
  }
}

/* =========================================================================
   Tab 3: Console Serial Auto-Locator + Syslog Radar + L3 Tracer + CLI Parser
   ========================================================================= */
async function loadSerialPorts() {
  const sel = $("consolePortSelect");
  if (!sel) return;
  try {
    const res = await apiGet("/api/console/ports");
    const ports = res.ports || [];
    sel.innerHTML = "";
    const simOpt = document.createElement("option");
    simOpt.value = "__SIM_CONSOLE__";
    simOpt.textContent = "✨ [仿真演练] 模拟 Console 线直连 H3C 汇聚交换机 (9600 8N1)";
    sel.appendChild(simOpt);

    ports.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.device;
      opt.textContent = `${p.is_usb === "1" ? "🔌" : "📟"} ${p.label}`;
      sel.appendChild(opt);
    });
    const bestUsb = ports.find((p) => p.is_usb === "1");
    sel.value = bestUsb ? bestUsb.device : "__SIM_CONSOLE__";
  } catch (e) {}
}

async function runConsoleInspect(simulate = false) {
  const device = simulate ? "__SIM_CONSOLE__" : ($("consolePortSelect").value || "").trim();
  const btn = simulate ? $("btnConsoleSim") : $("btnConsoleInspect");
  btn.disabled = true;
  const origText = btn.textContent;
  btn.textContent = simulate ? "⏳ 模拟双采样中..." : "⏳ Console 双采样采集中...";

  try {
    const res = await apiPost("/api/console/inspect", {
      device,
      baudrate: parseInt($("consoleBaud").value || "9600", 10),
      vendor: $("consoleVendor").value || "auto",
      sample_interval: parseFloat($("consoleInterval").value || "3.0"),
      switch_ip: $("consoleSwitchIp").value.trim(),
      username: $("consoleUser").value.trim(),
      password: $("consolePass").value,
      enable_password: $("consoleEnablePass").value,
      simulate: simulate || device === "__SIM_CONSOLE__",
    });
    if (!res.ok) {
      showToast(res.error || "Console 串口采集失败", "danger", 5500);
      return;
    }

    $("consoleResultArea").classList.remove("hidden");
    $("consoleSummaryBanner").innerHTML = `
      <div>
        <span class="pill pill-info">${esc(res.vendor)}</span>
        <span class="pill ${res.simulated ? "pill-warn" : "pill-ok"}">${esc(res.port_device)}</span>
        <strong style="margin-left:6px;">${esc(res.summary)}</strong>
      </div>`;

    const rows = (res.ranked_ports || []).map((p) => `
      <tr style="${p.risk_score >= 60 ? "background:rgba(239,68,68,0.12);" : ""}">
        <td><strong><code>${esc(p.port)}</code></strong><div class="muted-sm">${esc(p.location || "")}</div></td>
        <td><span class="pill ${p.risk_score >= 60 ? "pill-danger" : (p.risk_score >= 25 ? "pill-warn" : "pill-ok")}">${esc(p.direction)}</span></td>
        <td class="mono"><strong>${p.in_broadcast_pps} pps</strong></td>
        <td class="mono">${p.in_uti_pct > 0 || p.out_uti_pct > 0 ? `${p.in_uti_pct}% / ${p.out_uti_pct}%` : `${p.in_total_pps} pps`}</td>
        <td>${p.lldp_neighbor ? `↘ <strong>${esc(p.lldp_neighbor.remote_sys)}</strong> <code>${esc(p.lldp_neighbor.remote_port)}</code>` : `<span class="muted-sm">直连末端/无LLDP</span>`}</td>
        <td>${esc((p.reasons || []).join("；") || "正常")}</td>
      </tr>`).join("");

    $("consolePortTable").innerHTML = `<table>
      <thead><tr><th>物理端口 / 台账房间</th><th>方向判定</th><th>入向广播 PPS</th><th>入/出利用率或总PPS</th><th>LLDP 下联设备</th><th>诊断依据</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="empty-hint">未解析到端口计数器表格（可展开下方原始回显检查命令兼容性）</td></tr>`}</tbody>
    </table>`;

    $("consoleRawTranscript").textContent = res.raw_output || "";

    if (res.parsed_logs && res.parsed_logs.finding_count > 0) {
      renderCliParsed(res.parsed_logs);
    }
    showToast(res.summary, res.ranked_ports?.[0]?.risk_score >= 60 ? "warn" : "success", 5000);
  } catch (e) {
    showToast(`Console 请求异常: ${e}`, "danger");
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

function renderSyslogState(sys) {
  const pill = $("syslogStatusPill");
  const badge = $("syslogTabBadge");
  $("btnSyslogStart").classList.toggle("hidden", sys.running);
  $("btnSyslogStop").classList.toggle("hidden", !sys.running);

  pill.textContent = sys.running ? `监听中 UDP :${sys.port} (收 ${sys.total_received} 条)` : "未启动";
  pill.className = `pill ${sys.running ? "pill-ok" : "pill-info"}`;

  if (sys.alert_count > 0) {
    badge.classList.remove("hidden");
    badge.textContent = sys.alert_count > 99 ? "99+" : String(sys.alert_count);
  } else {
    badge.classList.add("hidden");
  }

  if (sys.last_alert_ts && sys.last_alert_ts > state.lastSyslogAlertTs) {
    if (state.lastSyslogAlertTs > 0) {
      playTone("syslog");
      const top = sys.alerts?.[0];
      if (top) showToast(`📡 Syslog 环路告警 (${top.source_ip}): ${top.title}`, "danger", 5000);
    }
    state.lastSyslogAlertTs = sys.last_alert_ts;
  }

  const wrap = $("syslogAlertTable");
  const alerts = sys.alerts || [];
  if (!alerts.length) {
    wrap.innerHTML = `<div class="empty-hint">暂无 Syslog 环路告警（可点击右上角「✨ 模拟注入告警」测试）。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>时间</th><th>交换机 IP</th><th>类型</th><th>告警详情 / 教研室位置</th><th>端口</th></tr></thead>
    <tbody>${alerts.map((a) => `
      <tr>
        <td class="mono">${esc(a.time_str)}</td>
        <td class="mono"><strong>${esc(a.source_ip)}</strong></td>
        <td><span class="pill ${a.severity === "danger" ? "pill-danger" : "pill-warn"}">${esc(a.type)}</span></td>
        <td><strong>${esc(a.title)}</strong>${a.location ? `<div style="color:var(--warning);">📍 ${esc(a.location)}</div>` : ""}<div class="muted-sm mono" style="font-size:11px;">${esc(a.raw)}</div></td>
        <td class="mono">${esc((a.ports || []).join(", ") || "-")}</td>
      </tr>`).join("")}
    </tbody></table>`;
}

async function runL3Trace(simulate = false) {
  const target = ($("l3TargetInput").value || "10.20.1.1").trim();
  const btn = simulate ? $("btnL3TraceSim") : $("btnL3Trace");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "⏳ 探测跳点中...";
  try {
    const res = await apiPost("/api/l3/trace", { target, max_hops: 16, simulate });
    if (!res.ok) {
      showToast(res.error || "三层探测失败", "danger");
      return;
    }
    $("l3ResultBox").classList.remove("hidden");
    const sum = $("l3Summary");
    sum.style.color = res.has_loop ? "var(--danger)" : "var(--success)";
    sum.textContent = (res.has_loop ? "🚨 " : "✅ ") + res.summary;

    $("l3HopsWrap").innerHTML = `<table>
      <thead><tr><th>跳数</th><th>节点 IP</th><th>时延</th><th>状态</th></tr></thead>
      <tbody>${(res.hops || []).map((h) => `
        <tr style="${h.in_loop_cycle ? "background:rgba(239,68,68,0.12);" : ""}">
          <td class="mono">#${h.hop}</td>
          <td class="mono"><strong>${esc(h.ip)}</strong></td>
          <td class="mono">${h.rtt_ms !== null && h.rtt_ms !== undefined ? `${h.rtt_ms} ms` : "*"}</td>
          <td>${h.is_loop ? `<span class="pill pill-danger">🔁 重复回环跳！</span>` : (h.in_loop_cycle ? `<span class="pill pill-warn">环路节点</span>` : `<span class="muted-sm">正常</span>`)}</td>
        </tr>`).join("")}
      </tbody></table>`;
    if (res.has_loop) showToast("检测到三层路由环路！", "danger", 4500);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function renderCliParsed(parsed) {
  $("cliParsedArea").classList.remove("hidden");
  $("cliParsedSummary").textContent = parsed.summary || "";

  $("cliPortsBox").innerHTML = parsed.affected_ports?.length ? `<table>
    <thead><tr><th>端口</th><th>教研室台账位置</th><th>异常原因</th></tr></thead>
    <tbody>${parsed.affected_ports.map((p) => `
      <tr><td class="mono"><strong>${esc(p.port)}</strong></td><td>${esc(p.location || "未关联台账")}</td><td>${esc((p.reasons || []).join("；"))}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty-hint">未提取到异常端口</div>`;

  $("cliMacsBox").innerHTML = parsed.involved_macs?.length ? `<table>
    <thead><tr><th>MAC 地址</th><th>厂商 / 类型</th><th>涉及端口</th></tr></thead>
    <tbody>${parsed.involved_macs.map((m) => `
      <tr><td class="mono"><strong>${esc(m.mac)}</strong></td><td>${esc(m.vendor)} <span class="pill ${m.category === "soho_router" ? "pill-danger" : "pill-info"}">${esc(m.category_label)}</span></td><td class="mono">${esc((m.ports || []).join(" ↔ "))}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty-hint">未提取到漂移 MAC</div>`;

  $("cliFindingsBox").innerHTML = parsed.findings?.length ? `<table>
    <thead><tr><th>行号</th><th>类型</th><th>告警摘要</th><th>原始日志</th></tr></thead>
    <tbody>${parsed.findings.map((f) => `
      <tr><td class="mono">L${f.line}</td><td><span class="pill ${f.severity === "danger" ? "pill-danger" : "pill-warn"}">${esc(f.type)}</span></td><td><strong>${esc(f.title)}</strong><div class="muted-sm">${esc(f.detail)}</div></td><td class="mono" style="font-size:11px;">${esc(f.raw)}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty-hint">日志中未发现明确环路/漂移告警</div>`;
}

/* =========================================================================
   Tab 4: Campus Port Ledger
   ========================================================================= */
async function loadLedger() {
  const res = await apiGet("/api/ledger");
  const entries = res.entries || [];
  const wrap = $("ledgerTableWrap");
  if (!entries.length) {
    wrap.innerHTML = `<div class="empty-hint">台账为空，可在上方手动添加或导入 CSV。</div>`;
    return;
  }
  wrap.innerHTML = `<table>
    <thead><tr><th>交换机 IP</th><th>端口名</th><th>楼栋</th><th>教研室 / 房间</th><th>墙面面板编号</th><th>备注</th><th>操作</th></tr></thead>
    <tbody>${entries.map((e) => `
      <tr>
        <td class="mono">${esc(e.switch_ip)}</td>
        <td class="mono"><strong>${esc(e.port)}</strong></td>
        <td>${esc(e.building)}</td>
        <td><strong>${esc(e.room)}</strong></td>
        <td>${esc(e.wall_jack)}</td>
        <td class="muted-sm">${esc(e.note)}</td>
        <td><button class="btn btn-xs btn-ghost del-ledger-btn" data-ip="${esc(e.switch_ip)}" data-port="${esc(e.port)}">删除</button></td>
      </tr>`).join("")}
    </tbody></table>`;

  wrap.querySelectorAll(".del-ledger-btn").forEach((b) => {
    b.onclick = async () => {
      const r = await apiPost("/api/ledger/delete", { switch_ip: b.dataset.ip, port: b.dataset.port });
      if (r.ok) {
        showToast("已删除台账条目", "info");
        loadLedger();
      }
    };
  });
}

/* =========================================================================
   Event Bindings
   ========================================================================= */
function bindEvents() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.onclick = () => switchTab(btn.dataset.tab);
  });

  $("miniStatusPill").onclick = () => switchTab("field");
  $("btnThemeToggle").onclick = () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(cur === "dark" ? "light" : "dark");
  };

  $("btnRefreshIfaces").onclick = async () => {
    await loadSystem();
    showToast("网卡列表已刷新", "info");
  };

  $("sensitivitySelect").onchange = async () => {
    const res = await apiPost("/api/capture/sensitivity", { preset: $("sensitivitySelect").value });
    if (res.ok) showToast(`已切换告警灵敏度：${$("sensitivitySelect").selectedOptions[0].text}`, "info");
  };

  $("btnGrantBpf").onclick = async () => {
    const btn = $("btnGrantBpf");
    btn.disabled = true;
    btn.textContent = "⏳ 等待输入 Mac 密码...";
    try {
      const res = await apiPost("/api/system/grant_bpf");
      if (res.ok) {
        showToast(res.message || "已开启有线抓包权限！", "success", 4500);
        await loadSystem();
      } else {
        showToast(res.error || "授权未完成", "warn", 5000);
      }
    } finally {
      btn.disabled = false;
      btn.textContent = "🔐 一键开启本机抓包权限";
    }
  };

  $("btnQuickDemo").onclick = async () => {
    $("ifaceSelect").value = "__SIMULATION__";
    await apiPost("/api/capture/start", { interface: "__SIMULATION__", mode: "active", backend: "simulation" });
    showToast("已启动教研室环路仿真演练模式", "success");
  };

  $("btnStartCapture").onclick = async () => {
    const iface = $("ifaceSelect").value;
    const mode = $("probeModeSelect").value;
    const backend = iface === "__SIMULATION__" ? "simulation" : "auto";
    const res = await apiPost("/api/capture/start", { interface: iface, mode, backend });
    if (!res.ok) {
      showToast(res.error || "启动失败", "danger", 5000);
      if (res.suggest_simulation) {
        $("ifaceSelect").value = "__SIMULATION__";
      }
    } else {
      showToast(`监测已启动 (${res.backend})`, "success");
    }
  };

  $("btnStopCapture").onclick = async () => {
    await apiPost("/api/capture/stop");
    showToast("已停止监测", "info");
  };
  $("btnResetStats").onclick = async () => {
    await apiPost("/api/capture/reset");
    showToast("统计计数与缓存已清零", "info");
  };
  $("btnSendProbe").onclick = async () => {
    const res = await apiPost("/api/capture/probe");
    showToast(res.ok ? `已发送二层环路探针 Seq #${res.seq}` : res.error, res.ok ? "info" : "warn");
  };
  $("btnDhcpScan").onclick = async () => {
    const res = await apiPost("/api/capture/dhcp_scan");
    showToast(res.ok ? res.message : res.error, res.ok ? "info" : "warn");
  };
  $("btnSaveTrustedDhcp").onclick = async () => {
    const res = await apiPost("/api/capture/trusted_dhcp", { ips: $("trustedDhcpInput").value });
    if (res.ok) showToast(`合法 DHCP 白名单已更新：${(res.trusted_dhcp_ips || []).join(", ") || "空"}`, "success");
  };

  $("btnSimUnplug").onclick = () => apiPost("/api/sim/toggle", { loop_active: false });
  $("btnSimReplug").onclick = () => apiPost("/api/sim/toggle", { loop_active: true });
  $("btnSimJumpSnmp").onclick = () => {
    switchTab("snmp");
    runHopTrace(true);
  };

  $("btnInspectUpstream").onclick = () => {
    const btn = $("btnInspectUpstream");
    switchTab("snmp");
    runSnmpScan({ switch_ip: btn.dataset.ip, simulate: btn.dataset.sim === "1" });
  };

  document.body.addEventListener("click", (ev) => {
    const ext = ev.target.closest("a[data-external-open]");
    if (ext && window.pywebview?.api?.open_in_browser) {
      ev.preventDefault();
      const href = ext.getAttribute("href");
      if (href) window.pywebview.api.open_in_browser(href);
      return;
    }
    const a = ev.target.closest(".mac-jump");
    if (!a) return;
    ev.preventDefault();
    const mac = a.dataset.mac;
    switchTab("snmp");
    lookupMacOnSwitch(mac);
  });

  // Bisection
  $("btnBisectInit").onclick = initBisection;
  $("btnBisectUndo").onclick = () => {
    if (!state.bisect || !state.bisect.stack.length) return;
    const prev = state.bisect.stack.pop();
    state.bisect.candidates = prev.candidates;
    state.bisect.step = prev.step;
    state.bisect.logs = prev.logs;
    renderBisection();
  };
  $("btnBisectReset").onclick = () => {
    state.bisect = null;
    renderBisection();
  };

  // Tab 2 SNMP / Inventory / Batch / Hop Trace
  $("btnSnmpScan").onclick = () => runSnmpScan({ simulate: false });
  $("btnSnmpSimulate").onclick = () => runSnmpScan({ switch_ip: "10.10.1.1", simulate: true });
  $("btnSnmpMacLookup").onclick = () => lookupMacOnSwitch();
  $("btnBatchScan").onclick = () => runBatchScan(false);
  $("btnBatchScanSim").onclick = () => runBatchScan(true);
  $("btnHopTrace").onclick = () => runHopTrace(false);
  $("btnHopTraceSim").onclick = () => runHopTrace(true);

  $("btnInvLoadSample").onclick = async () => {
    const res = await apiPost("/api/inventory/load_sample");
    if (res.ok) {
      showToast("已载入 4 台示例交换机（熟悉后可删掉换成自己学校的）", "info");
      loadInventory();
    }
  };

  $("btnInvAdd").onclick = async () => {
    const res = await apiPost("/api/inventory/upsert", {
      ip: $("invIp").value,
      name: $("invName").value,
      building: $("invBuilding").value,
      role: $("invRole").value,
      community: $("invComm").value,
      snmp_version: $("invVer").value,
    });
    if (!res.ok) return showToast(res.error, "danger");
    showToast("交换机已保存到资产簿", "success");
    ["invIp", "invName"].forEach((id) => ($(id).value = ""));
    loadInventory();
  };

  // Tab 3 Console / Syslog / L3 / Parser
  $("btnRefreshSerial").onclick = async () => {
    await loadSerialPorts();
    showToast("已刷新本机 Console 串口列表", "info");
  };
  $("btnConsoleInspect").onclick = () => runConsoleInspect(false);
  $("btnConsoleSim").onclick = () => runConsoleInspect(true);

  $("btnSyslogStart").onclick = async () => {
    const res = await apiPost("/api/syslog/start", { port: parseInt($("syslogPort").value || "1514", 10) });
    showToast(res.ok ? `Syslog 雷达已启动 (UDP :${res.port})` : res.error, res.ok ? "success" : "danger", 4500);
  };
  $("btnSyslogStop").onclick = async () => {
    await apiPost("/api/syslog/stop");
    showToast("Syslog 雷达已停止", "info");
  };
  $("btnSyslogClear").onclick = async () => {
    await apiPost("/api/syslog/clear");
    showToast("Syslog 记录已清空", "info");
  };
  $("btnSyslogDemo").onclick = async () => {
    const res = await apiPost("/api/syslog/demo");
    if (res.ok) showToast(`已模拟注入 ${res.injected} 条交换机 Syslog 告警`, "warn");
  };
  $("btnL3Trace").onclick = () => runL3Trace(false);
  $("btnL3TraceSim").onclick = () => runL3Trace(true);

  $("btnLoadSampleCli").onclick = () => {
    if (state.system?.sample_cli) {
      $("cliInputText").value = state.system.sample_cli;
      $("parseSwitchIp").value = "10.10.2.12";
      showToast("已载入示例华为环路/MAC漂移日志", "info");
    }
  };
  $("btnParseCli").onclick = async () => {
    const raw_text = $("cliInputText").value;
    if (!raw_text.trim()) return showToast("请先粘贴交换机输出日志", "warn");
    const res = await apiPost("/api/cli/parse", { raw_text, switch_ip: $("parseSwitchIp").value.trim() });
    if (res.ok) {
      renderCliParsed(res.parsed);
      showToast(res.parsed.summary, "info");
    }
  };
  // Tab 4 Ledger
  $("btnLedgerLoadSample").onclick = async () => {
    const res = await apiPost("/api/ledger/load_sample");
    if (res.ok) {
      showToast(`已载入 ${res.imported} 条示例面板台账（可作填写参考）`, "info");
      loadLedger();
    }
  };

  $("btnLedgerAdd").onclick = async () => {
    const res = await apiPost("/api/ledger/upsert", {
      switch_ip: $("lgIp").value,
      port: $("lgPort").value,
      building: $("lgBuilding").value,
      room: $("lgRoom").value,
      wall_jack: $("lgJack").value,
      note: $("lgNote").value,
    });
    if (!res.ok) return showToast(res.error, "danger");
    showToast("台账已保存", "success");
    ["lgPort", "lgJack", "lgNote"].forEach((id) => ($(id).value = ""));
    loadLedger();
  };
  $("ledgerCsvFile").onchange = async (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const res = await apiPost("/api/ledger/import_csv", { csv_text: text, replace: false });
    if (res.ok) {
      showToast(`成功导入 ${res.imported} 条台账记录！`, "success");
      loadLedger();
    }
    ev.target.value = "";
  };
}

/* =========================================================================
   Bootstrap
   ========================================================================= */
(async function init() {
  applyTheme(localStorage.getItem("loopfinder_theme") || "dark");
  bindEvents();
  await loadSystem();
  await loadInventory();
  await loadSerialPorts();
  await loadLedger();
  connectSSE();
})();
