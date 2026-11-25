const POLL_MS = 1000;
const $ = (id) => document.getElementById(id);

const form = $("scan-form");
const btnStart = $("btn-start");
const btnStop = $("btn-stop");
const formError = $("form-error");
const showFree = $("show-free");

let previousStatus = {};
let lastState = null;

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function formatTime(epoch) {
  return epoch ? new Date(epoch * 1000).toLocaleTimeString("pt-BR") : "—";
}

function statusPill(status) {
  const labels = { online: "Online", offline: "Offline", livre: "Livre" };
  return `<span class="pill ${status}">${labels[status]}</span>`;
}

function methodTag(device) {
  if (device.status !== "online") return '<span class="dim">—</span>';
  if (device.method === "ICMP") return '<span class="tag icmp">ICMP</span>';
  return '<span class="tag arp">ARP · ICMP bloqueado</span>';
}

function macCell(device) {
  if (!device.macs.length) return '<span class="dim">—</span>';
  const macs = device.macs.map((m) => `<div class="mono">${escapeHtml(m)}</div>`).join("");
  return device.conflict ? `<span class="tag conflict">Conflito de IP</span>${macs}` : macs;
}

function portsCell(device) {
  if (device.status !== "online") return '<span class="dim">—</span>';
  const list = device.ports
    .map((p) => `<span class="port"><b>${p.port}</b>/${escapeHtml(p.service)}</span>`)
    .join("");
  if (device.ports_state === "varrendo") return list + '<span class="dim">varrendo…</span>';
  if (device.ports_state === "pendente") return '<span class="dim">aguardando</span>';
  return list || '<span class="dim">nenhuma no intervalo</span>';
}

function renderTable(devices) {
  const visible = devices.filter((d) => d.status !== "livre" || showFree.checked);
  $("empty").hidden = visible.length > 0;

  $("devices").innerHTML = visible
    .map((d) => {
      const changed = previousStatus[d.ip] !== undefined && previousStatus[d.ip] !== d.status;
      return `
        <tr class="${changed ? "changed" : ""}">
          <td>${statusPill(d.status)}</td>
          <td class="mono">${d.ip}${d.is_self ? '<span class="tag self">este PC</span>' : ""}</td>
          <td>${macCell(d)}</td>
          <td>${methodTag(d)}</td>
          <td class="mono">${d.latency_ms != null ? d.latency_ms + " ms" : '<span class="dim">—</span>'}</td>
          <td class="mono">${d.ttl ?? '<span class="dim">—</span>'}</td>
          <td>${portsCell(d)}</td>
          <td class="mono dim">${formatTime(d.last_seen)}</td>
        </tr>`;
    })
    .join("");

  previousStatus = Object.fromEntries(devices.map((d) => [d.ip, d.status]));
}

function renderProgress(state) {
  const pct = state.total ? Math.round((state.done / state.total) * 100) : state.running ? 0 : 100;
  const showBar = state.running && state.phase !== "aguardando";
  $("progress-fill").style.width = (showBar ? pct : state.phase === "parado" ? 0 : 100) + "%";

  let label = state.phase_label;
  if (state.cycle > 1 || (state.config && state.config.monitor && state.cycle)) label += ` · ciclo ${state.cycle}`;
  if (state.error) label += ` — ${state.error}`;
  $("phase-label").textContent = label;

  let progress = "";
  if (showBar && state.total) progress = `${state.done} / ${state.total} (${pct}%)`;
  if (state.phase === "aguardando" && state.next_cycle_at) {
    const secs = Math.max(0, Math.round(state.next_cycle_at - Date.now() / 1000));
    progress = `próximo ciclo em ${secs}s`;
  }
  $("progress-text").textContent = progress;

  $("arp-mode").textContent = state.arp_mode ? `Modo ARP: ${state.arp_mode}` : "";
  const names = { icmp: "ICMP", arp: "ARP Probe", vinculacao: "IP/MAC", portas: "Portas" };
  $("timings").textContent = Object.keys(names)
    .filter((k) => k in state.timings)
    .map((k) => `${names[k]}: ${state.timings[k]}s`)
    .join("  ·  ");
}

function renderSummary(s) {
  $("c-online").textContent = s.online;
  $("c-icmp").textContent = s.icmp;
  $("c-arp").textContent = s.arp;
  $("c-offline").textContent = s.offline;
  $("c-conflicts").textContent = s.conflicts;
  $("c-ports").textContent = s.open_ports;
  $("c-free").textContent = s.free;
}

function render(state) {
  lastState = state;
  renderProgress(state);
  renderSummary(state.summary);
  renderTable(state.devices);

  $("live").classList.toggle("on", state.running);
  $("live-text").textContent = state.running ? (state.phase === "aguardando" ? "Monitorando" : "Varrendo") : "Parado";
  btnStart.disabled = state.running;
  btnStop.disabled = !state.running;
  form.querySelectorAll("input").forEach((input) => (input.disabled = state.running));
}

async function poll() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    render(await response.json());
  } catch {
    $("phase-label").textContent = "Sem conexão com o servidor do NetProbe";
  } finally {
    setTimeout(poll, POLL_MS);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  const data = Object.fromEntries(new FormData(form));
  data.monitor = $("monitor").checked;

  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    formError.textContent = (await response.json()).error;
    formError.hidden = false;
    return;
  }
  previousStatus = {};
});

btnStop.addEventListener("click", () => fetch("/api/stop", { method: "POST" }));
showFree.addEventListener("change", () => lastState && renderTable(lastState.devices));

poll();
