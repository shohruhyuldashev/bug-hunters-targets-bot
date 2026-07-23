const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const loginForm = document.querySelector("#login-form");
const platformForm = document.querySelector("#platform-form");
const toast = document.querySelector("#toast");
let socket;
let toastTimer;

function getCookie(name) {
  return document.cookie.split("; ").find((row) => row.startsWith(`${name}=`))?.split("=").slice(1).join("=") || "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", getCookie("csrf_token"));
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || "Request failed");
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 5000);
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function renderDashboard(data) {
  document.querySelector("#active-targets").textContent = data.stats.active_targets;
  document.querySelector("#enabled-platforms").textContent = data.stats.enabled_platforms;
  document.querySelector("#today-count").textContent = data.stats.today;
  const platforms = document.querySelector("#platform-list");
  platforms.innerHTML = data.platforms.length ? data.platforms.map((item) => `
    <article class="connection">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <small>${escapeHtml(item.program_name)} · every ${item.poll_interval_seconds}s · ${item.has_credentials ? "credentials saved" : "no credentials"}</small>
        ${item.last_error ? `<small class="form-error">Last error: ${escapeHtml(item.last_error)}</small>` : ""}
      </div>
      <button class="secondary scan-button" data-platform-id="${item.id}">Scan now</button>
    </article>`).join("") : "<p class=\"muted\">No connections yet. Add your first permitted scope feed below.</p>";
  platforms.querySelectorAll(".scan-button").forEach((button) => button.addEventListener("click", () => scanNow(button)));

  const events = document.querySelector("#event-list");
  events.innerHTML = data.events.length ? data.events.map((item) => `
    <article class="event">
      <div><span class="event-type">${escapeHtml(item.event_type)}</span><strong>${escapeHtml(item.identifier)}</strong><small>${escapeHtml(item.program)} · ${escapeHtml(item.asset_type)} · ${formatTime(item.created_at)}</small></div>
    </article>`).join("") : "<p class=\"muted\">No target changes recorded yet.</p>";
}

async function loadDashboard() {
  const data = await api("/api/dashboard");
  renderDashboard(data);
}

async function scanNow(button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = "Scanning…";
  try {
    const result = await api(`/api/platforms/${button.dataset.platformId}/scan`, { method: "POST" });
    showToast(result.first_snapshot ? `Baseline saved: ${result.targets_found} targets.` : `Scan finished: ${result.changes.length} change(s).`);
    await loadDashboard();
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function connectWebSocket() {
  socket?.close();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${location.host}/ws/events`);
  const state = document.querySelector("#connection-state");
  socket.addEventListener("open", () => { state.textContent = "Live"; state.classList.add("live"); });
  socket.addEventListener("close", () => {
    state.textContent = "Reconnecting";
    state.classList.remove("live");
    setTimeout(connectWebSocket, 3000);
  });
  socket.addEventListener("message", async (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "target.added") showToast(`New target: ${data.target.identifier}`);
    if (data.type === "target.added" || data.type === "scan.completed") await loadDashboard();
  });
}

async function showApp() {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  await loadDashboard();
  connectWebSocket();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#login-error");
  error.textContent = "";
  try {
    await api("/api/auth/login", { method: "POST", body: JSON.stringify({ username: document.querySelector("#username").value, password: document.querySelector("#password").value }) });
    await showApp();
  } catch (err) { error.textContent = err.message; }
});

platformForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#platform-error");
  error.textContent = "";
  const values = Object.fromEntries(new FormData(platformForm));
  values.poll_interval_seconds = Number(values.poll_interval_seconds);
  try {
    await api("/api/platforms", { method: "POST", body: JSON.stringify(values) });
    platformForm.reset();
    platformForm.querySelector("[name=poll_interval_seconds]").value = "300";
    showToast("Connection saved. Run its first scan to create a baseline.");
    await loadDashboard();
  } catch (err) { error.textContent = err.message; }
});

document.querySelector("#refresh-button").addEventListener("click", () => loadDashboard().catch((error) => showToast(error.message)));
document.querySelector("#logout-button").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  socket?.close();
  appView.classList.add("hidden");
  loginView.classList.remove("hidden");
  loginForm.reset();
});

api("/api/dashboard").then(showApp).catch(() => {});
