/**
 * Target Monitor — Private Client Setup Mini App
 * Telegram BotFather-style Expert UI Architecture
 */

(function () {
  "use strict";

  const KEYS = {
    consent: "tm-consent-v2",
    agent: "tm-agent-v1",
    connections: "tm-connections-v2"
  };

  const PLATFORM_CONFIGS = {
    hackerone: {
      name: "HackerOne",
      badge: "H1",
      badgeClass: "h1-badge",
      logoClass: "h1-logo",
      endpointPlaceholder: "",
      endpointHint: "",
      identifierLabel: "API identifier",
      identifierRequired: true,
      tokenLabel: "API token",
      tokenRequired: true,
      authHint: "Generate your API Token v2 in HackerOne Account Settings → API Tokens."
    },
    intigriti: {
      name: "Intigriti",
      badge: "IN",
      badgeClass: "it-badge",
      logoClass: "it-logo",
      endpointPlaceholder: "",
      endpointHint: "",
      identifierLabel: "API identifier (unused)",
      identifierRequired: false,
      tokenLabel: "Personal Access Token (PAT)",
      tokenRequired: true,
      authHint: "Generate a Personal Access Token in your Intigriti account settings."
    },
    yeswehack: {
      name: "YesWeHack",
      badge: "YW",
      badgeClass: "ywh-badge",
      logoClass: "ywh-logo",
      endpointPlaceholder: "",
      endpointHint: "",
      identifierLabel: "API identifier (unused)",
      identifierRequired: false,
      tokenLabel: "Bearer / JWT Token",
      tokenRequired: true,
      authHint: "Copy your Bearer JWT token from your YesWeHack account/session."
    },
    bugcrowd: {
      name: "Bugcrowd",
      badge: "BC",
      badgeClass: "bc-badge",
      logoClass: "bc-logo",
      endpointPlaceholder: "",
      endpointHint: "",
      identifierLabel: "API identifier (unused)",
      identifierRequired: false,
      tokenLabel: "API Token (Optional)",
      tokenRequired: false,
      authHint: "Enter your Bugcrowd API token for private programs. Leave empty for public programs."
    }
  };

  // Telegram WebApp SDK reference
  const tg = window.Telegram?.WebApp;

  // App State
  let agentCredential = null;
  let connections = [];
  let currentPlatform = "hackerone";
  let activeViewId = "view-consent";
  const viewHistory = [];

  // SecureStorage Promise wrappers
  function storage() {
    return tg?.CloudStorage;
  }

  function secureGet(key) {
    return new Promise((resolve, reject) => {
      const store = storage();
      if (!store) return resolve(null);
      store.getItem(key, (err, val) => (err ? reject(new Error(err)) : resolve(val)));
    });
  }

  function secureSet(key, value) {
    return new Promise((resolve, reject) => {
      const store = storage();
      if (!store) return resolve();
      store.setItem(key, value, (err) => (err ? reject(new Error(err)) : resolve()));
    });
  }

  function secureRemove(key) {
    return new Promise((resolve, reject) => {
      const store = storage();
      if (!store) return resolve();
      store.removeItem(key, (err) => (err ? reject(new Error(err)) : resolve()));
    });
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>'"]/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    }[c]));
  }

  // View Navigation Router
  function navigateTo(viewId, title = "Target Monitor", addToHistory = true) {
    if (activeViewId === viewId) return;

    if (addToHistory && activeViewId) {
      viewHistory.push({ id: activeViewId, title: document.querySelector("#header-title").textContent });
    }

    document.querySelectorAll(".view").forEach((el) => el.classList.add("hidden"));
    const targetView = document.querySelector(`#${viewId}`);
    if (targetView) targetView.classList.remove("hidden");

    activeViewId = viewId;

    // Header updates
    const header = document.querySelector("#app-header");
    const titleEl = document.querySelector("#header-title");
    const backBtn = document.querySelector("#back-btn");

    if (viewId === "view-consent") {
      header.classList.add("hidden");
    } else {
      header.classList.remove("hidden");
      titleEl.textContent = title;

      if (viewHistory.length > 0) {
        backBtn.classList.remove("hidden");
        if (tg?.BackButton) tg.BackButton.show();
      } else {
        backBtn.classList.add("hidden");
        if (tg?.BackButton) tg.BackButton.hide();
      }
    }

    // Scroll to top
    window.scrollTo(0, 0);
  }

  function goBack() {
    if (viewHistory.length === 0) return;
    const prev = viewHistory.pop();
    navigateTo(prev.id, prev.title, false);
  }

  // Agent Setup Registration
  async function registerAgentIfNeeded() {
    const setupCode = new URLSearchParams(location.search).get("setup");
    if (!setupCode) return;

    try {
      const res = await fetch("/relay/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setup_code: setupCode })
      });

      if (!res.ok) {
        throw new Error("This setup link expired. Please return to the bot and run /web again.");
      }

      agentCredential = await res.json();
      await secureSet(KEYS.agent, JSON.stringify(agentCredential));
      history.replaceState({}, "", location.pathname);
    } catch (err) {
      showError(err.message, "#consent-error");
    }
  }

  // Load Saved State
  async function loadWorkspaceData() {
    try {
      const storedAgent = await secureGet(KEYS.agent);
      if (storedAgent) {
        try {
          agentCredential = JSON.parse(storedAgent);
        } catch (e) {
          agentCredential = null;
        }
      }

      if (agentCredential?.agent_id && agentCredential?.agent_secret) {
        // Fetch server-side active user connections
        try {
          const res = await fetch(`/api/user/connections?agent_id=${encodeURIComponent(agentCredential.agent_id)}`, {
            headers: { "X-Agent-Secret": agentCredential.agent_secret }
          });
          if (res.ok) {
            const serverConns = await res.json();
            connections = serverConns.map((c) => ({
              id: c.id,
              platform: c.platform,
              program: c.program_name,
              endpoint: c.endpoint,
              details_endpoint: c.details_endpoint,
              identifier: c.credential_identifier,
              interval: c.poll_interval_seconds
            }));
            await secureSet(KEYS.connections, JSON.stringify(connections));
          }
        } catch (e) {
          console.warn("Failed to fetch server connections, fallback to local cache:", e);
        }
      }

      if (!connections || connections.length === 0) {
        const storedConns = (await secureGet(KEYS.connections)) || (await secureGet("tm-connections-v1"));
        if (storedConns) {
          try {
            const parsed = JSON.parse(storedConns);
            connections = Array.isArray(parsed) ? parsed : [];
          } catch (e) {
            connections = [];
          }
        } else {
          connections = [];
        }
      }
    } catch (err) {
      console.warn("Storage load warning:", err);
      connections = [];
    }

    updateDashboard();
    navigateTo("view-home", "Target Monitor", false);
  }

  // Update UI Elements
  function updateDashboard() {
    if (!Array.isArray(connections)) {
      connections = [];
    }

    const statusText = document.querySelector("#status-text");
    const statusBanner = document.querySelector("#agent-status");

    if (agentCredential) {
      statusText.textContent = "Relay Agent Link Active";
      statusBanner.classList.add("ready");
    } else {
      statusText.textContent = "Pending Relay Registration (/web)";
      statusBanner.classList.remove("ready");
    }

    // Stats
    const statsRow = document.querySelector("#stats-row");
    const statConn = document.querySelector("#stat-connections");
    const statPlat = document.querySelector("#stat-platforms");
    const progHint = document.querySelector("#programs-count-hint");

    const uniquePlatforms = new Set(connections.map((c) => c?.platform).filter(Boolean)).size;
    statConn.textContent = connections.length;
    statPlat.textContent = uniquePlatforms;

    if (connections.length > 0) {
      statsRow.classList.remove("hidden");
      progHint.textContent = `${connections.length} program(s) connected`;
    } else {
      statsRow.classList.add("hidden");
      progHint.textContent = "No saved connections";
    }
  }

  // Render Form based on Platform
  function configureFormForPlatform(platformKey) {
    currentPlatform = platformKey;
    const cfg = PLATFORM_CONFIGS[platformKey] || PLATFORM_CONFIGS.hackerone;

    document.querySelector("#f-platform").value = platformKey;
    document.querySelector("#sp-name").textContent = cfg.name;

    const spLogo = document.querySelector("#sp-logo");
    spLogo.className = `sp-logo ${cfg.logoClass}`;
    spLogo.textContent = cfg.badge;

    // Field placeholders & labels
    const epInput = document.querySelector("#f-endpoint");
    epInput.placeholder = cfg.endpointPlaceholder;
    document.querySelector("#endpoint-hint").textContent = cfg.endpointHint;

    const idField = document.querySelector("#field-identifier");
    const idDivider = document.querySelector("#divider-identifier");
    const idInput = document.querySelector("#f-identifier");
    const idLabel = document.querySelector("#label-identifier");

    idLabel.textContent = cfg.identifierLabel;
    idInput.required = cfg.identifierRequired;

    if (!cfg.identifierRequired) {
      idField.style.display = "none";
      idDivider.style.display = "none";
    } else {
      idField.style.display = "flex";
      idDivider.style.display = "block";
    }

    const programSection = document.querySelector("#program-section-group");
    const authSectionLabel = document.querySelector("#auth-section-label");
    
    // ALWAYS hide the Program/Endpoint section since all platforms now use "All Programs"
    programSection.style.display = "none";
    document.querySelector("#f-program").required = false;
    document.querySelector("#f-endpoint").required = false;
    authSectionLabel.textContent = "AUTHENTICATION";

    document.querySelector("#label-token").textContent = cfg.tokenLabel;
    document.querySelector("#auth-hint").textContent = cfg.authHint;
  }

  // Render Program List View
  function renderProgramsList() {
    const emptyState = document.querySelector("#empty-programs");
    const listWrap = document.querySelector("#programs-list");
    const actionsRow = document.querySelector("#programs-actions");

    listWrap.innerHTML = "";

    if (connections.length === 0) {
      emptyState.classList.remove("hidden");
      actionsRow.style.display = "none";
      return;
    }

    emptyState.classList.add("hidden");
    actionsRow.style.display = "flex";

    const card = document.createElement("div");
    card.className = "section-card";

    connections.forEach((conn, index) => {
      const cfg = PLATFORM_CONFIGS[conn.platform] || PLATFORM_CONFIGS.hackerone;

      const item = document.createElement("div");
      item.className = "program-item";
      item.innerHTML = `
        <div class="program-logo ${cfg.logoClass}">${cfg.badge}</div>
        <div class="program-info">
          <span class="program-title">${escapeHtml(conn.program)}</span>
          <span class="program-meta">${escapeHtml(cfg.name)} · every ${conn.interval}s</span>
        </div>
        <div class="program-actions">
          <button class="program-edit-btn" data-index="${index}" aria-label="Edit">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
          </button>
          <button class="program-del-btn" data-index="${index}" aria-label="Delete">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            </svg>
          </button>
        </div>
      `;

      card.appendChild(item);

      if (index < connections.length - 1) {
        const divider = document.createElement("div");
        divider.className = "cell-divider";
        card.appendChild(divider);
      }
    });

    listWrap.appendChild(card);

    // Delete buttons
    listWrap.querySelectorAll(".program-del-btn").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        const idx = Number(e.currentTarget.dataset.index);
        const item = connections[idx];
        if (item?.id && agentCredential?.agent_id && agentCredential?.agent_secret) {
          try {
            await fetch(`/api/user/connections/${encodeURIComponent(item.id)}?agent_id=${encodeURIComponent(agentCredential.agent_id)}`, {
              method: "DELETE",
              headers: { "X-Agent-Secret": agentCredential.agent_secret }
            });
          } catch (err) {
            console.warn("Server connection delete error:", err);
          }
        }
        connections.splice(idx, 1);
        await secureSet(KEYS.connections, JSON.stringify(connections));
        updateDashboard();
        renderProgramsList();
      });
    });

    // Edit buttons
    listWrap.querySelectorAll(".program-edit-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const idx = Number(e.currentTarget.dataset.index);
        const item = connections[idx];
        
        const cfg = PLATFORM_CONFIGS[item.platform];
        document.querySelector("#edit-sp-name").textContent = cfg.name;
        const spLogo = document.querySelector("#edit-sp-logo");
        spLogo.className = `sp-logo ${cfg.logoClass}`;
        spLogo.textContent = cfg.badge;

        document.querySelector("#edit-conn-index").value = idx;
        
        const idField = document.querySelector("#edit-field-identifier");
        const idDivider = document.querySelector("#edit-divider-identifier");
        if (!cfg.identifierRequired) {
          idField.style.display = "none";
          idDivider.style.display = "none";
        } else {
          idField.style.display = "flex";
          idDivider.style.display = "block";
        }

        document.querySelector("#edit-f-identifier").value = item.identifier || "";
        document.querySelector("#edit-f-token").value = ""; // Don't show existing token
        document.querySelector("#edit-f-interval").value = item.interval || "300";
        
        navigateTo("view-edit", "Edit Program");
      });
    });
  }

  // Render Download Summary
  function renderDownloadView() {
    document.querySelector("#dl-prog-count").textContent = connections.length;
    const uniquePlats = new Set(connections.map((c) => c.platform)).size;
    document.querySelector("#dl-platform-count").textContent = uniquePlats;

    const helpEl = document.querySelector("#download-help");
    if (!connections.length) {
      helpEl.textContent = "⚠️ Please add at least one program connection before downloading config.";
    } else {
      helpEl.textContent = "Config generated with your encrypted credentials. Keep it safe.";
    }
  }

  function showError(msg, selector = "#form-error") {
    const el = document.querySelector(selector);
    if (!el) return;
    el.textContent = msg;
    el.classList.remove("hidden");
  }

  function hideError(selector = "#form-error") {
    const el = document.querySelector(selector);
    if (el) el.classList.add("hidden");
  }

  // Initialize App
  async function init() {
    // Expand Telegram WebApp
    if (tg) {
      tg.ready();
      tg.expand();
      if (tg.setHeaderColor) tg.setHeaderColor("bg_color");
      if (tg.setBackgroundColor) tg.setBackgroundColor("bg_color");

      // Telegram BackButton listener
      if (tg.BackButton) {
        tg.BackButton.onClick(goBack);
      }
    }

    // DOM Event Listeners
    document.querySelector("#back-btn").addEventListener("click", goBack);

    // Consent Allow Button
    document.querySelector("#allow-btn").addEventListener("click", async () => {
      hideError("#consent-error");
      try {
        await secureSet(KEYS.consent, "true");
        await registerAgentIfNeeded();
        await loadWorkspaceData();
      } catch (err) {
        showError(err.message, "#consent-error");
      }
    });

    // Home view navigation buttons
    document.querySelector("#btn-add-program").addEventListener("click", () => {
      navigateTo("view-platforms", "Select Platform");
    });
    
    document.querySelector("#btn-my-programs").addEventListener("click", () => {
      renderProgramsList();
      navigateTo("view-programs", "My Programs");
    });

    document.querySelectorAll(".platform-card").forEach((card) => {
      card.addEventListener("click", (e) => {
        const plat = e.currentTarget.dataset.platform;
        configureFormForPlatform(plat);
        navigateTo("view-form", "Add " + PLATFORM_CONFIGS[plat].name);
      });
    });
    
    document.querySelector("#sp-change-btn").addEventListener("click", () => {
      navigateTo("view-platforms", "Select Platform");
    });

    // Toggle Password Visibility
    document.querySelector("#toggle-pw").addEventListener("click", () => {
      const pwdInput = document.querySelector("#f-token");
      const isPassword = pwdInput.type === "password";
      pwdInput.type = isPassword ? "text" : "password";
      document.querySelector("#eye-icon").style.opacity = isPassword ? "0.5" : "1";
    });
    
    document.querySelector("#edit-toggle-pw").addEventListener("click", () => {
      const pwdInput = document.querySelector("#edit-f-token");
      const isPassword = pwdInput.type === "password";
      pwdInput.type = isPassword ? "text" : "password";
      document.querySelector("#edit-eye-icon").style.opacity = isPassword ? "0.5" : "1";
    });

    // Connection Form Submit
    document.querySelector("#connection-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      hideError("#form-error");

      const fd = new FormData(e.currentTarget);
      const vals = Object.fromEntries(fd);

      const platKey = vals.platform || "hackerone";
      const cfg = PLATFORM_CONFIGS[platKey];

      if (cfg.identifierRequired && !vals.identifier?.trim()) {
        showError("API identifier is required for " + cfg.name);
        return;
      }

      if (cfg.tokenRequired && !vals.token?.trim()) {
        showError("API token is required for " + cfg.name);
        return;
      }

      try {
        if (!agentCredential?.agent_id || !agentCredential?.agent_secret) {
          throw new Error("Session expired. Please return to the bot and run /web again.");
        }

        const form = e.currentTarget;
        
        let reqProgram = "All Programs";
        let reqEndpoint = "";
        let reqDetails = null;

        if (platKey === "hackerone") {
          reqEndpoint = "https://api.hackerone.com/v1/hackers/programs";
        } else if (platKey === "yeswehack") {
          reqEndpoint = "https://api.yeswehack.com/programs";
        } else if (platKey === "intigriti") {
          reqEndpoint = "https://api.intigriti.com/core/researcher/program";
        } else {
          reqEndpoint = "https://bugcrowd.com/programs";
        }

        const payload = {
          agent_id: agentCredential.agent_id,
          platform: platKey,
          program_name: reqProgram,
          endpoint: reqEndpoint,
          details_endpoint: reqDetails,
          credential_identifier: vals.identifier?.trim() || null,
          credential_token: vals.token || null,
          poll_interval_seconds: Number(vals.interval) || 300
        };

        const res = await fetch("/api/user/connections", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Agent-Secret": agentCredential.agent_secret
          },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to save program connection on server");
        }

        const result = await res.json();

        const newConn = {
          id: result.id || crypto.randomUUID(),
          platform: platKey,
          program: reqProgram,
          endpoint: reqEndpoint,
          details_endpoint: reqDetails || reqEndpoint,
          identifier: vals.identifier?.trim() || "",
          interval: Number(vals.interval) || 300
        };

        connections.unshift(newConn);
        await secureSet(KEYS.connections, JSON.stringify(connections));

        form.reset();
        document.querySelector("#f-interval").value = "300";

        updateDashboard();
        renderProgramsList();
        viewHistory.length = 0; // reset navigation back to home
        navigateTo("view-programs", "My Programs", false);
      } catch (err) {
        showError(err.message);
      }
    });

    // Edit Connection Form Submit
    document.querySelector("#edit-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      hideError("#edit-form-error");

      const fd = new FormData(e.currentTarget);
      const vals = Object.fromEntries(fd);
      const idx = Number(vals.conn_index);
      const item = connections[idx];
      const cfg = PLATFORM_CONFIGS[item.platform];

      if (cfg.identifierRequired && !vals.identifier?.trim()) {
        showError("API identifier is required for " + cfg.name, "#edit-form-error");
        return;
      }

      if (!vals.token?.trim()) {
        showError("API token is required to update " + cfg.name, "#edit-form-error");
        return;
      }

      try {
        if (!agentCredential?.agent_id || !agentCredential?.agent_secret) {
          throw new Error("Session expired. Please return to the bot and run /web again.");
        }

        const payload = {
          agent_id: agentCredential.agent_id,
          platform: item.platform,
          program_name: item.program,
          endpoint: item.endpoint,
          details_endpoint: item.details_endpoint,
          credential_identifier: vals.identifier?.trim() || null,
          credential_token: vals.token || null,
          poll_interval_seconds: Number(vals.interval) || 300
        };

        const res = await fetch(`/api/user/connections/${encodeURIComponent(item.id)}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-Agent-Secret": agentCredential.agent_secret
          },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to update program connection on server");
        }

        connections[idx] = {
          ...item,
          identifier: vals.identifier?.trim() || "",
          interval: Number(vals.interval) || 300
        };

        await secureSet(KEYS.connections, JSON.stringify(connections));

        updateDashboard();
        renderProgramsList();
        goBack();
      } catch (err) {
        showError(err.message, "#edit-form-error");
      }
    });

    // Add another program from programs list
    document.querySelector("#btn-add-from-list").addEventListener("click", () => {
      navigateTo("view-platforms", "Select Platform");
    });

    // Clear all programs
    document.querySelector("#btn-clear-all").addEventListener("click", async () => {
      if (confirm("Are you sure you want to remove all saved programs?")) {
        connections = [];
        await secureRemove(KEYS.connections);
        updateDashboard();
        renderProgramsList();
      }
    });

    // Download Config Button
    document.querySelector("#download-config").addEventListener("click", () => {
      const helpEl = document.querySelector("#download-help");
      if (!agentCredential || !connections.length) {
        helpEl.textContent = "⚠️ Add at least one program connection first.";
        return;
      }

      const configData = JSON.stringify(
        {
          version: 2,
          relay: agentCredential,
          connections: connections
        },
        null,
        2
      );

      const blob = new Blob([configData], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "target-monitor-agent.json";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      helpEl.textContent = "✅ Downloaded target-monitor-agent.json. Keep it secure!";
    });

    // Initial storage check
    const consentGiven = (await secureGet(KEYS.consent)) || (await secureGet("tm-consent-v1"));
    if (consentGiven) {
      await registerAgentIfNeeded();
      await loadWorkspaceData();
    } else {
      navigateTo("view-consent", "Target Monitor", false);
    }
  }

  // Start app after DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
