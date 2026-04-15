document.addEventListener("DOMContentLoaded", () => {
  const toggle       = document.getElementById("toggle");
  const statusLabel  = document.getElementById("status-label");
  const domainInput  = document.getElementById("whitelist-input");
  const addBtn       = document.getElementById("add-btn");
  const whitelistList= document.getElementById("whitelist-list");
  const themeBtn     = document.getElementById("theme-btn");
  const vtKeyInput   = document.getElementById("vt-key-input");
  const vtSaveBtn    = document.getElementById("vt-save-btn");
  const vtStatus     = document.getElementById("vt-status");
  const root         = document.documentElement;

  let whitelist    = [];
  let currentDomain = '';

  /* ── Current tab domain ────────────────────────────────────────── */

  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (tabs[0]?.url) {
      try {
        const url = new URL(tabs[0].url);
        currentDomain = url.hostname.toLowerCase();
        domainInput.placeholder = `Current: ${currentDomain}`;
      } catch (_) {}
    }
  });

  /* ── Load saved settings ───────────────────────────────────────── */

  chrome.storage.local.get(
    ["protectionEnabled", "whitelist", "darkMode", "vtApiKey"],
    data => {
      toggle.checked = data.protectionEnabled ?? true;
      whitelist      = data.whitelist ?? [];
      root.setAttribute("data-theme", data.darkMode ? "dark" : "light");
      themeBtn.textContent = data.darkMode ? "☀️" : "🌙";
      updateStatus();
      renderWhitelist();

      // Show masked key if already saved
      if (data.vtApiKey) {
        vtKeyInput.placeholder = '✅ Key saved — paste a new one to replace';
        showVtStatus('ok', '✅ VirusTotal active');
      }
    }
  );

  /* ── Protection toggle ─────────────────────────────────────────── */

  toggle.addEventListener("change", () => {
    chrome.storage.local.set({ protectionEnabled: toggle.checked });
    updateStatus();
  });

  function updateStatus() {
    if (toggle.checked) {
      statusLabel.textContent = "Protection enabled";
      statusLabel.style.color = "var(--accent)";
    } else {
      statusLabel.textContent = "Protection disabled";
      statusLabel.style.color = "var(--danger)";
    }
  }

  /* ── Theme toggle ──────────────────────────────────────────────── */

  themeBtn.addEventListener("click", () => {
    const isDark = root.getAttribute("data-theme") === "dark";
    root.setAttribute("data-theme", isDark ? "light" : "dark");
    chrome.storage.local.set({ darkMode: !isDark });
    themeBtn.textContent = isDark ? "🌙" : "☀️";
  });

  /* ── Whitelist ─────────────────────────────────────────────────── */

  function renderWhitelist() {
    whitelistList.innerHTML = "";
    whitelist.forEach((domain, idx) => {
      const div = document.createElement("div");
      div.className = "whitelist-item";
      div.innerHTML = `
        <span>${domain}</span>
        <button data-idx="${idx}">×</button>
      `;
      whitelistList.appendChild(div);
    });
    whitelistList.querySelectorAll("button").forEach(btn => {
      btn.addEventListener("click", e => {
        whitelist.splice(Number(e.target.dataset.idx), 1);
        chrome.storage.local.set({ whitelist });
        renderWhitelist();
      });
    });
  }

  function addDomain() {
    let domain = domainInput.value.trim().toLowerCase() || currentDomain;
    if (!domain || whitelist.includes(domain)) {
      if (domain && whitelist.includes(domain)) {
        flash(domainInput, 'var(--danger)');
      }
      return;
    }
    whitelist.push(domain);
    chrome.storage.local.set({ whitelist });
    renderWhitelist();
    domainInput.value = "";
    flash(domainInput, 'var(--accent)');
  }

  addBtn.addEventListener("click", addDomain);
  domainInput.addEventListener("keydown", e => {
    if (e.key === "Enter") addDomain();
  });

  /* ── VirusTotal API key ────────────────────────────────────────── */

  vtSaveBtn.addEventListener("click", saveVtKey);
  vtKeyInput.addEventListener("keydown", e => {
    if (e.key === "Enter") saveVtKey();
  });

  function saveVtKey() {
    const key = vtKeyInput.value.trim();

    if (!key) {
      // Se il campo è vuoto, rimuove la key salvata
      chrome.storage.local.remove('vtApiKey');
      vtKeyInput.placeholder = 'Paste your free API key…';
      showVtStatus('err', '🗑️ Key removed');
      return;
    }

    // Validazione minima: le key VT sono hex da 64 caratteri
    if (!/^[a-f0-9]{64}$/i.test(key)) {
      showVtStatus('err', '❌ Invalid key format (must be 64 hex chars)');
      flash(vtKeyInput, 'var(--danger)');
      return;
    }

    chrome.storage.local.set({ vtApiKey: key }, () => {
      vtKeyInput.value = '';
      vtKeyInput.placeholder = '✅ Key saved — paste a new one to replace';
      showVtStatus('ok', '✅ Key saved successfully');
      flash(vtKeyInput, 'var(--accent)');
    });
  }

  function showVtStatus(type, msg) {
    vtStatus.textContent   = msg;
    vtStatus.className     = `vt-status ${type}`;
    // Auto-clear dopo 3s
    setTimeout(() => {
      vtStatus.textContent = '';
      vtStatus.className   = 'vt-status';
    }, 3000);
  }

  /* ── Utility ───────────────────────────────────────────────────── */

  function flash(el, color) {
    el.style.borderColor = color;
    setTimeout(() => { el.style.borderColor = ''; }, 600);
  }

});
