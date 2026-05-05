(() => {
  'use strict';

  /* ==================================================================
   *  CONSTANTS
   * ================================================================== */

  const OVERLAY_ID  = 'clip-detector-overlay-host';
  const MAX_Z_INDEX = '2147483647';

  /* ==================================================================
   *  DETECTION REGEX
   * ================================================================== */

  const RE = {

    /* ── URL completi (https://...) ────────────────────────────────── */
    URL_FULL:
      /\bhttps?:\/\/[^"'\s]{8,}/i,

    /* ── IP in formato esadecimale / ottale (sempre sospetto) ──────── */
    HEX_OCTAL_IP:
      /\b(?:(?:0x[0-9a-f]{1,2}|\d{1,3})\.){3}0x[0-9a-f]{1,2}\b/i,

    /* ── IP decimale standard (sospetto SOLO in contesto) ──────────── */
    PLAIN_IP:
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/,

    /* ── Generic flags / indicators ────────────────────────────────── */
    FLAGS_OR_INDICATORS:
      /\b(?:-EncodedCommand|-enc|-nop|-NoProfile|-UseBasicParsing|-Uri|\.ps1|-join|-[wW]\s+[hH]|-[wW]indowStyle|-[eE][pP]\s+[bB]|-ExecutionPolicy|-Bypass|-NonInteractive|-[mM][iI]|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|[A-Za-z0-9+/]{40,}=*)/i,

    /* ── LOLBINs / dangerous executables ───────────────────────────── */
    KEYWORDS:
      /\b(?:powershell(?:\.exe)?|mshta|msiexec|rundll32|regsvr32|certutil|iex|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-?Bits(?:Transfer)?|bitsadmin|bash|curl|\/bin\/bash|wget|wmic|cmd)\b/i,

    /* ── bash / sh + curl ──────────────────────────────────────────── */
    BASH_CURL:
      /\b(?:bash|\/bin\/bash|zsh|sh)\b[^\n]*\bcurl\b/i,

    /* ── iwr | iex ─────────────────────────────────────────────────── */
    IWR_IEX:
      /\b(?:iwr|irm)\b[^\n]*\|\s*iex\b/i,

    /* ── irm / iwr pipe diretta a iex ──────────────────────────────── */
    IRM_PIPE_IEX:
      /\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b/i,

    /* ── iex(irm ...) / iex(iwr ...) ───────────────────────────────── */
    IEX_WRAP:
      /\biex\s*\(\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i,

    /* ── iex $var ───────────────────────────────────────────────────── */
    IEX_VAR:
      /\biex\s+\$[a-z]+/i,

    /* ── Set-Alias per rinominare cmdlet pericolosi ─────────────────── */
    SET_ALIAS_EXEC:
      /Set-Alias\b[^\n]*(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|iex|iwr|irm)\b/i,

    /* ── PowerShell flag abbreviazioni + exec ───────────────────────── */
    PS_FLAG_EXEC:
      /powershell[^\n]{0,120}(?:-[wW]\s+[hH]|-[wW]indow[sS]tyle\s+[hH]idden|-[eE][pP]\s+[bB]|-[eE]xecution[pP]olicy\s+[bB]ypass|-[nN]on[iI]nteractive|-[mM][iI]|-[nN]o[pP]|-[nN]o[eE])[^\n]{0,120}(?:iex|irm|iwr|DownloadString|curl|wget)/i,

    /* ── PowerShell XOR / hex obfuscation ──────────────────────────── */
    POWERSHELL_XOR_EXEC:
      /\$[a-z]+='[a-z0-9+\/]{4,}'.*\$[a-z]+='[0-9a-f]{20,}'/i,
    HEX_BXOR_LOOP:
      /\[convert\]::ToInt32[^\n]*,\s*16\)[^\n]*bxor/i,
    SCRIPTBLOCK_INVOKE:
      /&\s*\(\s*\[ScriptBlock\]::Create\s*\(\s*\$[a-z]+\s*\)\s*\)/i,
    FAKE_VERIFICATION_HEADER:
      /<#\s*Verification\s+code\s*:\s*[A-F0-9]{10,}\s*#>/i,

    /* ── PowerShell -EncodedCommand + base64 blob ───────────────────── */
    ENCODEDCOMMAND:
      /powershell[^\n]{0,80}-[eE](?:nc(?:odedCommand)?)?[^\n]{1,5}[A-Za-z0-9+/]{20,}={0,2}/i,

    /* ── Base64 decode + exec ───────────────────────────────────────── */
    BASE64_DECODE_EXEC:
      /\bFromBase64String\b|\bbase64\s+-[dD]\b[^\n]*\|\s*(?:bash|zsh|sh|eval)\b/i,

    /* ── DownloadString / DownloadFile ──────────────────────────────── */
    DOWNLOAD_STRING:
      /\bDownloadString\b|\bDownloadFile\b/i,

    /* ── MSHTA ──────────────────────────────────────────────────────── */
    MSHTA_REMOTE:
      /\bmshta\b[^\n]*https?:\/\//i,
    MSHTA_LOLBIN_EXT:
      /\bmshta\b[^\n]*\.\s*(?:mp3|mp4|jpg|jpeg|swf|html?)\b/i,

    /* ── certutil ───────────────────────────────────────────────────── */
    CERTUTIL_DECODE:
      /\bcertutil\b[^\n]*(?:-decode|-urlcache|-f|-split)\b/i,

    /* ── BITSAdmin ──────────────────────────────────────────────────── */
    BITSADMIN_TRANSFER:
      /\bbitsadmin\b[^\n]*\/transfer\b/i,

    /* ── curl / wget pipe to shell ──────────────────────────────────── */
    CURL_PIPE_SHELL:
      /\bcurl\b[^\n]*\|\s*(?:bash|zsh|sh)\b|\bwget\b[^\n]*-[qO-]*\s*-\s*\|[^\n]*(?:bash|sh)\b/i,

    /* ── cmd /c one-liner ───────────────────────────────────────────── */
    CMD_ONELINER:
      /\bcmd(?:\.exe)?\b[^\n]{0,10}\/[cC]\s+[^\n]{10,}/i,

    /* ── Defender tampering ─────────────────────────────────────────── */
    DEFENDER_TAMPER:
      /Set-MpPreference\s+-Disable|Add-MpPreference\b/i,

    /* ── rundll32 / regsvr32 ────────────────────────────────────────── */
    RUNDLL_REMOTE:
      /\b(?:rundll32|regsvr32)\b[^\n]*https?:\/\//i,
    RUNDLL32_UNC:
      /\brundll32(?:\.exe)?\b[^\n]*\\\\[^\s\\]+@\d+\\/i,
    UNC_WEBDAV:
      /\\\\[a-z0-9._-]+@\d{2,5}\\[^\s]{4,}/i,

    /* ── wmic ───────────────────────────────────────────────────────── */
    WMIC_EXEC:
      /\bwmic\b[^\n]*process[^\n]*call[^\n]*create\b/i,

    /* ── Persistence ────────────────────────────────────────────────── */
    PERSISTENCE:
      /\bschtasks\b[^\n]*\/create\b|\bNew-ScheduledTask\b|HKCU\\[^\n]*\\Run\b|HKLM\\[^\n]*\\Run\b/i,

    /* ── Start-Process / Invoke-Expression con URL ──────────────────── */
    START_PROCESS_URL:
      /\bStart-Process\b[^\n]*https?:\/\/|\bInvoke-Expression\b[^\n]*https?:\/\//i,

    /* ── macOS ──────────────────────────────────────────────────────── */
    OSASCRIPT:
      /\bosascript\b/i,
    DSCL_AUTH:
      /\bdscl\b[^\n]*-authonly\b|\bdscl\s+\.\s+-(?:auth|passwd)\b/i,

	/* ── WindowStyle con qualsiasi valore (hidden, minimized, ecc.) case insensitive  ──────────────────── */
	PS_WINDOWSTYLE:
	   /powershell[^\n]{0,120}-[wW](?:indow[sS]tyle)?\s+(?:h(?:idden)?|m(?:inimized)?|n(?:ormal)?)\b/i,

	/* ── IP con anche solo un ottetto in hex ──────────────────── */
	MIXED_HEX_IP:
	   /\b(?:\d{1,3}\.){0,3}0x[0-9a-f]{1,2}(?:\.\d{1,3}){0,3}\b/i,

	/* ── Add-Type TypeDefinition ──────────────────── */
	ADD_TYPE_DEF:
	  /Add-Type\b[^\n]*-TypeDefinition\b/i,

    /* ── SSH proxy ──────────────────────────────────────────────────── */
    SSH_PROXY:
      /\bssh\b[^\n]*-[oO]\s*(?:StrictHostKeyChecking|ProxyCommand)\b/i,
	  
	  // [System.Diagnostics.Process]::Start con powershell
    PROCESS_START_PS:
      /\[System\.Diagnostics\.Process\]::Start\s*\([^\)]*powershell/i,

    // String obfuscation: -replace / .Trim / .Replace usati per ricostruire URL/comandi
    STRING_OBFUSCATION:
      /(?:-replace\s+['"][^'"]{1,20}['"]|\.Trim\s*\([^)]*\)|\.Replace\s*\([^)]*\))[^\n]{0,60}(?:https?|iex|iwr|irm|powershell)/i,

    // Concatenazione di array con |%{ } per costruire stringhe (foreach obfuscation)
    FOREACH_CONCAT:
      /\|\s*%\s*\{\s*\$[a-z]+\s*\+=\s*\$_\s*\}/i,
	  
	// Substring index obfuscation: $var[(N)/(M)] per costruire cmdlet
    SUBSTRING_INDEX_OBFUSC:
      /\$[a-z]+\[\s*\(\s*\d+\s*\)\s*\/\s*\(\s*\d+\s*\)\s*\]/i,

    // .Substring(N,M) per estrarre parti di stringa e costruire comandi
    SUBSTRING_BUILD:
      /\$[a-z]+=\s*\([^)]*\.Substring\s*\(\s*\d+\s*,\s*\d+\s*\)\s*\)/i,

    // .Remove(N).Remove(M) chaining — tecnica per estrarre nomi cmdlet
    REMOVE_CHAIN:
      /\.Remove\s*\(\s*\d+\s*(?:,\s*\d+\s*)?\)\.Remove\s*\(\s*\d+\s*\)/i,
	  
	// Chrome policy hijacking via reg add (forza installazione estensioni malevole)
    CHROME_POLICY_HIJACK:
      /reg\s+add\b[^\n]*(?:SOFTWARE\\Policies\\Google\\Chrome|CloudManagementEnrollmentToken|ExtensionInstallSources|ExtensionInstallAllowlist|ExtensionSettings)[^\n]*/i,

    // reg add generico su chiavi di policy/run (persistence + hijacking)
    REG_ADD_POLICY:
     /\breg\s+add\b[^\n]*(?:HKLM|HKCU)[^\n]*\\(?:Policies|Run|RunOnce|Software\\Microsoft\\Windows\\CurrentVersion)\b/i,
	 
	 // rundll32 UNC senza porta (path diretto)
    RUNDLL32_UNC_NOPORT:
     /\brundll32(?:\.exe)?\b[^\n]*\\\\[a-z0-9._-]+\\[^\s,]{8,},#\d+/i,

    // msiexec con URL remoto (dropper via installer)
    MSIEXEC_REMOTE:
     /\bmsiexec\b[^\n]*\/[iI]\s+https?:\/\//i,
	 
	// FromBase64String + UTF8.GetString + Invoke-Expression (decode + exec fileless)
    BASE64_DECODE_INVOKE:
     /\[System\.Convert\]::FromBase64String\b[^\n]*\n?[^\n]*\[System\.Text\.Encoding\]::\w+\.GetString\b/i,

    // [System.Text.Encoding]::UTF8.GetString usato per decodificare payload
    UTF8_GETSTRING:
     /\[System\.Text\.Encoding\]::\w+\.GetString\s*\(/i
	    
  };

  /* ==================================================================
   *  SCORING DETECTION
   * ================================================================== */

  function isSuspicious(text) {
    let score = 0;

    // Score 4 — da soli sufficienti a triggerare
    if (RE.FAKE_VERIFICATION_HEADER.test(text)) score += 4;
    if (RE.HEX_BXOR_LOOP.test(text))            score += 4;
    if (RE.SCRIPTBLOCK_INVOKE.test(text))        score += 4;
    if (RE.MSHTA_REMOTE.test(text))              score += 4;
    if (RE.CURL_PIPE_SHELL.test(text))           score += 4;
    if (RE.ENCODEDCOMMAND.test(text))            score += 4;
    if (RE.RUNDLL_REMOTE.test(text))             score += 4;
    if (RE.RUNDLL32_UNC.test(text))              score += 4;
    if (RE.UNC_WEBDAV.test(text))                score += 4;
    if (RE.HEX_OCTAL_IP.test(text))              score += 4;
    if (RE.SET_ALIAS_EXEC.test(text))            score += 4;
    if (RE.IRM_PIPE_IEX.test(text))              score += 4;
    if (RE.IEX_WRAP.test(text))                  score += 4;
    if (RE.PS_FLAG_EXEC.test(text))              score += 4;
	if (RE.PS_WINDOWSTYLE.test(text))            score += 4;
	if (RE.MIXED_HEX_IP.test(text))              score += 4;
	if (RE.PROCESS_START_PS.test(text))          score += 4;
	if (RE.SUBSTRING_INDEX_OBFUSC.test(text))    score += 4;
	if (RE.CHROME_POLICY_HIJACK.test(text))      score += 4;
	if (RE.RUNDLL32_UNC_NOPORT.test(text))       score += 4;
	if (RE.MSIEXEC_REMOTE.test(text))            score += 4;
	if (RE.BASE64_DECODE_INVOKE.test(text))      score += 4;

    // Score 3 — alta confidenza
    if (RE.IEX_VAR.test(text))                   score += 3;
    if (RE.POWERSHELL_XOR_EXEC.test(text))       score += 3;
    if (RE.BASE64_DECODE_EXEC.test(text))        score += 3;
    if (RE.CERTUTIL_DECODE.test(text))           score += 3;
    if (RE.BITSADMIN_TRANSFER.test(text))        score += 3;
    if (RE.DEFENDER_TAMPER.test(text))           score += 3;
    if (RE.MSHTA_LOLBIN_EXT.test(text))          score += 3;
    if (RE.DOWNLOAD_STRING.test(text))           score += 3;
    if (RE.DSCL_AUTH.test(text))                 score += 3;
    if (RE.WMIC_EXEC.test(text))                 score += 3;
    if (RE.PERSISTENCE.test(text))               score += 3;
    if (RE.START_PROCESS_URL.test(text))         score += 3;
	if (RE.ADD_TYPE_DEF.test(text))    		     score += 3;
	if (RE.STRING_OBFUSCATION.test(text))        score += 3;
	if (RE.FOREACH_CONCAT.test(text))            score += 3;
	if (RE.SUBSTRING_BUILD.test(text))           score += 3;
	if (RE.REMOVE_CHAIN.test(text))              score += 3;
	if (RE.REG_ADD_POLICY.test(text))            score += 3;
	if (RE.UTF8_GETSTRING.test(text))            score += 3;

    // Score 2 — media confidenza
    if (RE.IWR_IEX.test(text))                   score += 2;
    if (RE.BASH_CURL.test(text))                 score += 2;
    if (RE.CMD_ONELINER.test(text))              score += 2;
    if (RE.OSASCRIPT.test(text))                 score += 2;
    if (RE.SSH_PROXY.test(text))                 score += 2;

    // Score 1 — segnali deboli
    if (RE.KEYWORDS.test(text))                  score += 1;
    if (RE.FLAGS_OR_INDICATORS.test(text))       score += 1;

    // URL completo: conta solo se c'è già almeno un altro segnale
    if (RE.URL_FULL.test(text) && score > 0)     score += 1;

    // IP decimale plain: conta solo in contesto sospetto (score già > 0)
    if (RE.PLAIN_IP.test(text) && score > 0)     score += 1;

    return score >= 4;
  }

  /* ==================================================================
   *  PAGE CONTEXT INJECTION
   * ================================================================== */

  function injectPageScript() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('page_inject.js');
      script.type = 'text/javascript';
      (document.documentElement || document.head || document.body).appendChild(script);
      script.onload = () => { try { script.remove(); } catch (_) {} };
    } catch (err) {
      console.error('[CD] Injection error', err);
    }
  }

  /* ==================================================================
   *  UTILITIES
   * ================================================================== */

  function overlayExists() {
    return Boolean(document.getElementById(OVERLAY_ID));
  }

  function removeOverlay(host) {
    try { host.remove(); } catch (_) {}
  }

  function sendAction(action, payload = {}) {
    try {
      chrome.runtime.sendMessage({ type: 'clip_action', action, ...payload });
    } catch (_) {}
  }

  async function clearClipboard() {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText('');
      return;
    }
    const ta = document.createElement('textarea');
    ta.value = '';
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }

  function getCurrentDomain() {
    try { return window.location.hostname.toLowerCase(); } catch (_) { return ''; }
  }

  async function isWhitelisted() {
    return new Promise(resolve => {
      try {
        chrome.storage.local.get(['whitelist'], data => {
          const whitelist = data.whitelist || [];
          const currentDomain = getCurrentDomain();
          resolve(whitelist.some(d => currentDomain === d || currentDomain.endsWith('.' + d)));
        });
      } catch (_) { resolve(false); }
    });
  }

  /* ==================================================================
   *  VIRUSTOTAL — richiesta al background
   * ================================================================== */

  function requestVtScan(text, shadow) {
    const vtPanel = shadow.querySelector('#vt-panel');
    if (!vtPanel) return;

    chrome.storage.local.get(['vtApiKey'], data => {
      if (!data.vtApiKey) {
        vtPanel.innerHTML = `
          <div class="vt-note">
            ⚙️ Add your <a href="https://www.virustotal.com/gui/my-apikey" target="_blank">VirusTotal API key</a>
            in the extension settings to enable reputation checks.
          </div>`;
        return;
      }

      vtPanel.innerHTML = `<div class="vt-loading"><span class="vt-spinner"></span> Checking VirusTotal…</div>`;

      chrome.runtime.sendMessage({ type: 'vt_lookup', text }, response => {
        if (chrome.runtime.lastError || !response?.ok) {
          vtPanel.innerHTML = `<div class="vt-note">⚠️ VirusTotal lookup failed.</div>`;
          return;
        }

        if (response.noKey) {
          vtPanel.innerHTML = `<div class="vt-note">⚙️ No API key configured.</div>`;
          return;
        }

        if (response.noIndicators) {
          vtPanel.innerHTML = `<div class="vt-note">No domains or IPs found in payload.</div>`;
          return;
        }

        if (response.error) {
          vtPanel.innerHTML = `<div class="vt-note">⚠️ ${response.error}</div>`;
          return;
        }

        const results = response.results || [];
        if (results.length === 0) {
          vtPanel.innerHTML = `<div class="vt-note">No results.</div>`;
          return;
        }

        // Quota info
        const quota = response.quota;
        const quotaHtml = quota
          ? `<div class="vt-quota">Quota: ${quota.usedToday}/${500} used today</div>`
          : '';

        vtPanel.innerHTML = results.map(r => {
          if (r.error) {
            return `<div class="vt-row">
              <span class="vt-indicator">${r.type === 'ip' ? '🌐' : '🔗'} <strong>${r.value}</strong></span>
              <span class="vt-status vt-gray">Error: ${r.error}</span>
            </div>`;
          }
          if (r.unknown) {
            return `<div class="vt-row">
              <span class="vt-indicator">${r.type === 'ip' ? '🌐' : '🔗'} <strong>${r.value}</strong></span>
              <span class="vt-status vt-gray">Unknown to VT</span>
            </div>`;
          }

          const isDanger  = r.malicious >= 3;
          const isWarning = !isDanger && (r.malicious > 0 || r.suspicious > 0);
          const isClean   = !isDanger && !isWarning;
          const statusClass = isDanger ? 'vt-red' : isWarning ? 'vt-orange' : 'vt-green';
          const statusLabel = isDanger
            ? `🚨 ${r.malicious}/${r.total} malicious`
            : isWarning
              ? `⚠️ ${r.malicious} malicious, ${r.suspicious} suspicious / ${r.total}`
              : `✅ Clean (${r.total} engines)`;

          return `<div class="vt-row">
            <span class="vt-indicator">${r.type === 'ip' ? '🌐' : '🔗'}
              <a class="vt-link" href="${r.link}" target="_blank">${r.value}</a>
            </span>
            <span class="vt-status ${statusClass}">${statusLabel}</span>
          </div>`;
        }).join('') + quotaHtml;
      });
    });
  }

  /* ==================================================================
   *  UI (Shadow DOM Modal)
   * ================================================================== */

  const modalHtml = `
<style>
  :host { all: initial; }

  @keyframes fadeIn {
    from { opacity: 0; transform: scale(.96) translateY(8px); }
    to   { opacity: 1; transform: scale(1)   translateY(0); }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .overlay {
    position: fixed; inset: 0;
    background: rgba(2,6,23,.75);
    backdrop-filter: blur(14px) saturate(140%);
    display: flex; align-items: center; justify-content: center;
    pointer-events: auto;
  }

  .card {
    width: 660px; max-width: calc(100% - 32px);
    background: linear-gradient(180deg, rgba(15,23,42,.97), rgba(2,6,23,.97));
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,.08);
    box-shadow: 0 40px 120px rgba(0,0,0,.7);
    color: #e5e7eb;
    font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    animation: fadeIn .25s ease-out;
    overflow: hidden;
  }

  .header {
    padding: 18px 22px;
    border-bottom: 1px solid rgba(255,255,255,.06);
  }

  .badge {
    font-size: 11px; font-weight: 700; letter-spacing: .04em;
    text-transform: uppercase; padding: 4px 8px; border-radius: 999px;
    background: rgba(248,113,113,.15); color: #f87171;
    display: inline-block; margin-bottom: 6px;
  }

  .title    { font-size: 16px; font-weight: 600; color: #f8fafc; }
  .subtitle { font-size: 12px; color: #94a3b8; margin-top: 2px; }
  .content  { padding: 18px 22px; }

  .desc {
    font-size: 13px; line-height: 1.6; color: #cbd5f5; margin-bottom: 14px;
  }

  pre {
    background: rgba(2,6,23,.9);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 12px; padding: 14px;
    max-height: 200px; overflow: auto;
    font-size: 12.5px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: #e2e8f0; white-space: pre-wrap; word-break: break-word;
    margin-bottom: 14px;
  }

  .vt-section {
    border-top: 1px solid rgba(255,255,255,.06);
    padding: 12px 0 4px;
  }

  .vt-title {
    font-size: 11px; font-weight: 700; letter-spacing: .06em;
    text-transform: uppercase; color: #64748b; margin-bottom: 10px;
  }

  #vt-panel { min-height: 28px; }

  .vt-loading {
    display: flex; align-items: center; gap: 8px;
    font-size: 12px; color: #94a3b8;
  }

  .vt-spinner {
    width: 13px; height: 13px;
    border: 2px solid rgba(255,255,255,.15);
    border-top-color: #60a5fa;
    border-radius: 50%;
    display: inline-block;
    animation: spin .7s linear infinite;
  }

  .vt-row {
    display: flex; align-items: center; justify-content: space-between;
    gap: 10px; padding: 6px 0;
    border-bottom: 1px solid rgba(255,255,255,.04);
    font-size: 12px;
  }
  .vt-row:last-child { border-bottom: none; }

  .vt-indicator { color: #cbd5e1; display: flex; align-items: center; gap: 5px; }
  .vt-link { color: #93c5fd; text-decoration: none; }
  .vt-link:hover { text-decoration: underline; }

  .vt-status { font-size: 11.5px; font-weight: 600; white-space: nowrap; }
  .vt-red    { color: #f87171; }
  .vt-orange { color: #fb923c; }
  .vt-green  { color: #4ade80; }
  .vt-gray   { color: #64748b; }

  .vt-note {
    font-size: 11.5px; color: #64748b; padding: 4px 0;
  }
  .vt-note a { color: #60a5fa; }

  .vt-quota {
    font-size: 10.5px; color: #475569;
    margin-top: 8px; text-align: right;
  }

  .footer {
    padding: 14px 22px 18px;
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    border-top: 1px solid rgba(255,255,255,.06);
  }

  .hint    { font-size: 11px; color: #64748b; }
  .actions { display: flex; gap: 10px; }

  button {
    border-radius: 12px; padding: 9px 16px;
    font-size: 13px; font-weight: 600; cursor: pointer; border: none;
  }

  #ignore {
    background: rgba(255,255,255,.04); color: #cbd5e1;
    border: 1px solid rgba(255,255,255,.12);
  }
  #ignore:hover { background: rgba(255,255,255,.08); }

  #clean { background: linear-gradient(135deg, #fb7185, #ef4444); color: #020617; }
  #clean:hover { filter: brightness(1.05); }
</style>

<div class="overlay">
  <div class="card" role="dialog" aria-modal="true">
    <div class="header">
      <div class="badge">Security alert</div>
      <div class="title">Suspicious Clipboard Content</div>
      <div class="subtitle">Potential command execution detected</div>
    </div>
    <div class="content">
      <div class="desc">
        This content was copied to your clipboard and matches known patterns
        used for malware delivery or remote command execution.
      </div>
      <pre id="cd-text"></pre>
      <div class="vt-section">
        <div class="vt-title">🔍 VirusTotal Reputation</div>
        <div id="vt-panel"><div class="vt-loading"><span class="vt-spinner"></span> Initializing…</div></div>
      </div>
    </div>
    <div class="footer">
      <div class="hint">Clipboard Defender · By Alex Necula</div>
      <div class="actions">
        <button id="ignore">Allow once</button>
        <button id="clean">Clear clipboard</button>
      </div>
    </div>
  </div>
</div>
`;

  function createIsolatedModal({ text = '', reason = '' } = {}) {
    if (overlayExists()) return;

    const host = document.createElement('div');
    host.id = OVERLAY_ID;
    host.style.cssText = `position:fixed;inset:0;z-index:${MAX_Z_INDEX};pointer-events:none`;

    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = modalHtml;

    (document.documentElement || document.body).appendChild(host);

    shadow.querySelector('#cd-text').textContent = text;
    requestVtScan(text, shadow);

    shadow.querySelector('#ignore')?.addEventListener('click', () => {
      sendAction('ignore', { text, reason });
      removeOverlay(host);
    });

    shadow.querySelector('#clean')?.addEventListener('click', async () => {
      try {
        await clearClipboard();
        sendAction('clean', { text, reason });
      } catch (err) {
        sendAction('clean_failed', { error: String(err), text, reason });
      }
      removeOverlay(host);
    });

    shadow.querySelector('.overlay')?.addEventListener('click', ev => {
      if (ev.target.classList.contains('overlay')) removeOverlay(host);
    });
  }

  /* ==================================================================
   *  MESSAGE HANDLER
   * ================================================================== */

  async function onMessage(event) {
    const msg = event.data;
    if (!msg || typeof msg !== 'object') return;
    if (msg.text === '__INJECT_OK__') return;
    if (typeof msg.text !== 'string') return;

    const settings = await new Promise(resolve => {
      chrome.storage.local.get(['protectionEnabled'], data => resolve(data));
    });
    if (settings.protectionEnabled === false) return;

    if (await isWhitelisted()) {
      console.log('[CD] Domain is whitelisted, skipping detection');
      return;
    }

    if (!isSuspicious(msg.text)) return;

    try {
      if (window.top && window.top !== window) {
        window.top.postMessage({
          source: 'CLIP_DETECTOR_SHOW_UI',
          text: msg.text,
          reason: msg.reason,
          ts: msg.ts
        }, '*');
        return;
      }
    } catch (_) {}

    createIsolatedModal({ text: msg.text, reason: msg.reason });
  }

  /* ==================================================================
   *  INIT
   * ================================================================== */

  injectPageScript();
  window.addEventListener('message', onMessage, false);

})();
