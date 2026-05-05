// page_inject.js — eseguito nel contesto della pagina/frame
(function () {
  'use strict';

  /* ==================================================================
   *  SUSPICIOUS REGEX
   *  NOTA: l'IP decimale plain (es. 185.161.251.58) NON è incluso da
   *  solo — compare solo nei pattern contestuali (iex, powershell ecc.)
   *  per evitare falsi positivi quando si copia un IP da un articolo.
   * ================================================================== */

  const SUSPICIOUS_RE = new RegExp([

    // ── LOLBINs Windows ────────────────────────────────────────────
    '\\b(?:powershell(?:\\.exe)?|mshta|msiexec|rundll32|regsvr32|certutil|bitsadmin|wmic|cmd(?:\\.exe)?)\\b',

    // ── PowerShell esecuzione remota ───────────────────────────────
    '\\biex\\b',
    '\\biwr\\b',
    '\\birm\\b',
    'Invoke-WebRequest',
    'Invoke-RestMethod',
    'DownloadString',
    'DownloadFile',
    'FromBase64String',
    'Start-Process[^\\n]{0,60}https?:\\/\\/',
    'Invoke-Expression[^\\n]{0,60}https?:\\/\\/',

    // ── iex(irm/iwr ...) wrap ──────────────────────────────────────
    '\\biex\\s*\\(\\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\\b',

    // ── irm/iwr | iex pipe ─────────────────────────────────────────
    '\\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\\b[^\\n]*\\|\\s*(?:iex|Invoke-Expression)\\b',

    // ── Set-Alias per offuscare cmdlet ─────────────────────────────
    'Set-Alias\\b[^\\n]*(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|iex|iwr|irm)\\b',

    // ── PowerShell flag abbreviati + exec ──────────────────────────
    'powershell[^\\n]{0,120}(?:-[wW]\\s+[hH]|-[eE][pP]\\s+[bB]|-[nN]o[pP]|-[mM][iI]|-[nN]on[iI]nteractive)[^\\n]{0,120}(?:iex|irm|iwr|DownloadString|curl|wget)',

    // ── PowerShell XOR / hex obfuscation ──────────────────────────
    '\\[convert\\]::ToInt32[\\s\\S]{0,60},\\s*16\\)',
    '-bxor',
    '\\[ScriptBlock\\]::Create',
    '\\$[a-z]+=[\'"][a-z0-9+\\/]{4,}[\'"][\\s\\S]{0,200}\\$[a-z]+=[\'"][0-9a-f]{20,}[\'"]',

    // ── Fake verification header ───────────────────────────────────
    '<#\\s*Verification\\s+code\\s*:[^#]{6,}#>',

    // ── -EncodedCommand + base64 blob ─────────────────────────────
    'powershell[^\\n]{0,80}-[eE](?:nc(?:odedCommand)?)?[^\\n]{1,5}[A-Za-z0-9+\\/]{20,}={0,2}',

    // ── Base64 decode + exec (Linux/macOS) ────────────────────────
    'base64\\s+-[dD][^\\n]{0,60}\\|\\s*(?:bash|zsh|sh|eval)',

    // ── curl / wget pipe to shell ──────────────────────────────────
    '\\bcurl\\b[^\\n]*\\|\\s*(?:bash|zsh|sh)\\b',
    '\\bwget\\b[^\\n]*\\|\\s*(?:bash|zsh|sh)\\b',

    // ── bash/sh + curl combo ───────────────────────────────────────
    '\\b(?:bash|zsh|sh|\\/bin\\/bash)\\b[^\\n]*\\bcurl\\b',

    // ── MSHTA remote / fake extension ─────────────────────────────
    '\\bmshta\\b[^\\n]*https?:\\/\\/',
    '\\bmshta\\b[^\\n]*\\.(?:mp3|mp4|jpg|jpeg|swf|html?)\\b',

    // ── certutil abuse ─────────────────────────────────────────────
    '\\bcertutil\\b[^\\n]*(?:-decode|-urlcache|-f|-split)\\b',

    // ── bitsadmin ─────────────────────────────────────────────────
    '\\bbitsadmin\\b[^\\n]*\\/transfer\\b',

    // ── rundll32 / regsvr32 remote ─────────────────────────────────
    '\\b(?:rundll32|regsvr32)\\b[^\\n]*https?:\\/\\/',

    // ── rundll32 UNC WebDAV (@porta) ──────────────────────────────
    '\\brundll32(?:\\.exe)?\\b[^\\n]*\\\\\\\\[^\\s\\\\]+@\\d+\\\\',

    // ── UNC WebDAV generico (@80 @443 ecc.) ───────────────────────
    '\\\\\\\\[a-z0-9._-]+@\\d{2,5}\\\\[^\\s]{4,}',

    // ── IP esadecimale / ottale (sempre sospetto) ──────────────────
    '\\b(?:(?:0x[0-9a-f]{1,2}|\\d{1,3})\\.){3}0x[0-9a-f]{1,2}\\b',

    // ── wmic process call create ───────────────────────────────────
    '\\bwmic\\b[^\\n]*process[^\\n]*call[^\\n]*create\\b',

    // ── Defender disabling ─────────────────────────────────────────
    'Set-MpPreference\\s+-Disable',
    'Add-MpPreference\\b',

    // ── Persistence ────────────────────────────────────────────────
    '\\bschtasks\\b[^\\n]*\\/create\\b',
    'New-ScheduledTask\\b',
    'HKCU\\\\[^\\n]*\\\\Run\\b',
    'HKLM\\\\[^\\n]*\\\\Run\\b',

    // ── macOS specifici ────────────────────────────────────────────
    '\\bosascript\\b',
    '\\bdscl\\b[^\\n]*-authonly\\b',
	
	// WindowStyle case insensitive
	'powershell[^\\n]{0,120}-[wW](?:indow[sS]tyle)?\\s+(?:h(?:idden)?|m(?:inimized)?)',

	// IP misto decimale/hex
	'\\b(?:\\d{1,3}\\.){0,3}0x[0-9a-f]{1,2}(?:\\.\\d{1,3}){0,3}\\b',
	
	// Add-Type TypeDefinition
	'Add-Type\\b[^\\n]*-TypeDefinition\\b',

    // ── SSH proxy tunneling ────────────────────────────────────────
    '\\bssh\\b[^\\n]*-[oO]\\s*(?:StrictHostKeyChecking|ProxyCommand)\\b',
	
	// [System.Diagnostics.Process]::Start powershell
    '\\[System\\.Diagnostics\\.Process\\]::Start\\s*\\([^\\)]*powershell',

    // String obfuscation -replace / .Trim / .Replace
    '(?:-replace\\s+[\'"][^\'"]{1,20}[\'"]|\\.Trim\\s*\\(|\\.Replace\\s*\\()[^\\n]{0,60}(?:https?|iex|iwr|irm|powershell)',

    // foreach concat obfuscation |%{$x+=$_}
    '\\|\\s*%\\s*\\{\\s*\\$[a-z]+\\s*\\+=\\s*\\$_\\s*\\}',
	
	// Substring index obfuscation
    '\\$[a-z]+\\[\\s*\\(\\s*\\d+\\s*\\)\\s*\\/\\s*\\(\\s*\\d+\\s*\\)\\s*\\]',

    // .Substring(N,M) build
    '\\$[a-z]+=\\s*\\([^)]*\\.Substring\\s*\\(\\s*\\d+\\s*,\\s*\\d+\\s*\\)',

    // .Remove(N).Remove(M) chaining
    '\\.Remove\\s*\\(\\s*\\d+\\s*(?:,\\s*\\d+\\s*)?\\)\\.Remove\\s*\\(\\s*\\d+\\s*\\)',
	
	// Chrome policy hijacking
    'reg\\s+add\\b[^\\n]*(?:SOFTWARE\\\\Policies\\\\Google\\\\Chrome|CloudManagementEnrollmentToken|ExtensionInstallSources|ExtensionInstallAllowlist)',

    // reg add su chiavi HKLM/HKCU sensibili
    '\\breg\\s+add\\b[^\\n]*(?:HKLM|HKCU)[^\\n]*\\\\(?:Policies|Run|RunOnce)',
	
	// rundll32 UNC senza porta
    '\\brundll32(?:\\.exe)?\\b[^\\n]*\\\\\\\\[a-z0-9._-]+\\\\[^\\s,]{8,},#\\d+',

    // msiexec URL remoto
    '\\bmsiexec\\b[^\\n]*\\/[iI]\\s+https?:\\/\\/',
	
	// FromBase64String + UTF8.GetString chain
    '\\[System\\.Convert\\]::FromBase64String\\b',
    '\\[System\\.Text\\.Encoding\\]::\\w+\\.GetString\\s*\\('
	

  ].join('|'), 'i');

  /* ==================================================================
   *  UTILITIES
   * ================================================================== */

  function postDetection(text, reason) {
    try {
      window.postMessage({ source: 'CLIP_DETECTOR_INJECT', text, reason, ts: Date.now() }, '*');
      window.postMessage({ source: 'CLIP_DETECTOR_SHOW_UI', text, reason, ts: Date.now() }, '*');
    } catch (_) {}
  }

  function isSuspicious(text) {
    return typeof text === 'string' && text.length > 0 && SUSPICIOUS_RE.test(text);
  }

  /* ==================================================================
   *  HEARTBEAT
   * ================================================================== */

  window.postMessage({ source: 'CLIP_DETECTOR_INJECT', text: '__INJECT_OK__', reason: 'injected' }, '*');

  /* ==================================================================
   *  1) navigator.clipboard.writeText
   * ================================================================== */

  try {
    if (navigator?.clipboard && typeof navigator.clipboard.writeText === 'function') {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function (text) {
        try { if (isSuspicious(text)) postDetection(text, 'navigator.clipboard.writeText'); } catch (_) {}
        return orig(text);
      };
    }
  } catch (_) {}

  /* ==================================================================
   *  2) navigator.clipboard.write (ClipboardItem API)
   * ================================================================== */

  try {
    if (navigator?.clipboard && typeof navigator.clipboard.write === 'function') {
      const orig = navigator.clipboard.write.bind(navigator.clipboard);
      navigator.clipboard.write = async function (items) {
        try {
          for (const item of items) {
            for (const type of item.types) {
              if (type === 'text/plain') {
                const text = await (await item.getType(type)).text();
                if (isSuspicious(text)) postDetection(text, 'navigator.clipboard.write');
              }
            }
          }
        } catch (_) {}
        return orig(items);
      };
    }
  } catch (_) {}

  /* ==================================================================
   *  3) document.execCommand('copy')
   * ================================================================== */

  try {
    const origExec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (cmd) {
      try {
        if (String(cmd).toLowerCase() === 'copy') {
          const sel = window.getSelection?.().toString() || '';
          if (isSuspicious(sel)) { postDetection(sel, 'document.execCommand(copy)'); return false; }
        }
      } catch (_) {}
      return origExec.apply(this, arguments);
    };
  } catch (_) {}

  /* ==================================================================
   *  4) 'copy' event listener
   * ================================================================== */

  try {
    window.addEventListener('copy', function (evt) {
      try {
        const cb   = evt.clipboardData || window.clipboardData;
        const text = cb?.getData?.('text/plain') || window.getSelection?.().toString() || '';
        if (isSuspicious(text)) {
          postDetection(text, 'copy-event');
          evt.preventDefault();
          try { cb?.setData?.('text/plain', text); } catch (_) {}
        }
      } catch (_) {}
    }, true);
  } catch (_) {}

  /* ==================================================================
   *  5) MutationObserver — textarea / input dinamici
   * ================================================================== */

  try {
    const mo = new MutationObserver(records => {
      try {
        records.forEach(r => {
          (r.addedNodes || []).forEach(node => {
            if (!node || node.nodeType !== 1) return;
            const tag = node.tagName?.toLowerCase();
            if (tag === 'textarea' || (tag === 'input' && ['text', 'hidden'].includes(node.type))) {
              const v = node.value || node.getAttribute?.('value') || '';
              if (isSuspicious(v)) postDetection(v, 'hidden-textarea-created');
            }
          });
        });
      } catch (_) {}
    });
    mo.observe(document, { childList: true, subtree: true });
  } catch (_) {}

  /* ==================================================================
   *  6) createElement('textarea') — valore scritto via .value
   * ================================================================== */

  try {
    const origCreate = Document.prototype.createElement;
    Document.prototype.createElement = function (name) {
      const el = origCreate.apply(this, arguments);
      try {
        if (String(name).toLowerCase() === 'textarea') {
          const desc = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
          if (desc?.set) {
            Object.defineProperty(el, 'value', {
              set(v) {
                try { if (isSuspicious(v)) postDetection(v, 'textarea.value-set'); } catch (_) {}
                return desc.set.call(this, v);
              },
              get: desc.get,
              configurable: true,
              enumerable: true
            });
          }
        }
      } catch (_) {}
      return el;
    };
  } catch (_) {}

})();
