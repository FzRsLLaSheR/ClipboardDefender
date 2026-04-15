// background.js — service worker
'use strict';

const LOG_KEY  = 'clip_detector_logs';
const MAX_LOGS = 200;

/* ==================================================================
 *  VIRUSTOTAL RATE LIMITER
 *  Free tier: 4 lookups/min · 500 lookups/day
 * ================================================================== */

const VT_API_BASE     = 'https://www.virustotal.com/api/v3';
const VT_MAX_PER_MIN  = 4;
const VT_MAX_PER_DAY  = 500;

const vtQueue = {
  lastMinute: [],
  today: { date: null, count: 0 },

  canCall() {
    const now      = Date.now();
    const todayStr = new Date().toISOString().slice(0, 10);
    if (this.today.date !== todayStr) { this.today.date = todayStr; this.today.count = 0; }
    this.lastMinute = this.lastMinute.filter(t => now - t < 60000);
    if (this.today.count >= VT_MAX_PER_DAY) return false;
    if (this.lastMinute.length >= VT_MAX_PER_MIN) return false;
    return true;
  },

  register() {
    this.lastMinute.push(Date.now());
    this.today.count++;
  },

  msUntilNext() {
    if (this.lastMinute.length < VT_MAX_PER_MIN) return 0;
    return Math.max(0, 60000 - (Date.now() - this.lastMinute[0]) + 100);
  },

  quotaInfo() {
    return {
      usedToday:    this.today.count,
      remaining:    VT_MAX_PER_DAY - this.today.count,
      callsLastMin: this.lastMinute.length
    };
  }
};

async function vtCallWithRateLimit(fn) {
  const todayStr = new Date().toISOString().slice(0, 10);
  if (vtQueue.today.date === todayStr && vtQueue.today.count >= VT_MAX_PER_DAY) {
    throw new Error('Daily quota exhausted (500/day)');
  }
  const wait = vtQueue.msUntilNext();
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  vtQueue.register();
  return fn();
}

/* ==================================================================
 *  EXTRACTION
 * ================================================================== */

function extractIndicators(text) {
  const indicators = [];

  // Domini con TLD comuni — con O SENZA https://
  // NOTA: 'txt' rimosso dalla lista perché causa falsi match su path tipo /ois.txt
  const domainRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|xyz|top|site|online|info|co|cc|pw|tk|ml|ga|cf|gq|gg|app|dev|cloud|store|shop|live|click|link|zip|mov|me|us|uk|de|fr|it|es|nl|pl|ro|ua|in|br)\b/gi;

  (text.match(domainRe) || []).forEach(d => {
    // Taglia path, query string e fragment dopo il TLD
    const clean = d.toLowerCase()
      .replace(/[\/\?\#].*$/, '')
      .replace(/\.$/, '')
      .trim();
    if (clean) indicators.push({ type: 'domain', value: clean });
  });

  // IP hex/ottali e decimali
  const ipRe = /\b(?:(?:0x[0-9a-f]{1,2}|\d{1,3})\.){3}(?:0x[0-9a-f]{1,2}|\d{1,3})\b/gi;
  (text.match(ipRe) || []).forEach(ip =>
    indicators.push({ type: 'ip', value: ip })
  );

  // Deduplication
  const seen = new Set();
  return indicators.filter(i => {
    const key = `${i.type}:${i.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeIp(ip) {
  return ip.split('.').map(part =>
    part.startsWith('0x') || part.startsWith('0X')
      ? parseInt(part, 16)
      : parseInt(part, 10)
  ).join('.');
}

async function vtLookupOne(apiKey, indicator) {
  const value = indicator.type === 'ip' ? normalizeIp(indicator.value) : indicator.value;

  // Domini e IP usano endpoint diretto — NO base64 (quello è solo per /urls/)
  const endpoint = indicator.type === 'ip'
    ? `${VT_API_BASE}/ip_addresses/${value}`
    : `${VT_API_BASE}/domains/${value}`;

  const res = await fetch(endpoint, { headers: { 'x-apikey': apiKey } });

  if (res.status === 404) {
    return { value: indicator.value, type: indicator.type, unknown: true };
  }
  if (res.status === 429) {
    throw new Error('VT rate limit hit (429)');
  }
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }

  const data  = await res.json();
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const votes = attrs.total_votes || {};

  return {
    value:           indicator.value,
    type:            indicator.type,
    malicious:       stats.malicious  ?? 0,
    suspicious:      stats.suspicious ?? 0,
    harmless:        stats.harmless   ?? 0,
    undetected:      stats.undetected ?? 0,
    total:           Object.values(stats).reduce((a, b) => a + b, 0),
    reputation:      attrs.reputation ?? null,
    votes_malicious: votes.malicious  ?? 0,
    votes_harmless:  votes.harmless   ?? 0,
    link: indicator.type === 'ip'
      ? `https://www.virustotal.com/gui/ip-address/${value}`
      : `https://www.virustotal.com/gui/domain/${value}`
  };
}

async function runVirusTotal(text) {
  try {
    const data   = await chrome.storage.local.get(['vtApiKey']);
    const apiKey = data.vtApiKey?.trim() || '';
    if (!apiKey) return { noKey: true };

    const indicators = extractIndicators(text);
    if (indicators.length === 0) return { noIndicators: true };

    const toCheck = indicators.slice(0, 3);
    const results = [];

    for (const indicator of toCheck) {
      try {
        const result = await vtCallWithRateLimit(() => vtLookupOne(apiKey, indicator));
        results.push(result);
      } catch (e) {
        results.push({ value: indicator.value, type: indicator.type, error: e.message });
        if (e.message.includes('quota') || e.message.includes('429')) break;
      }
    }

    return { results, quota: vtQueue.quotaInfo() };
  } catch (e) {
    console.error('[CD] VT error', e);
    return { error: e.message };
  }
}

/* ==================================================================
 *  LOGGING
 * ================================================================== */

async function pushLog(entry) {
  try {
    const data = await chrome.storage.local.get(LOG_KEY);
    const arr  = Array.isArray(data[LOG_KEY]) ? data[LOG_KEY] : [];
    arr.unshift(entry);
    await chrome.storage.local.set({ [LOG_KEY]: arr.slice(0, MAX_LOGS) });
  } catch (e) {
    console.error('[CD] pushLog error', e);
  }
}

function buildEntry(payload, action, sender) {
  return {
    ts:     payload.ts     || Date.now(),
    action: action         || 'detected',
    reason: payload.reason || payload.error || 'unknown',
    text:   payload.text   || '',
    url:    sender.tab?.url || 'unknown',
    tabId:  sender.tab?.id  ?? null
  };
}

/* ==================================================================
 *  MESSAGE HANDLER
 * ================================================================== */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;

  // ── vt_lookup ────────────────────────────────────────────────────
  if (msg.type === 'vt_lookup') {
    runVirusTotal(msg.text || '').then(data => {
      sendResponse({ ok: true, ...data });
    });
    return true;
  }

  // ── clip_detected (legacy) ───────────────────────────────────────
  if (msg.type === 'clip_detected') {
    const entry = buildEntry(msg.payload || {}, 'detected', sender);
    console.warn('[CD BG] Detected:', entry);
    pushLog(entry);
    sendResponse({ ok: true });
    return true;
  }

  // ── clip_action (ignore / clean / clean_failed) ──────────────────
  if (msg.type === 'clip_action') {
    const entry = buildEntry(msg, msg.action || 'action', sender);
    console.info('[CD BG] Action:', entry);
    pushLog(entry);
    sendResponse({ ok: true });
    return true;
  }
});