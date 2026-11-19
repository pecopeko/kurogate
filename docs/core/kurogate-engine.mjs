/**
 * KUROGATE (黒門) — Zero-Dependency Browser-Local PII Redaction & Vault Engine.
 *
 * Pure ES module shared identically across the Web UI, Manifest V3 Chrome Extension,
 * and Node.js automated test suite. Performs zero network I/O.
 */

export const ENTITY_LABELS = Object.freeze({
  API_KEY: "APIキー (AWS / OpenAI / Anthropic)",
  SECRET_TOKEN: "認証トークン (GitHub / Slack / JWT)",
  INVOICE_ID: "適格請求書登録番号 (NTA Mod-9)",
  CORPORATE_ID: "法人番号 (NTA Mod-9)",
  MYNUMBER: "マイナンバー (MIC Mod-11)",
  CREDIT_CARD: "クレジットカード番号 (Luhn)",
  JP_BANK_ACCOUNT: "銀行口座番号 (普通/当座)",
  EMAIL: "メールアドレス",
  CUSTOM_TERM: "社内辞書 (固有名詞・案件名)",
  JP_PHONE: "電話番号",
  JP_POSTAL: "郵便番号",
});

// Strictly 1-to-1 character translation table (1 UTF-16 code unit -> 1 UTF-16 code unit)
// so match indices in scanText map back to the raw string with zero span drift.
const SCAN_CHAR_MAP = Object.freeze({
  "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
  "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
  "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
  "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
  "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
  "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
  "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y",
  "Ｚ": "Z",
  "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
  "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
  "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
  "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
  "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y",
  "ｚ": "z",
  "－": "-", "−": "-", "‐": "-", "‒": "-", "–": "-", "—": "-", "―": "-",
  "＠": "@", "．": ".", "＿": "_", "＋": "+", "（": "(", "）": ")",
  "：": ":", "\u3000": " ",
});

const SCAN_REPLACE_RE = /[０-９Ａ-Ｚａ-ｚ－−‐‒–—―＠．＿＋（）：\u3000]/g;

const ZERO_WIDTH_RE = /[\u200b\u200c\u200d\ufeff\u2060]/g;
const BIDI_OVERRIDE_RE = /[\u202a-\u202e\u2066-\u2069]/g;
const DASH_BETWEEN_DIGITS_RE = /(?<=\d)[\u2212\u2010\u2011\u2012\u2013\u2014\u2015](?=\d)/g;

const AWS_ACCESS_KEY_RE = /(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])/g;
const PROVIDER_API_KEY_RE =
  /(?<![A-Za-z0-9_-])sk-(?:(?:proj|ant|live|test|svcacct|admin)-[A-Za-z0-9_-]{16,}|[A-Za-z0-9]{20,})(?![A-Za-z0-9_-])/g;
const GITHUB_PAT_RE =
  /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9]{10,}_[A-Za-z0-9]{20,})(?![A-Za-z0-9_])/g;
const SLACK_TOKEN_RE = /(?<![A-Za-z0-9_-])xox[bp]-[A-Za-z0-9-]{16,}(?![A-Za-z0-9_-])/g;
const JWT_RE = /(?<![A-Za-z0-9_.-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_.-])/g;

const INVOICE_RE = /(?<![A-Za-z0-9])[Tt][ \t]*-?[ \t]*(\d(?:[ \t-]?\d){12})(?![A-Za-z0-9]|[ \t-]\d)/g;
const CORP_RE = /(?<!\d[ \t-])(?<![A-Za-z0-9])(\d(?:[ \t-]?\d){12})(?![A-Za-z0-9]|[ \t-]\d)/g;
const MYNUMBER_RE = /(?<!\d[ \t-])(?<![A-Za-z0-9])(\d{4}[ \t-]?\d{4}[ \t-]?\d{4})(?![A-Za-z0-9]|[ \t-]\d)/g;
const CARD_RE = /(?<!\d[ \t-])(?<![A-Za-z0-9])((?:\d[ \t-]?){13,18}\d)(?![A-Za-z0-9]|[ \t-]\d)/g;
const BANK_ACCOUNT_RE = /(?:普通|当座|貯蓄|定期)(?:預金|口座)?(?:[ \t]*(?:No\.?|番号))?[ \t]*:?[ \t]*\d{7}(?!\d)/g;
const EMAIL_RE = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9])/g;
const JP_PHONE_RE = /(?<![0-9-])((?:\+81[ \t-]?|\(?0)(?:\d[ \t()-]{0,2}){8,10}\d)(?![0-9-])/g;
const JP_POSTAL_RE = /(?:〒[ \t]*|(?<![0-9A-Za-z-]))(\d{3}-\d{4})(?![0-9-])|〒[ \t]*(\d{7})(?![0-9])/g;

const INJECTION_RULES = [
  {
    id: "en_override_instructions",
    regex: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)\b/i,
    weight: 0.55,
  },
  {
    id: "en_system_prompt_exfil",
    regex: /\b(?:reveal|print|output|leak|show)\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|developer\s+message)\b/i,
    weight: 0.55,
  },
  {
    id: "en_jailbreak_persona",
    regex: /\b(?:jailbreak|do\s+anything\s+now|developer\s+mode\s+enabled|you\s+are\s+now\s+unrestricted)\b/i,
    weight: 0.45,
  },
  {
    id: "ja_override_instructions",
    regex: /(?:以前|これまで|上記)の(?:指示|命令|ルール)を(?:すべて|全て)?(?:無視|忘れ|破棄)/,
    weight: 0.60,
  },
  {
    id: "ja_system_prompt_exfil",
    regex: /(?:システムプロンプト|内部指示|開発者プロンプト)を(?:開示|表示|出力|教え)/,
    weight: 0.60,
  },
  {
    id: "ja_jailbreak_mode",
    regex: /(?:制限|制約|ガードレール)を(?:すべて|全て)?解除|(?:開発者|管理者)モードを有効/,
    weight: 0.45,
  },
  {
    id: "role_delimiter_spoof",
    regex: /(?:<\|im_start\|>|<\|system\|>|\[INST\]|^[ \t]*###[ \t]*System:|^[ \t]*System:[ \t]*)/im,
    weight: 0.50,
  },
  {
    id: "suspicious_base64_blob",
    regex: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])/,
    weight: 0.25,
  },
];

/**
 * 1-to-1 width normalization for scanning so character spans map identically
 * back to the original input string without UTF-16 index drift.
 * @param {string} text
 * @returns {string}
 */
export function toScanText(text) {
  return String(text ?? "").replace(SCAN_REPLACE_RE, (ch) => SCAN_CHAR_MAP[ch] ?? ch);
}

/**
 * Compute NTA modulo-9 check digit (1..9) from 12 corporate body digits.
 * @param {string} digits12
 * @returns {number}
 */
export function computeCorporateCheckDigit(digits12) {
  const cleaned = toScanText(digits12).replace(/[\s-]/g, "");
  if (!/^\d{12}$/.test(cleaned)) {
    throw new RangeError("Corporate body must be exactly 12 digits.");
  }
  let weightedSum = 0;
  for (let n = 1; n <= 12; n += 1) {
    const pn = Number(cleaned[12 - n]);
    const qn = n % 2 === 1 ? 1 : 2;
    weightedSum += pn * qn;
  }
  return 9 - (weightedSum % 9);
}

/**
 * Validate 13-digit Japanese Corporate Number or Qualified Invoice ID (T + 13 digits)
 * using the National Tax Agency (国税庁) modulo-9 formula.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidCorporateNumber(raw) {
  let cleaned = toScanText(raw).replace(/[\s-]/g, "");
  if (cleaned.startsWith("T") || cleaned.startsWith("t")) {
    cleaned = cleaned.slice(1);
  }
  if (!/^\d{13}$/.test(cleaned)) return false;

  const checkDigit = Number(cleaned[0]);
  if (checkDigit < 1 || checkDigit > 9) return false;
  return checkDigit === computeCorporateCheckDigit(cleaned.slice(1));
}

/**
 * Compute MIC modulo-11 check digit (0..9) from 11 MyNumber body digits.
 * @param {string} digits11
 * @returns {number}
 */
export function computeMyNumberCheckDigit(digits11) {
  const cleaned = toScanText(digits11).replace(/[\s-]/g, "");
  if (!/^\d{11}$/.test(cleaned)) {
    throw new RangeError("MyNumber body must be exactly 11 digits.");
  }
  let weightedSum = 0;
  for (let n = 1; n <= 11; n += 1) {
    const pn = Number(cleaned[11 - n]);
    const qn = n <= 6 ? n + 1 : n - 5;
    weightedSum += pn * qn;
  }
  const rem = weightedSum % 11;
  return rem <= 1 ? 0 : 11 - rem;
}

/**
 * Validate 12-digit Japanese Individual Number (マイナンバー) using the
 * Ministry of Internal Affairs and Communications (総務省) modulo-11 formula.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidMyNumber(raw) {
  const cleaned = toScanText(raw).replace(/[\s-]/g, "");
  if (!/^\d{12}$/.test(cleaned)) return false;
  const checkDigit = Number(cleaned[11]);
  return checkDigit === computeMyNumberCheckDigit(cleaned.slice(0, 11));
}

/**
 * Validate payment card digit sequence with standard Luhn check.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidLuhn(raw) {
  const cleaned = toScanText(raw).replace(/[\s-]/g, "");
  if (cleaned.length < 13 || cleaned.length > 19 || !/^\d+$/.test(cleaned)) {
    return false;
  }
  if (new Set(cleaned).size === 1) return false;

  let total = 0;
  for (let idx = 0; idx < cleaned.length; idx += 1) {
    let val = Number(cleaned[cleaned.length - 1 - idx]);
    if (idx % 2 === 1) {
      val *= 2;
      if (val > 9) val -= 9;
    }
    total += val;
  }
  return total % 10 === 0;
}

/**
 * Normalize Japanese business text / CSV fields cleanly while preserving
 * full-width katakana (NFKC) and converting full-width tilde U+FF5E to U+301C.
 * @param {string} text
 * @returns {string}
 */
export function normalizeJpBusinessText(text) {
  let cleaned = String(text ?? "");
  cleaned = cleaned.replace(ZERO_WIDTH_RE, "");
  cleaned = cleaned.replace(BIDI_OVERRIDE_RE, "");
  cleaned = cleaned.replace(/\uff5e/g, "\u301c");
  cleaned = cleaned.replace(DASH_BETWEEN_DIGITS_RE, "-");
  let normalized = cleaned.normalize("NFKC");
  normalized = normalized.replace(/[ \t]+/g, " ");
  normalized = normalized.replace(/ *\n */g, "\n");
  return normalized.trim();
}

/**
 * Score multilingual prompt-injection indicators in [0.0, 1.0].
 * @param {string} text
 * @returns {{ score: number, flags: string[] }}
 */
export function assessInjectionRisk(text) {
  const raw = String(text ?? "");
  const flags = [];
  let score = 0;

  for (const rule of INJECTION_RULES) {
    if (rule.regex.test(raw)) {
      flags.push(rule.id);
      score += rule.weight;
    }
  }

  ZERO_WIDTH_RE.lastIndex = 0;
  BIDI_OVERRIDE_RE.lastIndex = 0;
  if (ZERO_WIDTH_RE.test(raw) || BIDI_OVERRIDE_RE.test(raw)) {
    flags.push("hidden_unicode_controls");
    score += 0.30;
  }
  ZERO_WIDTH_RE.lastIndex = 0;
  BIDI_OVERRIDE_RE.lastIndex = 0;

  return {
    score: Math.round(Math.min(score, 1.0) * 10000) / 10000,
    flags,
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeCustomEntries(customDictionary) {
  if (!Array.isArray(customDictionary) || customDictionary.length === 0) return [];
  const deduped = new Map();
  for (const entry of customDictionary) {
    const rawTerm = typeof entry === "string" ? entry : entry?.term;
    const trimmed = String(rawTerm ?? "").trim();
    if (!trimmed) continue;
    const scanTerm = toScanText(trimmed);
    if (!deduped.has(scanTerm)) {
      deduped.set(scanTerm, {
        scanTerm,
        caseSensitive: typeof entry === "object" && entry !== null ? Boolean(entry.caseSensitive) : false,
      });
    }
  }
  return [...deduped.values()].sort((a, b) => b.scanTerm.length - a.scanTerm.length);
}

function collectCandidates(scanText, options = {}) {
  const enabled = options.enabledKinds ? new Set(options.enabledKinds) : null;
  const isEnabled = (kind) => !enabled || enabled.has(kind);
  const rawHits = [];

  if (isEnabled("API_KEY")) {
    for (const re of [AWS_ACCESS_KEY_RE, PROVIDER_API_KEY_RE]) {
      for (const m of scanText.matchAll(re)) {
        rawHits.push({ priority: 1, start: m.index, end: m.index + m[0].length, kind: "API_KEY", verified: false });
      }
    }
  }

  if (isEnabled("SECRET_TOKEN")) {
    for (const re of [GITHUB_PAT_RE, SLACK_TOKEN_RE, JWT_RE]) {
      for (const m of scanText.matchAll(re)) {
        rawHits.push({ priority: 2, start: m.index, end: m.index + m[0].length, kind: "SECRET_TOKEN", verified: false });
      }
    }
  }

  if (isEnabled("INVOICE_ID")) {
    for (const m of scanText.matchAll(INVOICE_RE)) {
      const digits = m[1].replace(/[ \t-]/g, "");
      if (isValidCorporateNumber(digits)) {
        rawHits.push({ priority: 3, start: m.index, end: m.index + m[0].length, kind: "INVOICE_ID", verified: true });
      }
    }
  }

  if (isEnabled("CORPORATE_ID")) {
    for (const m of scanText.matchAll(CORP_RE)) {
      const digits = m[1].replace(/[ \t-]/g, "");
      if (isValidCorporateNumber(digits)) {
        rawHits.push({ priority: 4, start: m.index, end: m.index + m[0].length, kind: "CORPORATE_ID", verified: true });
      }
    }
  }

  if (isEnabled("MYNUMBER")) {
    for (const m of scanText.matchAll(MYNUMBER_RE)) {
      const digits = m[1].replace(/[ \t-]/g, "");
      if (isValidMyNumber(digits)) {
        rawHits.push({ priority: 5, start: m.index, end: m.index + m[0].length, kind: "MYNUMBER", verified: true });
      }
    }
  }

  if (isEnabled("CREDIT_CARD")) {
    for (const m of scanText.matchAll(CARD_RE)) {
      const digits = m[1].replace(/[ \t-]/g, "");
      if (digits.length >= 14 && isValidLuhn(digits)) {
        rawHits.push({ priority: 6, start: m.index, end: m.index + m[0].length, kind: "CREDIT_CARD", verified: true });
      }
    }
  }

  if (isEnabled("JP_BANK_ACCOUNT")) {
    for (const m of scanText.matchAll(BANK_ACCOUNT_RE)) {
      rawHits.push({ priority: 7, start: m.index, end: m.index + m[0].length, kind: "JP_BANK_ACCOUNT", verified: false });
    }
  }

  if (isEnabled("EMAIL")) {
    for (const m of scanText.matchAll(EMAIL_RE)) {
      const offset = m[0].indexOf(m[1]);
      const start = m.index + offset;
      rawHits.push({ priority: 8, start, end: start + m[1].length, kind: "EMAIL", verified: false });
    }
  }

  if (isEnabled("CUSTOM_TERM")) {
    const entries = normalizeCustomEntries(options.customDictionary);
    for (const entry of entries) {
      const startsAscii = /^[A-Za-z0-9]/.test(entry.scanTerm);
      const endsAscii = /[A-Za-z0-9]$/.test(entry.scanTerm);
      const pattern = `${startsAscii ? "(?<![A-Za-z0-9])" : ""}${escapeRegex(entry.scanTerm)}${endsAscii ? "(?![A-Za-z0-9])" : ""}`;
      const flags = entry.caseSensitive ? "g" : "gi";
      const re = new RegExp(pattern, flags);
      for (const m of scanText.matchAll(re)) {
        rawHits.push({ priority: 9, start: m.index, end: m.index + m[0].length, kind: "CUSTOM_TERM", verified: false });
      }
    }
  }

  if (isEnabled("JP_PHONE")) {
    for (const m of scanText.matchAll(JP_PHONE_RE)) {
      const digits = m[1].replace(/[^0-9]/g, "");
      const isIntlJp = digits.startsWith("81") && (digits.length === 11 || digits.length === 12);
      const isDomesticJp = digits.startsWith("0") && (digits.length === 10 || digits.length === 11);
      if (isIntlJp || isDomesticJp) {
        const offset = m[0].indexOf(m[1]);
        const start = m.index + offset;
        rawHits.push({ priority: 10, start, end: start + m[1].length, kind: "JP_PHONE", verified: false });
      }
    }
  }

  if (isEnabled("JP_POSTAL")) {
    for (const m of scanText.matchAll(JP_POSTAL_RE)) {
      const captured = m[1] || m[2];
      const offset = m[0].indexOf(captured);
      const start = m.index + offset;
      rawHits.push({ priority: 11, start, end: start + captured.length, kind: "JP_POSTAL", verified: false });
    }
  }

  rawHits.sort((a, b) => a.priority - b.priority || (b.end - b.start) - (a.end - a.start) || a.start - b.start);

  const accepted = [];
  for (const hit of rawHits) {
    const overlaps = accepted.some((acc) => !(hit.end <= acc.start || hit.start >= acc.end));
    if (!overlaps) accepted.push(hit);
  }
  accepted.sort((a, b) => a.start - b.start);
  return accepted;
}

/**
 * Create a reusable session vault so multi-row CSV/TSV or multi-turn prompts
 * assign identical tokens to identical sensitive strings.
 */
export function createVaultSession() {
  return {
    counters: Object.create(null),
    rawToPlaceholder: new Map(),
    vaultMap: Object.create(null),
  };
}

const PLACEHOLDER_TOKEN_RE = /^\[([A-Z0-9_]+)_(\d+)\]$/;

/**
 * Rebuild a reusable Vault session from a persisted placeholder->raw map so
 * repeated redactions never re-issue existing placeholder indices or overwrite
 * previous entries, and re-occurring raw values reuse the same placeholder.
 * @param {Record<string, string>} [existingVaultMap]
 * @returns {{ counters: Record<string, number>, rawToPlaceholder: Map<string, string>, vaultMap: Record<string, string> }}
 */
export function restoreVaultSession(existingVaultMap) {
  const session = createVaultSession();
  if (!existingVaultMap || typeof existingVaultMap !== "object") {
    return session;
  }

  const parsedEntries = [];
  for (const [placeholder, original] of Object.entries(existingVaultMap)) {
    if (typeof placeholder !== "string" || !placeholder || typeof original !== "string") {
      continue;
    }
    session.vaultMap[placeholder] = original;
    const match = PLACEHOLDER_TOKEN_RE.exec(placeholder);
    if (match) {
      parsedEntries.push({
        placeholder,
        original,
        kind: match[1],
        index: Number.parseInt(match[2], 10),
      });
    }
  }

  parsedEntries.sort((a, b) => a.index - b.index || a.placeholder.localeCompare(b.placeholder));

  for (const entry of parsedEntries) {
    if (Number.isFinite(entry.index) && entry.index > (session.counters[entry.kind] || 0)) {
      session.counters[entry.kind] = entry.index;
    }
    const cacheKey = `${entry.kind}::${entry.original}`;
    if (!session.rawToPlaceholder.has(cacheKey)) {
      session.rawToPlaceholder.set(cacheKey, entry.placeholder);
    }
  }

  return session;
}

/**
 * Redact verified Japanese PII, bank accounts, custom enterprise terms,
 * and screen for prompt-injection vectors locally in-browser.
 * @param {string} text
 * @param {object} [options]
 * @returns {object}
 */
export function redact(text, options = {}) {
  const input = String(text ?? "");
  const working = options.normalize ? normalizeJpBusinessText(input) : input;
  const scanText = toScanText(working);
  const spans = collectCandidates(scanText, options);

  const session = options.vaultSession || createVaultSession();
  const findings = [];
  const byKind = Object.create(null);
  const chunks = [];
  let cursor = 0;

  for (const span of spans) {
    const rawValue = working.slice(span.start, span.end);
    const cacheKey = `${span.kind}::${rawValue}`;
    let placeholder = session.rawToPlaceholder.get(cacheKey);
    if (!placeholder) {
      session.counters[span.kind] = (session.counters[span.kind] || 0) + 1;
      placeholder = `[${span.kind}_${session.counters[span.kind]}]`;
      session.rawToPlaceholder.set(cacheKey, placeholder);
      session.vaultMap[placeholder] = rawValue;
    }

    chunks.push(working.slice(cursor, span.start), placeholder);
    cursor = span.end;

    byKind[span.kind] = (byKind[span.kind] || 0) + 1;
    findings.push({
      kind: span.kind,
      label: ENTITY_LABELS[span.kind] || span.kind,
      placeholder,
      start: span.start,
      end: span.end,
      charLength: rawValue.length,
      verifiedCheckDigit: span.verified,
    });
  }

  chunks.push(working.slice(cursor));
  const redactedText = chunks.join("");
  const { score: injectionRiskScore, flags: injectionFlags } = assessInjectionRisk(working);

  return {
    redactedText,
    vaultMap: { ...session.vaultMap },
    findings,
    injectionRiskScore,
    injectionFlags,
    stats: {
      totalFindings: findings.length,
      verifiedCheckDigitCount: findings.filter((f) => f.verifiedCheckDigit).length,
      customDictCount: byKind.CUSTOM_TERM || 0,
      byKind,
    },
  };
}

/**
 * Restore placeholders in LLM output back to original sensitive strings.
 * @param {string} text
 * @param {Record<string, string>} vaultMap
 * @returns {string}
 */
export function restore(text, vaultMap) {
  const input = String(text ?? "");
  if (!vaultMap || typeof vaultMap !== "object") return input;
  const keys = Object.keys(vaultMap).filter((k) => k.length > 0).sort((a, b) => b.length - a.length);
  if (keys.length === 0) return input;
  const pattern = new RegExp(keys.map(escapeRegex).join("|"), "g");
  return input.replace(pattern, (match) => vaultMap[match] ?? match);
}

/**
 * Detect whether CSV (comma) or TSV (tab) delimiter dominates the sample.
 * @param {string} text
 * @returns {"," | "\t"}
 */
export function detectDelimiter(text) {
  const firstLine = String(text ?? "").split(/\r?\n/, 1)[0] || "";
  const tabs = (firstLine.match(/\t/g) || []).length;
  const commas = (firstLine.match(/,/g) || []).length;
  return tabs > commas ? "\t" : ",";
}

/**
 * Parse RFC-4180 CSV or TSV text into a 2D array of strings.
 * @param {string} text
 * @param {"," | "\t" | "auto"} [delimiter="auto"]
 * @returns {{ rows: string[][], delimiter: "," | "\t" }}
 */
export function parseDelimited(text, delimiter = "auto") {
  const source = String(text ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const sep = delimiter === "auto" ? detectDelimiter(source) : delimiter;
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (inQuotes) {
      if (ch === "\"") {
        if (source[i + 1] === "\"") {
          field += "\"";
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === "\"" && field.length === 0) {
      inQuotes = true;
    } else if (ch === sep) {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return { rows, delimiter: sep };
}

/**
 * Serialize a 2D string array back into RFC-4180 CSV or TSV text.
 * @param {string[][]} rows
 * @param {"," | "\t"} [delimiter=","]
 * @returns {string}
 */
export function serializeDelimited(rows, delimiter = ",") {
  return rows
    .map((row) =>
      row
        .map((cell) => {
          const val = String(cell ?? "");
          if (val.includes("\"") || val.includes(delimiter) || val.includes("\n")) {
            return `"${val.replace(/"/g, "\"\"")}"`;
          }
          return val;
        })
        .join(delimiter)
    )
    .join("\n");
}

/**
 * Redact CSV/TSV rows and selected columns with a shared token vault.
 * @param {string} text
 * @param {object} [options]
 * @returns {object}
 */
export function redactDelimited(text, options = {}) {
  const { rows, delimiter } = parseDelimited(text, options.delimiter || "auto");
  if (rows.length === 0) {
    return {
      redactedText: "",
      vaultMap: {},
      findings: [],
      injectionRiskScore: 0,
      injectionFlags: [],
      delimiter,
      headers: [],
      rowsProcessed: 0,
      cellsRedacted: 0,
      stats: { totalFindings: 0, verifiedCheckDigitCount: 0, customDictCount: 0, byKind: {} },
    };
  }

  const hasHeader = options.hasHeader !== false;
  const headers = hasHeader ? rows[0] : rows[0].map((_, idx) => `Column ${idx + 1}`);
  const startRow = hasHeader ? 1 : 0;

  let targetColSet = null;
  if (Array.isArray(options.targetColumns) && options.targetColumns.length > 0) {
    targetColSet = new Set();
    for (const spec of options.targetColumns) {
      if (typeof spec === "number" && Number.isInteger(spec) && spec >= 0) {
        targetColSet.add(spec);
      } else {
        const idx = headers.indexOf(String(spec));
        if (idx !== -1) targetColSet.add(idx);
      }
    }
  }

  const vaultSession = options.vaultSession || createVaultSession();
  const outRows = rows.map((r) => [...r]);
  const allFindings = [];
  const allInjectionFlags = new Set();
  const byKind = Object.create(null);
  let maxRisk = 0;
  let cellsRedacted = 0;

  for (let r = startRow; r < outRows.length; r += 1) {
    for (let c = 0; c < outRows[r].length; c += 1) {
      if (targetColSet && !targetColSet.has(c)) continue;
      const cellRes = redact(outRows[r][c], { ...options, vaultSession });
      outRows[r][c] = cellRes.redactedText;
      if (cellRes.findings.length > 0) {
        cellsRedacted += 1;
        for (const f of cellRes.findings) {
          byKind[f.kind] = (byKind[f.kind] || 0) + 1;
          allFindings.push({ ...f, row: r + 1, column: headers[c] || `col_${c + 1}` });
        }
      }
      if (cellRes.injectionRiskScore > maxRisk) maxRisk = cellRes.injectionRiskScore;
      for (const fl of cellRes.injectionFlags) allInjectionFlags.add(fl);
    }
  }

  return {
    redactedText: serializeDelimited(outRows, delimiter),
    vaultMap: { ...vaultSession.vaultMap },
    findings: allFindings,
    injectionRiskScore: maxRisk,
    injectionFlags: [...allInjectionFlags],
    delimiter,
    headers,
    rowsProcessed: Math.max(0, outRows.length - startRow),
    cellsRedacted,
    stats: {
      totalFindings: allFindings.length,
      verifiedCheckDigitCount: allFindings.filter((f) => f.verifiedCheckDigit).length,
      customDictCount: byKind.CUSTOM_TERM || 0,
      byKind,
    },
  };
}

/**
 * Restore redacted CSV/TSV content using the local token vault.
 * @param {string} text
 * @param {Record<string, string>} vaultMap
 * @param {"," | "\t" | "auto"} [delimiter="auto"]
 * @returns {string}
 */
export function restoreDelimited(text, vaultMap, delimiter = "auto") {
  const { rows, delimiter: sep } = parseDelimited(text, delimiter);
  const restoredRows = rows.map((row) => row.map((cell) => restore(cell, vaultMap)));
  return serializeDelimited(restoredRows, sep);
}

/**
 * Build ISMS (JIS Q 27001) / PrivacyMark (JIS Q 15001) compliance audit exports
 * in JSON and Markdown without ever exposing raw unmasked PII values.
 * @param {object} result
 * @param {object} [meta]
 * @returns {{ summary: object, jsonString: string, markdownString: string }}
 */
export function buildAuditReport(result, meta = {}) {
  const timestamp = meta.timestamp || new Date().toISOString();
  const mode = meta.mode || "text";
  const sourceLabel = meta.sourceLabel || "browser-local-workbench";
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const byKind = result?.stats?.byKind || {};

  const summary = {
    schema: "kurogate.audit.v1",
    standards: ["ISMS / JIS Q 27001", "PrivacyMark / JIS Q 15001", "APPI (改正個人情報保護法)"],
    executedAt: timestamp,
    executionEnvironment: "100% browser-local (0 external network calls)",
    externalNetworkCalls: 0,
    mode,
    sourceLabel,
    metrics: {
      totalMaskedEntities: findings.length,
      uniqueVaultTokens: Object.keys(result?.vaultMap || {}).length,
      verifiedCheckDigitEntities: findings.filter((f) => f.verifiedCheckDigit).length,
      customDictionaryMatches: byKind.CUSTOM_TERM || 0,
      injectionRiskScore: result?.injectionRiskScore ?? 0,
      injectionFlags: result?.injectionFlags || [],
    },
    countsByKind: byKind,
    // Strictly omit plaintext PII values from compliance audit logs.
    maskedRecords: findings.map((f) => ({
      placeholder: f.placeholder,
      kind: f.kind,
      label: f.label || ENTITY_LABELS[f.kind] || f.kind,
      verifiedCheckDigit: Boolean(f.verifiedCheckDigit),
      charLength: f.charLength ?? (f.end - f.start),
      span: [f.start, f.end],
      ...(f.row !== undefined ? { row: f.row, column: f.column } : {}),
    })),
  };

  const lines = [
    "# KUROGATE（黒門）ISMS / Pマーク 監査証跡レポート",
    "",
    `- 実行日時: \`${summary.executedAt}\``,
    `- 準拠規格: ${summary.standards.join(" / ")}`,
    `- 実行環境: ${summary.executionEnvironment}`,
    `- 外部通信回数: **${summary.externalNetworkCalls}回**`,
    `- 処理モード: ${mode} (${sourceLabel})`,
    "",
    "## サマリ統計",
    "",
    "| 項目 | 値 |",
    "| --- | ---: |",
    `| マスキング検出総数 | ${summary.metrics.totalMaskedEntities} |`,
    `| 発行トークン数 (Vault) | ${summary.metrics.uniqueVaultTokens} |`,
    `| チェックディジット検証済 | ${summary.metrics.verifiedCheckDigitEntities} |`,
    `| 社内固有名詞辞書一致 | ${summary.metrics.customDictionaryMatches} |`,
    `| プロンプトインジェクション危険度 | ${summary.metrics.injectionRiskScore} |`,
    "",
    "## 検出トークン明細（平文PII非記録）",
    "",
    "| トークン | 種別 | 検算 | 文字数 | スパン |",
    "| --- | --- | :---: | ---: | --- |",
  ];

  if (summary.maskedRecords.length === 0) {
    lines.push("| （検出なし） | - | - | 0 | - |");
  } else {
    for (const rec of summary.maskedRecords) {
      const loc = rec.row !== undefined ? `R${rec.row} ${rec.column} [${rec.span[0]}..${rec.span[1]}]` : `[${rec.span[0]}..${rec.span[1]}]`;
      lines.push(`| \`${rec.placeholder}\` | ${rec.label} | ${rec.verifiedCheckDigit ? "済" : "-"} | ${rec.charLength} | ${loc} |`);
    }
  }

  if (summary.metrics.injectionFlags.length > 0) {
    lines.push("", "## プロンプトインジェクション検知フラグ", "");
    for (const fl of summary.metrics.injectionFlags) {
      lines.push(`- \`${fl}\``);
    }
  }

  return {
    summary,
    jsonString: JSON.stringify(summary, null, 2),
    markdownString: lines.join("\n"),
  };
}
