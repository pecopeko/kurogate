import { redact, restore, restoreVaultSession } from "./core/kurogate-engine.mjs";

const STORAGE_KEYS = {
  vault: "kurogate_vault_v1",
  dict: "kurogate_dict_v1",
  settings: "kurogate_settings_v1",
};

const DEFAULT_SETTINGS = {
  collapsed: false,
  pasteGuard: true,
};

const inputEl = document.getElementById("inputText");
const outputEl = document.getElementById("outputText");
const dictEl = document.getElementById("dictInput");
const statusEl = document.getElementById("statusBadge");
const vaultCountEl = document.getElementById("vaultCount");
const pasteGuardToggleEl = document.getElementById("pasteGuardToggle");

let currentVault = {};
let customDict = [];
let uiSettings = { ...DEFAULT_SETTINGS };

function parseDictText(raw) {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function setStatus(msg) {
  statusEl.textContent = msg;
}

function updateVaultDisplay() {
  vaultCountEl.textContent = String(Object.keys(currentVault).length);
}

async function loadState() {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.vault,
    STORAGE_KEYS.dict,
    STORAGE_KEYS.settings,
  ]);
  currentVault = stored[STORAGE_KEYS.vault] || {};
  customDict = Array.isArray(stored[STORAGE_KEYS.dict]) ? stored[STORAGE_KEYS.dict] : [];
  if (stored[STORAGE_KEYS.settings] && typeof stored[STORAGE_KEYS.settings] === "object") {
    uiSettings = { ...DEFAULT_SETTINGS, ...stored[STORAGE_KEYS.settings] };
  }
  dictEl.value = customDict.join("\n");
  if (pasteGuardToggleEl) {
    pasteGuardToggleEl.checked = Boolean(uiSettings.pasteGuard);
  }
  updateVaultDisplay();
}

async function saveVault(nextVault) {
  currentVault = { ...currentVault, ...nextVault };
  await chrome.storage.local.set({ [STORAGE_KEYS.vault]: currentVault });
  updateVaultDisplay();
}

document.getElementById("redactBtn").addEventListener("click", async () => {
  const session = restoreVaultSession(currentVault);
  const res = redact(inputEl.value, { customDictionary: customDict, vaultSession: session });
  outputEl.value = res.redactedText;
  await saveVault(res.vaultMap);
  const risk = res.injectionRiskScore > 0 ? ` · 注入警戒:${res.injectionRiskScore}` : "";
  setStatus(`黒塗り ${res.findings.length}件${risk}`);
});

document.getElementById("restoreBtn").addEventListener("click", () => {
  outputEl.value = restore(inputEl.value, currentVault);
  setStatus("Vaultから復元済");
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  if (!outputEl.value) return;
  await navigator.clipboard.writeText(outputEl.value);
  setStatus("コピー完了");
});

document.getElementById("saveDictBtn").addEventListener("click", async () => {
  customDict = parseDictText(dictEl.value);
  await chrome.storage.local.set({ [STORAGE_KEYS.dict]: customDict });
  setStatus(`辞書保存 (${customDict.length}語)`);
});

document.getElementById("clearVaultBtn").addEventListener("click", async () => {
  currentVault = {};
  await chrome.storage.local.set({ [STORAGE_KEYS.vault]: {} });
  updateVaultDisplay();
  setStatus("Vault消去済");
});

if (pasteGuardToggleEl) {
  pasteGuardToggleEl.addEventListener("change", async () => {
    uiSettings = { ...uiSettings, pasteGuard: pasteGuardToggleEl.checked };
    await chrome.storage.local.set({ [STORAGE_KEYS.settings]: uiSettings });
    setStatus(pasteGuardToggleEl.checked ? "ペースト時自動警告 ON" : "ペースト時自動警告 OFF");
  });
}

async function sendTabAction(action) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    setStatus("対象タブなし");
    return;
  }
  try {
    const response = await chrome.tabs.sendMessage(tab.id, { action });
    if (response?.ok) {
      if (response.vaultMap) await saveVault(response.vaultMap);
      setStatus(response.message || "実行完了");
    } else {
      setStatus(response?.message || "入力欄未検出");
    }
  } catch {
    setStatus("対象LLMページで実行してください");
  }
}

document.getElementById("redactPageBtn").addEventListener("click", () => sendTabAction("KUROGATE_REDACT_ACTIVE"));
document.getElementById("restorePageBtn").addEventListener("click", () => sendTabAction("KUROGATE_RESTORE_ACTIVE"));

loadState();
