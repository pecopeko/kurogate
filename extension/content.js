(() => {
  if (window.__kurogateMounted) return;
  window.__kurogateMounted = true;

  const STORAGE_KEYS = {
    vault: "kurogate_vault_v1",
    dict: "kurogate_dict_v1",
    settings: "kurogate_settings_v1",
  };

  const DEFAULT_SETTINGS = {
    collapsed: false,
    pasteGuard: true,
  };

  let enginePromise = null;
  let lastPromptTarget = null;
  let uiSettings = { ...DEFAULT_SETTINGS };
  let uiRefs = null;
  const highlightedTargets = new WeakMap();

  function getEngine() {
    if (!enginePromise) {
      enginePromise = import(chrome.runtime.getURL("core/kurogate-engine.mjs"));
    }
    return enginePromise;
  }

  function isPromptEditable(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.closest && el.closest("#kurogate-floating-gate")) return false;
    if (el.disabled || el.readOnly) return false;
    if (el.tagName === "TEXTAREA") return true;
    if (el.tagName === "INPUT") {
      const type = String(el.type || "text").toLowerCase();
      return type === "text" || type === "search" || type === "url" || type === "email";
    }
    return Boolean(el.isContentEditable);
  }

  document.addEventListener(
    "focusin",
    (event) => {
      if (isPromptEditable(event.target)) {
        lastPromptTarget = event.target;
      }
    },
    true
  );

  function findPromptTarget() {
    const active = document.activeElement;
    if (isPromptEditable(active)) {
      lastPromptTarget = active;
      return active;
    }
    if (lastPromptTarget && lastPromptTarget.isConnected && isPromptEditable(lastPromptTarget)) {
      return lastPromptTarget;
    }
    const selectors = [
      "#prompt-textarea",
      "#ask-input",
      "textarea#userInput",
      'textarea[data-testid="composer-input"]',
      "textarea.query-box-input",
      "textarea[data-id]",
      'div.ProseMirror[contenteditable="true"]',
      'rich-textarea div.ql-editor[contenteditable="true"]',
      'rich-textarea div[contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"]',
      "textarea",
    ];
    for (const sel of selectors) {
      const candidates = document.querySelectorAll(sel);
      for (const el of candidates) {
        if (isPromptEditable(el)) return el;
      }
    }
    return null;
  }

  function readTargetText(el) {
    if (!el) return "";
    return el.tagName === "TEXTAREA" || el.tagName === "INPUT"
      ? String(el.value ?? "")
      : String(el.innerText ?? el.textContent ?? "");
  }

  function normalizeCompare(str) {
    return String(str ?? "").replace(/\s+/g, " ").trim();
  }

  function setEditableText(el, nextText) {
    if (!el) return;
    const textValue = String(nextText ?? "");

    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      const proto =
        el.tagName === "TEXTAREA"
          ? window.HTMLTextAreaElement?.prototype
          : window.HTMLInputElement?.prototype;
      const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, "value") : null;
      if (descriptor && typeof descriptor.set === "function") {
        descriptor.set.call(el, textValue);
      } else {
        el.value = textValue;
      }
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }

    el.focus();
    let inserted = false;
    try {
      const selection = window.getSelection();
      if (selection && typeof document.createRange === "function") {
        const range = document.createRange();
        range.selectNodeContents(el);
        selection.removeAllRanges();
        selection.addRange(range);
        if (typeof document.execCommand === "function") {
          const ok = document.execCommand("insertText", false, textValue);
          if (ok) {
            const actual = normalizeCompare(el.innerText ?? el.textContent ?? "");
            const expected = normalizeCompare(textValue);
            inserted = actual === expected;
          }
        }
      }
    } catch {
      inserted = false;
    }

    if (!inserted) {
      el.textContent = textValue;
      const ev =
        typeof InputEvent === "function"
          ? new InputEvent("input", {
              bubbles: true,
              cancelable: true,
              inputType: "insertText",
              data: textValue,
            })
          : new Event("input", { bubbles: true });
      el.dispatchEvent(ev);
    }
  }

  function clearPasteWarningStyle(el) {
    if (!el) return;
    const saved = highlightedTargets.get(el);
    if (!saved) return;
    clearTimeout(saved.timer);
    el.style.outline = saved.outline;
    el.style.outlineOffset = saved.outlineOffset;
    highlightedTargets.delete(el);
  }

  function highlightPasteTarget(el) {
    if (!el || !el.style) return;
    clearPasteWarningStyle(el);
    const prevOutline = el.style.outline;
    const prevOffset = el.style.outlineOffset;
    el.style.outline = "2px solid #7d0c14";
    el.style.outlineOffset = "2px";
    const timer = setTimeout(() => {
      clearPasteWarningStyle(el);
    }, 6000);
    highlightedTargets.set(el, { outline: prevOutline, outlineOffset: prevOffset, timer });
  }

  function showPasteWarning(message) {
    if (!uiRefs) return;
    uiRefs.alertText.textContent = message;
    uiRefs.alertBanner.style.display = "flex";
    uiRefs.status.textContent = "⚠ 機密貼付検知";
  }

  function hidePasteWarning() {
    if (!uiRefs) return;
    uiRefs.alertBanner.style.display = "none";
    uiRefs.alertText.textContent = "";
  }

  async function saveSettings(partial) {
    uiSettings = { ...uiSettings, ...partial };
    applySettingsToUi();
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.settings]: uiSettings });
    } catch {
      // Ignore storage failures in restricted contexts
    }
  }

  function applySettingsToUi() {
    if (!uiRefs) return;
    const collapsed = Boolean(uiSettings.collapsed);
    uiRefs.controlsWrap.style.display = collapsed ? "none" : "flex";
    uiRefs.btnCollapse.textContent = collapsed ? "展開" : "最小化";
    uiRefs.btnCollapse.setAttribute("aria-expanded", String(!collapsed));
    uiRefs.host.style.opacity = collapsed ? "0.9" : "1";
    uiRefs.pasteCheckbox.checked = Boolean(uiSettings.pasteGuard);
  }

  async function runRedactOnPage() {
    const target = findPromptTarget();
    if (!target) return { ok: false, message: "入力欄が見つかりません" };
    const raw = readTargetText(target);
    if (!raw.trim()) return { ok: false, message: "入力欄が空です" };

    const engine = await getEngine();
    const stored = await chrome.storage.local.get([STORAGE_KEYS.vault, STORAGE_KEYS.dict]);
    const prevVault = stored[STORAGE_KEYS.vault] || {};
    const dict = Array.isArray(stored[STORAGE_KEYS.dict]) ? stored[STORAGE_KEYS.dict] : [];

    const session = engine.restoreVaultSession(prevVault);
    const res = engine.redact(raw, { customDictionary: dict, vaultSession: session });
    setEditableText(target, res.redactedText);
    clearPasteWarningStyle(target);
    hidePasteWarning();

    const mergedVault = res.vaultMap;
    await chrome.storage.local.set({ [STORAGE_KEYS.vault]: mergedVault });

    const riskSuffix = res.injectionRiskScore >= 0.4 ? ` · 注入警戒:${res.injectionRiskScore}` : "";
    return {
      ok: true,
      vaultMap: mergedVault,
      findingsCount: res.findings.length,
      message: `黒塗り ${res.findings.length}件 (外部送信0)${riskSuffix}`,
    };
  }

  async function runRestoreOnPage() {
    const engine = await getEngine();
    const stored = await chrome.storage.local.get([STORAGE_KEYS.vault]);
    const vaultMap = stored[STORAGE_KEYS.vault] || {};
    const keys = Object.keys(vaultMap);
    if (keys.length === 0) return { ok: false, message: "Vaultに復元対象がありません" };

    const target = findPromptTarget();
    let updated = 0;
    if (target) {
      const current = readTargetText(target);
      const restored = engine.restore(current, vaultMap);
      if (restored !== current) {
        setEditableText(target, restored);
        updated += 1;
      }
    }

    const responseNodes = document.querySelectorAll(
      "article, .markdown, .prose, message-content, [data-message-author-role='assistant'], [data-testid='ai-message'], .chat-message-text, .response-container"
    );
    for (const node of responseNodes) {
      if (node.closest && node.closest("#kurogate-floating-gate")) continue;
      if (node.innerText && keys.some((k) => node.innerText.includes(k))) {
        const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
        for (let t = walker.nextNode(); t; t = walker.nextNode()) {
          const next = engine.restore(t.nodeValue, vaultMap);
          if (next !== t.nodeValue) {
            t.nodeValue = next;
            updated += 1;
          }
        }
      }
    }

    return {
      ok: true,
      message: updated > 0 ? `復元完了 (${updated}箇所)` : "トークン未検出",
    };
  }

  async function handlePasteGuard(event) {
    if (!uiSettings.pasteGuard) return;
    const rawTarget = event.target?.nodeType === 1 ? event.target : event.target?.parentElement;
    const editable = isPromptEditable(rawTarget)
      ? rawTarget
      : rawTarget?.closest?.('[contenteditable="true"], textarea, input');
    if (!isPromptEditable(editable)) return;

    const pastedText = event.clipboardData?.getData("text/plain") || "";
    if (!pastedText.trim()) return;

    lastPromptTarget = editable;
    const engine = await getEngine();
    const stored = await chrome.storage.local.get([STORAGE_KEYS.dict]);
    const dict = Array.isArray(stored[STORAGE_KEYS.dict]) ? stored[STORAGE_KEYS.dict] : [];
    const res = engine.redact(pastedText, { customDictionary: dict });

    if (res.findings.length > 0 || res.injectionRiskScore >= 0.4) {
      highlightPasteTarget(editable);
      const kinds = [...new Set(res.findings.map((f) => f.kind))].slice(0, 3).join(", ");
      const parts = [];
      if (res.findings.length > 0) {
        parts.push(`機密 ${res.findings.length}件 (${kinds})`);
      }
      if (res.injectionRiskScore >= 0.4) {
        parts.push(`注入警戒 ${res.injectionRiskScore}`);
      }
      showPasteWarning(`⚠ 貼付警告: ${parts.join(" / ")} — 「黒塗り」推奨`);
    }
  }

  function mountBar() {
    const host = document.createElement("div");
    host.id = "kurogate-floating-gate";
    host.setAttribute("data-kurogate-badge", "true");
    host.style.cssText = [
      "position:fixed",
      "right:16px",
      "bottom:16px",
      "z-index:2147483647",
      "display:flex",
      "flex-direction:column",
      "align-items:flex-end",
      "gap:4px",
      "font:600 12px/1.25 -apple-system,BlinkMacSystemFont,'Hiragino Sans','Yu Gothic UI',sans-serif",
    ].join(";");

    const alertBanner = document.createElement("div");
    alertBanner.setAttribute("role", "alert");
    alertBanner.style.cssText = [
      "display:none",
      "align-items:center",
      "gap:6px",
      "max-width:340px",
      "padding:6px 8px",
      "background:#7d0c14",
      "color:#f5f5f5",
      "border:1px solid #3d0509",
      "box-shadow:0 2px 8px rgba(0,0,0,0.22)",
    ].join(";");

    const alertText = document.createElement("span");
    const btnDismissAlert = document.createElement("button");
    btnDismissAlert.type = "button";
    btnDismissAlert.textContent = "×";
    btnDismissAlert.setAttribute("aria-label", "警告を閉じる");
    btnDismissAlert.style.cssText =
      "padding:0 4px;background:transparent;color:#f5f5f5;border:0;font:inherit;cursor:pointer;";
    btnDismissAlert.addEventListener("click", hidePasteWarning);
    alertBanner.append(alertText, btnDismissAlert);

    const bar = document.createElement("div");
    bar.style.cssText = [
      "display:flex",
      "align-items:center",
      "gap:6px",
      "padding:6px 8px",
      "background:#e2e2e2",
      "color:#7d0c14",
      "border:2px solid #7d0c14",
      "box-shadow:0 2px 8px rgba(0,0,0,0.16)",
    ].join(";");

    const status = document.createElement("span");
    status.textContent = "黒門";
    status.style.paddingRight = "2px";

    const controlsWrap = document.createElement("div");
    controlsWrap.style.cssText = "display:flex;align-items:center;gap:6px;";

    const btnRedact = document.createElement("button");
    btnRedact.type = "button";
    btnRedact.textContent = "黒塗り";
    btnRedact.style.cssText =
      "padding:4px 8px;background:#7d0c14;color:#e2e2e2;border:0;font:inherit;cursor:pointer;";

    const btnRestore = document.createElement("button");
    btnRestore.type = "button";
    btnRestore.textContent = "復元";
    btnRestore.style.cssText =
      "padding:4px 8px;background:#d6d6d6;color:#7d0c14;border:1px solid #7d0c14;font:inherit;cursor:pointer;";

    const pasteLabel = document.createElement("label");
    pasteLabel.title = "貼り付け時に個人情報・APIキーをローカル検知して警告します";
    pasteLabel.style.cssText =
      "display:inline-flex;align-items:center;gap:4px;font-weight:500;cursor:pointer;user-select:none;";
    const pasteCheckbox = document.createElement("input");
    pasteCheckbox.type = "checkbox";
    pasteCheckbox.checked = Boolean(uiSettings.pasteGuard);
    pasteCheckbox.style.cssText = "margin:0;accent-color:#7d0c14;cursor:pointer;";
    const pasteLabelText = document.createElement("span");
    pasteLabelText.textContent = "ペースト時自動警告";
    pasteLabel.append(pasteCheckbox, pasteLabelText);

    const btnCollapse = document.createElement("button");
    btnCollapse.type = "button";
    btnCollapse.textContent = "最小化";
    btnCollapse.setAttribute("aria-expanded", "true");
    btnCollapse.style.cssText =
      "padding:4px 6px;background:transparent;color:#7d0c14;border:1px solid #7d0c14;font:inherit;cursor:pointer;";

    btnRedact.addEventListener("click", async () => {
      const res = await runRedactOnPage();
      status.textContent = res.message;
    });

    btnRestore.addEventListener("click", async () => {
      const res = await runRestoreOnPage();
      status.textContent = res.message;
    });

    pasteCheckbox.addEventListener("change", () => {
      saveSettings({ pasteGuard: pasteCheckbox.checked });
      status.textContent = pasteCheckbox.checked ? "貼付警告 ON" : "貼付警告 OFF";
    });

    btnCollapse.addEventListener("click", () => {
      saveSettings({ collapsed: !uiSettings.collapsed });
    });

    controlsWrap.append(btnRedact, btnRestore, pasteLabel);
    bar.append(status, controlsWrap, btnCollapse);
    host.append(alertBanner, bar);
    document.body.appendChild(host);

    uiRefs = {
      host,
      status,
      controlsWrap,
      btnCollapse,
      pasteCheckbox,
      alertBanner,
      alertText,
    };

    chrome.storage.local
      .get([STORAGE_KEYS.settings])
      .then((stored) => {
        if (stored && typeof stored[STORAGE_KEYS.settings] === "object" && stored[STORAGE_KEYS.settings]) {
          uiSettings = { ...DEFAULT_SETTINGS, ...stored[STORAGE_KEYS.settings] };
        }
        applySettingsToUi();
      })
      .catch(() => {
        applySettingsToUi();
      });

    if (chrome.storage?.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== "local" || !changes[STORAGE_KEYS.settings]?.newValue) return;
        uiSettings = { ...DEFAULT_SETTINGS, ...changes[STORAGE_KEYS.settings].newValue };
        applySettingsToUi();
      });
    }
  }

  document.addEventListener(
    "paste",
    (event) => {
      handlePasteGuard(event).catch(() => {});
    },
    true
  );

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.action === "KUROGATE_REDACT_ACTIVE") {
      runRedactOnPage().then(sendResponse);
      return true;
    }
    if (msg?.action === "KUROGATE_RESTORE_ACTIVE") {
      runRestoreOnPage().then(sendResponse);
      return true;
    }
    return false;
  });

  if (document.body) mountBar();
})();
