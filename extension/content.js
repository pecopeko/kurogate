(() => {
  if (window.__kurogateMounted) return;
  window.__kurogateMounted = true;

  const STORAGE_KEYS = {
    vault: "kurogate_vault_v1",
    dict: "kurogate_dict_v1",
  };

  let enginePromise = null;
  function getEngine() {
    if (!enginePromise) {
      enginePromise = import(chrome.runtime.getURL("core/kurogate-engine.mjs"));
    }
    return enginePromise;
  }

  function findPromptTarget() {
    const active = document.activeElement;
    if (active && (active.tagName === "TEXTAREA" || active.isContentEditable)) {
      return active;
    }
    const selectors = [
      "#prompt-textarea",
      "textarea[data-id]",
      'div.ProseMirror[contenteditable="true"]',
      'rich-textarea div[contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
      "textarea",
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  function readTargetText(el) {
    if (!el) return "";
    return el.tagName === "TEXTAREA" || el.tagName === "INPUT" ? el.value : el.innerText;
  }

  function writeTargetText(el, nextText) {
    if (!el) return;
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      el.value = nextText;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      el.innerText = nextText;
      el.dispatchEvent(new InputEvent("input", { bubbles: true, data: nextText }));
    }
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

    const session = engine.createVaultSession();
    for (const [placeholder, original] of Object.entries(prevVault)) {
      session.vaultMap[placeholder] = original;
    }

    const res = engine.redact(raw, { customDictionary: dict, vaultSession: session });
    writeTargetText(target, res.redactedText);
    const mergedVault = { ...prevVault, ...res.vaultMap };
    await chrome.storage.local.set({ [STORAGE_KEYS.vault]: mergedVault });

    return {
      ok: true,
      vaultMap: mergedVault,
      message: `黒塗り ${res.findings.length}件 (外部送信0)`,
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
        writeTargetText(target, restored);
        updated += 1;
      }
    }

    const responseNodes = document.querySelectorAll("article, .markdown, message-content, [data-message-author-role='assistant']");
    for (const node of responseNodes) {
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
      "align-items:center",
      "gap:6px",
      "padding:6px 8px",
      "background:#e2e2e2",
      "color:#7d0c14",
      "border:2px solid #7d0c14",
      "font:600 12px/1.2 -apple-system,BlinkMacSystemFont,'Hiragino Sans',sans-serif",
    ].join(";");

    const status = document.createElement("span");
    status.textContent = "黒門";
    status.style.paddingRight = "4px";

    const btnRedact = document.createElement("button");
    btnRedact.type = "button";
    btnRedact.textContent = "黒塗り";
    btnRedact.style.cssText = "padding:4px 8px;background:#7d0c14;color:#e2e2e2;border:0;font:inherit;cursor:pointer;";

    const btnRestore = document.createElement("button");
    btnRestore.type = "button";
    btnRestore.textContent = "復元";
    btnRestore.style.cssText = "padding:4px 8px;background:#d6d6d6;color:#7d0c14;border:1px solid #7d0c14;font:inherit;cursor:pointer;";

    btnRedact.addEventListener("click", async () => {
      const res = await runRedactOnPage();
      status.textContent = res.message;
    });

    btnRestore.addEventListener("click", async () => {
      const res = await runRestoreOnPage();
      status.textContent = res.message;
    });

    host.append(status, btnRedact, btnRestore);
    document.body.appendChild(host);
  }

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
