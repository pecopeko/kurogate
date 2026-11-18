# KUROGATE（黒門）

100% browser-local Japanese LLM privacy gateway, mathematical check-digit PII redactor, reversible vault, and Manifest V3 Chrome extension. **Zero external network calls. Zero telemetry.**

- Live Static Web Workbench: https://pecopeko.github.io/kurogate/
- Chrome Extension Release (`.zip`): https://github.com/pecopeko/kurogate/releases/tag/v1.0.0

## Capabilities

- **National Tax Agency (NTA) Modulo-9 Verification**: Validates 13-digit Japanese Corporate Numbers (`法人番号`) and `T` + 13-digit Qualified Invoice Registration Numbers (`適格請求書発行事業者登録番号`) across full-width, half-width, and hyphenated formats with 1-to-1 UTF-16 span preservation.
- **MIC Modulo-11 Verification**: Validates 12-digit Individual Numbers (`マイナンバー`), including `remainder <= 1` edge cases, avoiding false positives on internal order codes.
- **Luhn Card & Japanese Ledger Patterns**: Detects 14–19 digit payment cards (Luhn), Japanese bank accounts (`普通 / 当座 / 貯蓄 / 定期 + 7桁`), domestic/`+81` phones, `〒` postal codes, and emails.
- **Custom Enterprise Dictionary**: Persists internal company names, client names, and project codenames locally (`localStorage` in web app, `chrome.storage.local` in Chrome extension).
- **CSV / TSV Batch Processing**: Preserves column headers, scrubs selected columns, and shares one deterministic token vault across rows.
- **Multilingual Prompt-Injection Screening**: Detects English/Japanese override & exfiltration prompts, role-delimiter spoofing, suspicious Base64 payloads, and hidden zero-width/BiDi Unicode controls.
- **ISMS / PrivacyMark Audit Export**: Generates JSON and Markdown compliance summaries containing zero plaintext PII.

## Local Development & Verification

```bash
node --test test/engine.test.mjs
```

## Installing the Chrome Extension (v1.0.0)

1. Download `kurogate-chrome-extension-v1.0.0.zip` from [GitHub Releases](https://github.com/pecopeko/kurogate/releases/tag/v1.0.0) and unzip it.
2. Open `chrome://extensions` in Chrome and toggle **Developer mode** on.
3. Click **Load unpacked** and select the extracted extension directory.
4. Click **黒塗り** / **復元** in the popup or on supported `chatgpt.com`, `claude.ai`, and `gemini.google.com` tabs.
