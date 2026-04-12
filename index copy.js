const express = require("express");
const crypto = require("crypto");

const { sendTelegram } = require("./ipn");
// --- Tối ưu gửi Telegram: dùng queue để tránh nghẽn khi nhiều IPN đồng thời ---
const PQueue = require("p-queue").default || require("p-queue");
// Giới hạn: tối đa 5 message gửi đồng thời, 20 msg/giây
const telegramQueue = new PQueue({ concurrency: 5, interval: 1000, intervalCap: 20 });

const app = express();
app.use(express.json({ limit: "50kb" })); // Server có thể bị tấn công bằng payload khổng lồ
/**
 * 🔐 DANH SÁCH KEY (MAX 5)
 *
 * 👉 Mỗi key gồm:
 * - name: tên merchant (hiển thị log)
 * - key: AES key dạng HEX (64 ký tự = 32 bytes)
 *
 * ⚠️ Ví dụ key:
 * "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
 */
const AES_KEY_LIST = [
  {
    name: "Dunk SG",
    key: "616c1b1a28401f20692f27c34f1eb2609d6993c90a440e37744202e6bfaefce4"
  },
  {
    name: "Chè xôi bà Sáu",
    key: "7114514da32bc2c1c9956c508f608730464ab67b66ae66c649dbc6629f9bd035"
  },
  {
    name: "Tabby VA",
    key: "8b2392c1d6a66cde222ce9946d795134a84c6a22831f7d27f35af6e119504df9"
  },
  {
    name: "Fast Food KDC Kim Sơn",
    key: "049c05ad3f58adaa6def59cf7976656c00a7c5c4a63ba246432bcb3380cc9911"
  },
  {
    name: "Apple Store Hà Nội",
    key: "c30e2793d2e3f8e22be9f77cb84d4c0753159767f3d63f52944f69f2bdcedf8b"
  },
  {
    name: "Bánh kẹo 2",
    key: "fcdc9f6059a9d8867473ee787d3f131faea9926870569eb34c09751b117e3161"
  },

].filter(item => item.key); // loại key null

// 🧠 in-memory store để hiển thị UI log
const MAX_LOGS = 5;
const ipnLogs = [];
const sseClients = new Set();
const duplicateCounter = new Map();
const telegramDedupe = new Map(); // key -> lastSentAtMs (best-effort)
const TELEGRAM_DEDUPE_TTL_MS = 0;
let ipnSequence = 0;

setInterval(() => {
  const now = Date.now();
  for (const [key, ts] of telegramDedupe.entries()) {
    if (now - ts > TELEGRAM_DEDUPE_TTL_MS) telegramDedupe.delete(key);
  }
}, 60_000);

// =========================
// ROUTE CONFIG (dễ mở rộng)
// =========================
// Muốn thêm route mới + topic mới:
// - Thêm 1 dòng vào IPN_ROUTES (path + telegramThreadId)
// - Không cần sửa logic decrypt/validate/log
const IPN_ROUTES = [
  { path: "/zonkhanh", telegramThreadId: undefined }, // dùng default topic trong ipn.js
  { path: "/mie", telegramThreadId: 63 },
  { path: "/yfe", telegramThreadId: 65 }
];

// 🔴 Monitor alert thread ID (topic "IPN Monitor" trong group)
const MONITOR_THREAD_ID = 1820; // ← thay bằng thread ID thực của bạn

/**
 * 🔴 Gửi alert Telegram khi server start (wake up sau sleep)
 */
async function sendServerWakeAlert() {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });
  const message = `🟢 IPN Server đã online\n🕐 ${now}\n🌐 https://ipn-server.onrender.com`;
  await sendTelegram(message, { threadId: MONITOR_THREAD_ID });
}

/**
 * 🧾 LOG HELPER (JSON chuẩn 100%)
 */
function logJSON(type, data) {
  const frame = "-".repeat(72);
  console.log(frame);
  console.log(JSON.stringify({
    type,
    ...data
  }, null, 2));
  console.log(frame);
}

function logIPN(type, entry) {
  const frame = "-".repeat(72);
  console.log(frame);
  console.log(`[${type}]`);
  console.log(formatTelegramMessage(entry));
  console.log(`\n=> Route: ${entry?.route || "-"}`);
  console.log(frame);
}

/**
 * 🔓 AES-256-CBC decrypt
 */
function decryptAES(encryptedHex, keyHex) {
  const key = Buffer.from(keyHex, "hex");

  const ivHex = encryptedHex.substring(0, 32);
  const dataHex = encryptedHex.substring(32);

  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(dataHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString("utf8"));
}

/**
 * ✅ Validate payload
 */
function isValidPayload(data) {
  return (
    data &&
    typeof data === "object" &&
    (data.txnId || data.orderId || data.amount)
  );
}

/**
 * 🔁 Multi-key decrypt
 */
function decryptWithKeys(encryptedHex) {
  let attempts = 0;

  for (const item of AES_KEY_LIST) {
    attempts++;

    try {
      const data = decryptAES(encryptedHex, item.key);

      if (isValidPayload(data)) {
        return {
          success: true,
          data,
          merchant: item.name,
          attempts
        };
      }
    } catch (err) {
      // bỏ qua key lỗi
    }
  }

  return { success: false, attempts };
}

/**
 * ✅ Validate payload theo rule CARD/QR
 */
function validateIPNPayload(data) {
  const paymentType = data?.paymentType;
  const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const hasValue = (value) => value !== undefined && value !== null && value !== "";

  if (paymentType !== "CARD" && paymentType !== "QR") {
    return {
      applied: false,
      profile: "normal",
      valid: true,
      missingFields: [],
      errors: []
    };
  }

  const errors = [];
  let profile = "normal";
  let missingFields = [];

  if (paymentType === "CARD") {
    const isMasterMerchant = hasOwn(data, "cardOrigin");
    const requiredMasterFields = [
      "requestId",
      "orderId",
      "paymentType",
      "transactionType",
      "txnId",
      "serialNo",
      "posEntryMode",
      "tid",
      "mid",
      "batchNo",
      "authIdResponse",
      "retrievalRefNo",
      "cardNo",
      "cardType",
      "bankCode",
      "invoiceNo",
      "requestAmount",
      "tipAmount",
      "billUrl",
      "originalTransactionDate",
      "createdUnixTime",
      "updatedUnixTime",
      "isSettle",
      "settleUnixTime",
      "isVoid",
      "voidUnixTime",
      "isReversal",
      "reversalUnixTime",
      "responseCode",
      "systemTraceNo",
      "cardOrigin",
      "extraData",
      "referenceRefNo"
    ];
    const requiredMerchantFields = [
      "requestId",
      "orderId",
      "amount",
      "tip",
      "paymentType",
      "narrative",
      "fromAccNo",
      "extraData",
      "authIdResponse",
      "retrievalRefNo",
      "cardNo",
      "referenceRefNo",
      "status"
    ];

    const requiredFields = isMasterMerchant ? requiredMasterFields : requiredMerchantFields;
    missingFields = requiredFields.filter((field) => !hasOwn(data, field));
    profile = isMasterMerchant ? "master-merchant-card" : "merchant-card";

    if (!hasValue(data?.orderId)) {
      errors.push("orderId must have data");
    }

    if (!hasValue(data?.referenceRefNo)) {
      errors.push("referenceRefNo must have data");
    } else if (hasValue(data?.orderId) && data.referenceRefNo !== data.orderId) {
      errors.push("referenceRefNo must equal orderId");
    }

    if (hasOwn(data, "extraData")) {
      if (!data.extraData || typeof data.extraData !== "object" || Array.isArray(data.extraData)) {
        errors.push("extraData must be an object");
      }
    }
  }

  if (paymentType === "QR") {
    const isMasterMerchantQR = hasOwn(data, "detailTransaction");
    const requiredMasterQRFields = [
      "requestId",
      "orderId",
      "amount",
      "tip",
      "paymentType",
      "narrative",
      "fromAccNo",
      "accNo",
      "extraData",
      "detailTransaction"
    ];
    const requiredMerchantQRFields = [
      "requestId",
      "orderId",
      "amount",
      "tip",
      "paymentType",
      "narrative",
      "fromAccNo",
      "accNo",
      "trnRefNo",
      "extraData"
    ];

    const requiredFields = isMasterMerchantQR ? requiredMasterQRFields : requiredMerchantQRFields;
    missingFields = requiredFields.filter((field) => !hasOwn(data, field));
    profile = isMasterMerchantQR ? "master-merchant-qr" : "merchant-qr";

    if (!hasValue(data?.accNo)) {
      errors.push("accNo must have data");
    }

    if (hasOwn(data, "extraData")) {
      if (!data.extraData || typeof data.extraData !== "object" || Array.isArray(data.extraData)) {
        errors.push("extraData must be an object");
      }
    }

    if (isMasterMerchantQR) {
      const detail = data?.detailTransaction;
      if (!detail || typeof detail !== "object" || Array.isArray(detail)) {
        errors.push("detailTransaction must be an object");
      } else {
        const requiredDetailFields = [
          "externalRefNo",
          "trnRefNo",
          "acEntrySrNo",
          "accNo",
          "source",
          "ccy",
          "drcr",
          "lcyAmount",
          "valueDt",
          "txnInitDt",
          "relatedAccount",
          "relatedAccountName",
          "narrative",
          "clientUserID",
          "channel",
          "fromAccNo",
          "fromAccName",
          "fromBankCode",
          "fromBankName",
          "napasTraceId"
        ];
        const missingDetailFields = requiredDetailFields
          .filter((field) => !hasOwn(detail, field))
          .map((field) => `detailTransaction.${field}`);
        missingFields = missingFields.concat(missingDetailFields);
      }
    }
  }

  return {
    applied: true,
    profile,
    valid: missingFields.length === 0 && errors.length === 0,
    missingFields,
    errors
  };
}

function pushLog(entry) {
  ipnLogs.push(entry);
  if (ipnLogs.length > MAX_LOGS) {
    ipnLogs.shift();
  }

  const eventData = `data: ${JSON.stringify(entry)}\n\n`;
  sseClients.forEach((res) => {
    res.write(eventData);
  });

  if (!entry.__skipTelegram) {
    void pushLogToTelegram(entry);
  }
}

function getTelegramValidationState(entry) {
  const profile = entry?.validation?.profile;
  const isCardProfile = profile === "master-merchant-card" || profile === "merchant-card";
  const isInvalid = isCardProfile && entry?.validation?.applied && !entry?.validation?.valid;

  return {
    isCardProfile,
    isInvalid
  };
}

//Data hiện ở log telegram
function formatTelegramMessage(entry) {
  if (entry?.decryptFailed) {
    const prefix = "⚠️ [IPN-LOG] Decrypt failed";
    const routeLine = `🛤 Route: ${entry?.route || "-"}`;
    const raw = entry?.rawData != null ? String(entry.rawData) : "";
    return `${prefix}\n${routeLine}\n\nraw data:\n${raw}`;
  }

  const { isInvalid } = getTelegramValidationState(entry);
  const statusIcon = isInvalid ? "❌" : "✅";
  const invalidTag = isInvalid ? " [INVALID]" : "";
  const prefix = `${statusIcon} [IPN-LOG]${invalidTag}`;
  const merchantLine = `🐳 Merchant: ${entry?.merchant || "-"}`;
  const isMasterMerchantCard = entry?.validation?.profile === "master-merchant-card";
  const posLine = isMasterMerchantCard ? `\n🤖 POS: ${entry?.decrypted?.serialNo || "-"}` : "";

  // Validation block
  const validation = entry?.validation;
  let validationLine = "";
  if (validation?.applied) {
    const validStatus = validation.valid ? "PASS" : "FAIL";
    validationLine = `\n📋 Validation [${validation.profile}]: ${validStatus}`;
    if (!validation.valid) {
      const bulletPoints = [
        ...(validation.missingFields || []).map(f => `  • Missing: ${f}`),
        ...(validation.errors || []).map(e => `  • ${e}`)
      ].join("\n");
      if (bulletPoints) validationLine += `\n${bulletPoints}`;
    }
  }

  // In thẳng decrypted, không wrap
  const prettyLog = JSON.stringify(entry?.decrypted ?? null, null, 2);

  return `${prefix}\n${merchantLine}${posLine}${validationLine}\n\nDecrypted:\n${prettyLog}`;
}

function buildTelegramErrorLog(entry, errorInfo) {
  ipnSequence += 1;

  return {
    Sequence: ipnSequence,
    duplicateInfo: "system",
    status: "telegram_error",
    merchant: entry?.merchant || null,
    decrypted: entry?.decrypted || null,
    validation: entry?.validation || {
      applied: false,
      profile: "normal",
      valid: true,
      missingFields: [],
      errors: []
    },
    telegram: {
      error: errorInfo?.error?.message || "Unknown telegram error",
      attempt: errorInfo?.attempt || 0
    },
    __skipTelegram: true
  };
}

async function pushLogToTelegram(entry) {
  // best-effort chống gửi trùng do IPN retry / network timeout
  const threadId = entry?.__telegramThreadId ?? "default";
  const fingerprint = entry?.__fingerprint;
  if (fingerprint) {
    const key = `${threadId}|${fingerprint}`;
    const now = Date.now();
    const last = telegramDedupe.get(key);
    if (last && now - last < TELEGRAM_DEDUPE_TTL_MS) return;
    telegramDedupe.set(key, now);
  }

  // Đưa task gửi Telegram vào queue để kiểm soát tốc độ và số lượng gửi đồng thời
  telegramQueue.add(async () => {
    const message = formatTelegramMessage(entry);
    const result = await sendTelegram(message, { maxRetries: 3, threadId: entry?.__telegramThreadId });
    if (!result.success) {
      const telegramErrorLog = buildTelegramErrorLog(entry, result);
      pushLog(telegramErrorLog);
      logJSON("TELEGRAM_ERROR", sanitizeLogForDisplay(telegramErrorLog));
    }
  });
}

function createIPNHandler({ routeName, telegramThreadId }) {
  return (req, res) => {
    const body = req.body;

    // ✅ trả response ngay (QUAN TRỌNG)
    res.status(200).json({ status: "received" });

    setImmediate(() => {
      const log = {
        decrypted: null,
        status: "pending",
        merchant: null,
        attempts: 0,
        error: null
      };

      try {
        const encryptedHex = body?.data;

        if (!encryptedHex) {
          throw new Error("Missing data field");
        }

        const result = decryptWithKeys(encryptedHex);

        log.attempts = result.attempts;

        if (!result.success) {
          throw new Error("All keys failed");
        }

        const decrypted = result.data;

        log.decrypted = decrypted;
        log.merchant = result.merchant;
        log.status = "success";
        const validation = validateIPNPayload(decrypted);
        const uiLog = buildLogEntry({ body, log, validation });
        uiLog.__telegramThreadId = telegramThreadId;
        uiLog.route = routeName;
        pushLog(uiLog);
        logIPN("IPN_SUCCESS", uiLog);

      } catch (err) {
        if (err.message === "All keys failed") {
          const uiLog = buildDecryptFailedLogEntry({ body, routeName, telegramThreadId });
          pushLog(uiLog);
          logJSON("IPN_ERROR", {
            route: routeName,
            error: err.message,
            rawData: body?.data !== undefined && body?.data !== null ? body.data : body
          });
        } else {
          log.status = "error";
          log.error = err.message;
          const validation = validateIPNPayload(log.decrypted);
          const uiLog = buildLogEntry({ body, log, validation });
          uiLog.__telegramThreadId = telegramThreadId;
          uiLog.route = routeName;
          pushLog(uiLog);
          logIPN("IPN_ERROR", uiLog);
        }
      }
    });
  };
}

function getFingerprint(payload) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(payload || {}))
    .digest("hex");
}

// Data hiện ở log render
function buildLogEntry({ body, log, validation }) {
  ipnSequence += 1;
  const Sequence = ipnSequence;
  const fingerprint = getFingerprint(log.decrypted || body);
  const duplicateCount = (duplicateCounter.get(fingerprint) || 0) + 1;
  duplicateCounter.set(fingerprint, duplicateCount);
  const duplicateInfo = duplicateCount === 1 ? "first_time" : `duplicate_x${duplicateCount}`;

  return {
    Sequence,
    duplicateInfo,
    ...log,
    validation,
    __fingerprint: fingerprint
    // raw: body,
  };
}

/**
 * Log tối giản khi không decrypt được: chỉ raw `data` + route, không Sequence/validation/...
 */
function buildDecryptFailedLogEntry({ body, routeName, telegramThreadId }) {
  ipnSequence += 1;
  const rawData =
    body?.data !== undefined && body?.data !== null ? String(body.data) : JSON.stringify(body ?? {});
  const fingerprint = getFingerprint({ raw: rawData });

  return {
    decryptFailed: true,
    Sequence: ipnSequence,
    route: routeName,
    rawData,
    error: "All keys failed",
    __fingerprint: fingerprint,
    __telegramThreadId: telegramThreadId
  };
}

function sanitizeLogForDisplay(logEntry) {
  const output = { ...logEntry };
  delete output.timestamp;
  delete output.attempts;
  delete output.error;
  delete output.status;
  delete output.__skipTelegram;
  delete output.__telegramThreadId;
  delete output.__fingerprint;
  return output;
}


function renderLogPage() {
  return `<!doctype html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>IPN Log Viewer</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:        #0d0d0f;
      --bg2:       #141417;
      --bg3:       #1c1c21;
      --border:    #2a2a32;
      --border2:   #36363f;
      --text:      #e8e8f0;
      --text2:     #8888a0;
      --text3:     #55556a;
      --accent:    #4f8cff;
      --green:     #34d399;
      --red:       #f87171;
      --yellow:    #fbbf24;
      --purple:    #a78bfa;
      --cyan:      #22d3ee;
      --sidebar-w: 340px;
      --topbar-h:  52px;
      --bottomnav-h: 56px;
      --safe-bottom: env(safe-area-inset-bottom, 0px);
    }

    html, body { height: 100%; overflow: hidden; }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
    }

    /* ── TOPBAR ── */
    .topbar {
      height: var(--topbar-h);
      min-height: var(--topbar-h);
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 16px;
      gap: 10px;
      z-index: 20;
      padding-left: max(16px, env(safe-area-inset-left));
      padding-right: max(16px, env(safe-area-inset-right));
    }
    .topbar-logo {
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      letter-spacing: -0.3px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .topbar-logo .dot {
      width: 8px; height: 8px;
      background: var(--green);
      border-radius: 50%;
      box-shadow: 0 0 6px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.4; }
    }
    .topbar-sep { width: 1px; height: 20px; background: var(--border2); flex-shrink: 0; }
    .chip {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      padding: 3px 9px;
      border-radius: 5px;
      border: 1px solid var(--border2);
      color: var(--text2);
      background: var(--bg3);
      white-space: nowrap;
    }
    .chip.live { border-color: #34d39940; color: var(--green); background: #34d3991a; }
    /* hide POST chip on very small screens */
    .chip.post-chip { }
    .topbar-right { margin-left: auto; display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    #counter-chip {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--text2);
      white-space: nowrap;
    }
    .clear-btn {
      font-size: 11px;
      font-family: 'Inter', sans-serif;
      padding: 5px 10px;
      border-radius: 5px;
      border: 1px solid var(--border2);
      color: var(--text2);
      background: transparent;
      cursor: pointer;
      transition: all 0.15s;
      -webkit-tap-highlight-color: transparent;
    }
    .clear-btn:hover { background: var(--bg3); color: var(--text); }

    /* ── MAIN LAYOUT ── */
    .main {
      display: flex;
      flex: 1;
      overflow: hidden;
    }

    /* ── SIDEBAR (desktop) ── */
    .sidebar {
      width: var(--sidebar-w);
      min-width: var(--sidebar-w);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: var(--bg2);
    }
    .sidebar-header {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .sidebar-header span {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text3);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .filter-bar {
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 6px;
      overflow-x: auto;
      scrollbar-width: none;
      -webkit-overflow-scrolling: touch;
    }
    .filter-bar::-webkit-scrollbar { display: none; }
    .filter-btn {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid var(--border2);
      color: var(--text3);
      background: transparent;
      cursor: pointer;
      transition: all 0.15s;
      white-space: nowrap;
      flex-shrink: 0;
      -webkit-tap-highlight-color: transparent;
    }
    .filter-btn:hover, .filter-btn.active {
      border-color: var(--accent);
      color: var(--accent);
      background: #4f8cff15;
    }
    .list {
      flex: 1;
      overflow-y: auto;
      scrollbar-width: thin;
      scrollbar-color: var(--border2) transparent;
      -webkit-overflow-scrolling: touch;
    }
    .list-item {
      padding: 11px 14px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.1s;
      display: flex;
      flex-direction: column;
      gap: 4px;
      position: relative;
      -webkit-tap-highlight-color: transparent;
    }
    .list-item::before {
      content: '';
      position: absolute;
      left: 0; top: 0; bottom: 0;
      width: 3px;
      border-radius: 0 2px 2px 0;
      background: transparent;
      transition: background 0.15s;
    }
    .list-item:active { background: var(--bg3); }
    .list-item.active { background: #4f8cff12; }
    .list-item.active::before { background: var(--accent); }
    .list-item.failed::before { background: var(--red); }
    @keyframes flashIn {
      0%   { background: #4f8cff22; }
      100% { background: transparent; }
    }
    .list-item.new-flash { animation: flashIn 0.5s ease; }

    .item-row1 { display: flex; align-items: center; gap: 6px; }
    .seq-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: var(--text3);
      min-width: 36px;
    }
    .method-badge {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      padding: 1px 6px;
      border-radius: 3px;
      background: #4f8cff22;
      color: var(--accent);
      flex-shrink: 0;
    }
    .route-text {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--text);
      font-weight: 500;
      flex: 1;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .status-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .status-dot.ok   { background: var(--green); }
    .status-dot.fail { background: var(--red); }
    .item-row2 {
      display: flex;
      align-items: center;
      gap: 6px;
      padding-left: 42px;
    }
    .merchant-text {
      font-size: 11px;
      color: var(--text2);
      flex: 1;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .dup-badge {
      font-size: 9px;
      font-family: 'JetBrains Mono', monospace;
      padding: 1px 5px;
      border-radius: 3px;
      background: #fbbf2422;
      color: var(--yellow);
      border: 1px solid #fbbf2430;
      flex-shrink: 0;
    }
    .time-text {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: var(--text3);
      flex-shrink: 0;
    }
    .empty-list {
      padding: 40px 20px;
      text-align: center;
      color: var(--text3);
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.8;
    }
    .empty-list .empty-icon { font-size: 28px; margin-bottom: 12px; }

    /* ── DETAIL PANEL ── */
    .detail {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      scrollbar-width: thin;
      scrollbar-color: var(--border2) transparent;
      -webkit-overflow-scrolling: touch;
    }
    .detail-empty {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: var(--text3);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      gap: 12px;
    }
    .detail-empty .big { font-size: 36px; }

    .detail-topbar {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      background: var(--bg2);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    /* back button — mobile only */
    .back-btn {
      display: none;
      align-items: center;
      gap: 4px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent);
      background: transparent;
      border: none;
      cursor: pointer;
      padding: 4px 0;
      -webkit-tap-highlight-color: transparent;
    }
    .back-btn svg { width: 14px; height: 14px; stroke: var(--accent); fill: none; stroke-width: 2; }
    .detail-seq {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: var(--text3);
    }
    .detail-route {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
    }
    .status-pill {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      padding: 3px 10px;
      border-radius: 999px;
      white-space: nowrap;
    }
    .status-pill.ok   { background: #34d39920; color: var(--green); border: 1px solid #34d39940; }
    .status-pill.fail { background: #f8717120; color: var(--red);   border: 1px solid #f8717140; }
    .status-pill.warn { background: #fbbf2420; color: var(--yellow); border: 1px solid #fbbf2440; }
    .copy-btn {
      margin-left: auto;
      font-size: 11px;
      font-family: 'Inter', sans-serif;
      padding: 5px 12px;
      border-radius: 5px;
      border: 1px solid var(--border2);
      color: var(--text2);
      background: transparent;
      cursor: pointer;
      transition: all 0.15s;
      -webkit-tap-highlight-color: transparent;
    }
    .copy-btn:hover { background: var(--bg3); color: var(--text); }

    .detail-body { padding: 16px; display: flex; flex-direction: column; gap: 14px; }

    /* info grid */
    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 8px;
    }
    .info-cell {
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
    }
    .info-label {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text3);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    .info-value {
      font-size: 13px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 500;
      color: var(--text);
      word-break: break-all;
    }
    .info-value.green  { color: var(--green); }
    .info-value.red    { color: var(--red); }
    .info-value.yellow { color: var(--yellow); }
    .info-value.accent { color: var(--accent); }
    .info-value.purple { color: var(--purple); }
    .info-value.cyan   { color: var(--cyan); }

    /* section block */
    .section {
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    .section-header {
      padding: 9px 14px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--bg2);
    }
    .section-title {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      color: var(--text2);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .section-badge {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      padding: 1px 6px;
      border-radius: 3px;
      background: var(--bg3);
      color: var(--text3);
      border: 1px solid var(--border2);
    }
    pre.json-block {
      margin: 0;
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.7;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--text);
      background: transparent;
      -webkit-overflow-scrolling: touch;
    }
    .json-key  { color: var(--cyan); }
    .json-str  { color: var(--green); }
    .json-num  { color: var(--purple); }
    .json-bool { color: var(--yellow); }
    .json-null { color: var(--text3); }

    /* validation */
    .val-pass {
      padding: 12px 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--green);
    }
    .val-fail {
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .val-fail-header {
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--red);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .val-item {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      padding: 5px 10px;
      border-radius: 5px;
      background: #f8717110;
      border: 1px solid #f8717125;
      color: #fca5a5;
    }
    .raw-block {
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--yellow);
      word-break: break-all;
      line-height: 1.6;
    }

    /* ── BOTTOM NAV (mobile) ── */
    .bottom-nav {
      display: none;
      position: fixed;
      bottom: 0; left: 0; right: 0;
      height: calc(var(--bottomnav-h) + var(--safe-bottom));
      background: var(--bg2);
      border-top: 1px solid var(--border);
      z-index: 30;
      padding-bottom: var(--safe-bottom);
    }
    .bottom-nav-inner {
      display: flex;
      height: var(--bottomnav-h);
    }
    .nav-tab {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 3px;
      cursor: pointer;
      color: var(--text3);
      font-size: 10px;
      font-family: 'Inter', sans-serif;
      transition: color 0.15s;
      -webkit-tap-highlight-color: transparent;
      position: relative;
    }
    .nav-tab.active { color: var(--accent); }
    .nav-tab svg { width: 20px; height: 20px; }
    .nav-tab .nav-badge {
      position: absolute;
      top: 8px; right: calc(50% - 18px);
      background: var(--red);
      color: #fff;
      font-size: 9px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      min-width: 16px;
      height: 16px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0 4px;
      display: none;
    }
    .nav-tab .nav-badge.visible { display: flex; }

    /* ── MOBILE RESPONSIVE (≤ 768px) ── */
    @media (max-width: 768px) {
      :root { --sidebar-w: 100%; }

      .main { position: relative; overflow: hidden; }

      /* sidebar takes full width, slides */
      .sidebar {
        position: absolute;
        inset: 0;
        width: 100%;
        min-width: 100%;
        border-right: none;
        transform: translateX(0);
        transition: transform 0.28s cubic-bezier(0.4,0,0.2,1);
        z-index: 2;
      }
      .sidebar.hidden {
        transform: translateX(-100%);
        pointer-events: none;
      }

      /* detail panel takes full width, slides from right */
      .detail {
        position: absolute;
        inset: 0;
        transform: translateX(100%);
        transition: transform 0.28s cubic-bezier(0.4,0,0.2,1);
        z-index: 2;
        background: var(--bg);
        /* leave room for bottom nav */
        padding-bottom: calc(var(--bottomnav-h) + var(--safe-bottom));
      }
      .detail.visible {
        transform: translateX(0);
      }

      .back-btn { display: flex; }

      .chip.post-chip { display: none; }
      .topbar-sep    { display: none; }

      .bottom-nav { display: flex; flex-direction: column; }

      /* slightly larger tap targets on list items */
      .list-item { padding: 13px 14px; }

      /* 2-col info grid on mobile */
      .info-grid { grid-template-columns: 1fr 1fr; }

      .detail-body { padding: 12px; }
    }

    /* ── TABLET (769–1024px) ── */
    @media (min-width: 769px) and (max-width: 1024px) {
      :root { --sidebar-w: 280px; }
    }
  </style>
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div class="topbar-logo">
    <span class="dot"></span>
    IPN Logger
  </div>
  <div class="topbar-sep"></div>
  <span class="chip live">● LIVE</span>
  <span class="chip post-chip">POST</span>
  <div class="topbar-right">
    <span id="counter-chip">0 requests</span>
    <button class="clear-btn" onclick="clearAll()">Clear</button>
  </div>
</div>

<!-- MAIN -->
<div class="main">

  <!-- SIDEBAR -->
  <div class="sidebar" id="sidebar">
    <div class="sidebar-header">
      <span>Requests</span>
    </div>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
      <button class="filter-btn" onclick="setFilter('ok', this)">Success</button>
      <button class="filter-btn" onclick="setFilter('fail', this)">Failed</button>
      <button class="filter-btn" onclick="setFilter('dup', this)">Duplicate</button>
    </div>
    <div class="list" id="list">
      <div class="empty-list">
        <div class="empty-icon">📭</div>
        Chưa có IPN nào.<br/>Đang chờ request...
      </div>
    </div>
  </div>

  <!-- DETAIL -->
  <div class="detail" id="detail">
    <div class="detail-empty">
      <div class="big">👈</div>
      Chọn một request để xem chi tiết
    </div>
  </div>

</div>

<!-- BOTTOM NAV (mobile only) -->
<nav class="bottom-nav">
  <div class="bottom-nav-inner">
    <div class="nav-tab active" id="nav-list" onclick="mobileShowList()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/>
        <line x1="8" y1="18" x2="21" y2="18"/>
        <line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/>
        <line x1="3" y1="18" x2="3.01" y2="18"/>
      </svg>
      Requests
      <span class="nav-badge" id="new-badge">0</span>
    </div>
    <div class="nav-tab" id="nav-detail" onclick="mobileShowDetail()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="3" width="18" height="18" rx="2"/>
        <line x1="3" y1="9" x2="21" y2="9"/>
        <line x1="9" y1="21" x2="9" y2="9"/>
      </svg>
      Detail
    </div>
  </div>
</nav>

<script>
  const pathParts = window.location.pathname.split("/");
  const routeFilter = pathParts.length > 2 ? "/" + pathParts[2] : null;

  const listEl    = document.getElementById("list");
  const detailEl  = document.getElementById("detail");
  const sidebarEl = document.getElementById("sidebar");
  const counterEl = document.getElementById("counter-chip");
  const newBadge  = document.getElementById("new-badge");

  let allEntries    = [];
  let selectedSeq   = null;
  let currentFilter = "all";
  let MAX_LOGS      = 500;
  let isMobile      = () => window.innerWidth <= 768;
  let mobileView    = "list"; // "list" | "detail"
  let newCount      = 0;

  /* ── MOBILE NAV ── */
  function mobileShowList() {
    mobileView = "list";
    sidebarEl.classList.remove("hidden");
    detailEl.classList.remove("visible");
    document.getElementById("nav-list").classList.add("active");
    document.getElementById("nav-detail").classList.remove("active");
    newCount = 0;
    newBadge.classList.remove("visible");
  }

  function mobileShowDetail() {
    if (!selectedSeq) return;
    mobileView = "detail";
    sidebarEl.classList.add("hidden");
    detailEl.classList.add("visible");
    document.getElementById("nav-detail").classList.add("active");
    document.getElementById("nav-list").classList.remove("active");
  }

  /* ── UTILS ── */
  function esc(v) {
    return String(v ?? "-")
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  }

  function formatTime(ts) {
    if (!ts) return "";
    return new Date(ts).toLocaleTimeString("vi-VN", { hour12: false });
  }

  function highlightJSON(obj) {
    const raw = JSON.stringify(obj, null, 2);
    return esc(raw).replace(
      /("(?:\\\\u[a-fA-F0-9]{4}|\\\\[^u]|[^\\\\"])*")(\s*:\s*)|("(?:\\\\u[a-fA-F0-9]{4}|\\\\[^u]|[^\\\\"])*")|\b(true|false)\b|\b(null)\b|(-?\d+(?:\\.\\d+)?(?:[eE][+\-]?\d+)?)/g,
      (m, kTok, sep, sTok, bTok, nulTok, numTok) => {
        if (kTok)   return '<span class="json-key">'  + kTok  + '</span>' + sep;
        if (sTok)   return '<span class="json-str">'  + sTok  + '</span>';
        if (bTok)   return '<span class="json-bool">' + bTok  + '</span>';
        if (nulTok) return '<span class="json-null">' + nulTok + '</span>';
        if (numTok) return '<span class="json-num">'  + numTok + '</span>';
        return m;
      }
    );
  }

  /* ── FILTER ── */
  function setFilter(f, btn) {
    currentFilter = f;
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    rebuildList();
  }

  function matchFilter(entry) {
  // 🔥 filter theo route từ URL trước
  if (routeFilter && entry.route !== routeFilter) {
    return false;
  }

  if (currentFilter === "all") return true;

  if (currentFilter === "ok") {
    return !entry.decryptFailed && (!entry.validation?.applied || entry.validation.valid);
  }

  if (currentFilter === "fail") {
    return (
      entry.decryptFailed ||
      (entry.validation?.applied && !entry.validation.valid)
    );
  }

  if (currentFilter === "dup") {
    return entry.duplicateInfo && entry.duplicateInfo !== "first_time";
  }

  return true;
}

  /* ── LIST ITEM ── */
  function buildListItem(entry) {
    const isFailed = !!entry.decryptFailed;
    const isDup    = entry.duplicateInfo && entry.duplicateInfo !== "first_time";
    const route    = entry.route || "-";
    const merchant = entry.merchant || (isFailed ? "decrypt failed" : "-");
    const ts       = entry._ts || null;

    const li = document.createElement("div");
    li.className = "list-item" + (isFailed ? " failed" : "");
    li.dataset.seq = entry.Sequence;

    li.innerHTML =
      '<div class="item-row1">' +
        '<span class="seq-badge">#' + esc(entry.Sequence) + '</span>' +
        '<span class="method-badge">POST</span>' +
        '<span class="route-text">' + esc(route) + '</span>' +
        '<span class="status-dot ' + (isFailed ? "fail" : "ok") + '"></span>' +
      '</div>' +
      '<div class="item-row2">' +
        '<span class="merchant-text">' + esc(merchant) + '</span>' +
        (isDup ? '<span class="dup-badge">DUP</span>' : '') +
        (ts ? '<span class="time-text">' + esc(formatTime(ts)) + '</span>' : '') +
      '</div>';

    li.addEventListener("click", () => {
      selectEntry(entry.Sequence);
      if (isMobile()) mobileShowDetail();
    });
    return li;
  }

  function rebuildList() {
    const filtered = allEntries.filter(matchFilter);
    listEl.innerHTML = "";
    if (!filtered.length) {
      listEl.innerHTML = '<div class="empty-list"><div class="empty-icon">🔍</div>Không có request nào.</div>';
      return;
    }
    filtered.forEach(e => listEl.appendChild(buildListItem(e)));
    if (selectedSeq !== null) {
      const el = listEl.querySelector('[data-seq="' + selectedSeq + '"]');
      if (el) el.classList.add("active");
    }
  }

  /* ── DETAIL ── */
  function selectEntry(seq) {
    selectedSeq = seq;
    document.querySelectorAll(".list-item").forEach(el => {
      el.classList.toggle("active", el.dataset.seq == seq);
    });
    const entry = allEntries.find(e => e.Sequence == seq);
    if (!entry) return;
    renderDetail(entry);
  }

  function renderDetail(entry) {
    const isFailed = !!entry.decryptFailed;
    const isDup    = entry.duplicateInfo && entry.duplicateInfo !== "first_time";
    const route    = entry.route || "-";
    const pType    = entry.decrypted?.paymentType || "-";
    const retrievalRefNo = entry.decrypted?.retrievalRefNo || "-";
    const amount   = entry.decrypted?.requestAmount || entry.decrypted?.amount || "-";
    const orderId  = entry.decrypted?.orderId || "-";
    const status   = entry.decrypted?.status || "-";
    const cardNo   = entry.decrypted?.cardNo || "-";
    const bankCode = entry.decrypted?.bankCode || "-";
    const val      = entry.validation;

    let pillCls = "ok", pillTxt = "SUCCESS";
    if (isFailed) { pillCls = "fail"; pillTxt = "DECRYPT FAILED"; }
    else if (val && val.applied && !val.valid) { pillCls = "warn"; pillTxt = "INVALID"; }
    else if (isDup) { pillCls = "warn"; pillTxt = "DUPLICATE"; }

    let html = '';

    // sticky topbar
    html += '<div class="detail-topbar">';
    html += '<button class="back-btn" onclick="mobileShowList()">' +
              '<svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>Back' +
            '</button>';
    html += '<span class="detail-seq">#' + esc(entry.Sequence) + '</span>';
    html += '<span class="detail-route">' + esc(route) + '</span>';
    html += '<span class="status-pill ' + pillCls + '">' + pillTxt + '</span>';
    if (!isFailed) {
      html += '<button class="copy-btn" onclick="copyJSON()">Copy JSON</button>';
    }
    html += '</div>';

    html += '<div class="detail-body">';

    if (isFailed) {
      html += '<div class="info-grid">';
      html += infoCell("Route", route, "accent");
      html += infoCell("Sequence", "#" + entry.Sequence, "");
      html += infoCell("Status", "DECRYPT FAILED", "red");
      html += '</div>';
      html += '<div class="section">';
      html += '<div class="section-header"><span class="section-title">Raw Data</span></div>';
      html += '<div class="raw-block">' + esc(entry.rawData || "") + '</div>';
      html += '</div>';
    } else {
      html += '<div class="info-grid">';
      html += infoCell("Route", route, "accent");
      html += infoCell("Merchant", entry.merchant || "-", "");
      html += infoCell("Payment Type", pType, pType === "CARD" ? "cyan" : pType === "QR" ? "purple" : "");
      html += infoCell("Order ID", orderId, "");
      html += infoCell("Amount", amount !== "-" ? amount + " VND" : "-", "green");
      html += infoCell("Retrieval RefNo", retrievalRefNo, "");
      if (cardNo !== "-") html += infoCell("Card No", "•••• " + cardNo, "");
      if (bankCode !== "-") html += infoCell("Bank", bankCode, "");
      html += infoCell("Status", status, status === "SUCCESS" ? "green" : status !== "-" ? "red" : "");
      html += infoCell("Duplicate", isDup ? entry.duplicateInfo : "first_time", isDup ? "yellow" : "");
      if (val && val.applied) html += infoCell("Validation", val.profile, "");
      html += '</div>';

      if (val && val.applied) {
        html += '<div class="section">';
        html += '<div class="section-header"><span class="section-title">Validation</span><span class="section-badge">' + esc(val.profile) + '</span></div>';
        if (val.valid) {
          html += '<div class="val-pass">✅ PASS — all required fields present</div>';
        } else {
          html += '<div class="val-fail">';
          html += '<div class="val-fail-header">❌ FAIL</div>';
          (val.missingFields || []).forEach(f => { html += '<div class="val-item">Missing: ' + esc(f) + '</div>'; });
          (val.errors || []).forEach(e => { html += '<div class="val-item">Error: ' + esc(e) + '</div>'; });
          html += '</div>';
        }
        html += '</div>';
      }

      html += '<div class="section">';
      html += '<div class="section-header"><span class="section-title">Decrypted Payload</span></div>';
      html += '<pre class="json-block">' + highlightJSON(entry.decrypted || {}) + '</pre>';
      html += '</div>';
    }

    html += '</div>';
    detailEl.innerHTML = html;
    detailEl.scrollTop = 0;
    window.__selectedEntry = entry;
  }

  function infoCell(label, value, colorClass) {
    return '<div class="info-cell">' +
      '<div class="info-label">' + esc(label) + '</div>' +
      '<div class="info-value ' + (colorClass || "") + '">' + esc(value) + '</div>' +
      '</div>';
  }

  function copyJSON() {
    if (!window.__selectedEntry?.decrypted) return;
    navigator.clipboard.writeText(JSON.stringify(window.__selectedEntry.decrypted, null, 2))
      .then(() => {
        const btn = detailEl.querySelector(".copy-btn");
        if (btn) { btn.textContent = "Copied!"; setTimeout(() => btn.textContent = "Copy JSON", 1500); }
      });
  }

  /* ── PUSH / COUNTER ── */
  function pushEntry(entry) {
    entry._ts = Date.now();
    if (allEntries.length >= MAX_LOGS) allEntries.pop();
    allEntries.unshift(entry);
    updateCounter();
  }

  function updateCounter() {
    counterEl.textContent = allEntries.length + " request" + (allEntries.length !== 1 ? "s" : "");
  }

  function clearAll() {
    allEntries = []; selectedSeq = null; newCount = 0;
    listEl.innerHTML = '<div class="empty-list"><div class="empty-icon">📭</div>Chưa có IPN nào.<br/>Đang chờ request...</div>';
    detailEl.innerHTML = '<div class="detail-empty"><div class="big">👈</div>Chọn một request để xem chi tiết</div>';
    newBadge.classList.remove("visible");
    updateCounter();
    if (isMobile()) mobileShowList();
  }

  /* ── INIT ── */
  async function init() {
    const res  = await fetch("/logs/history");
    const data = await res.json();
    MAX_LOGS   = data.maxLogs || 500;

    (data.logs || []).forEach(e => { e._ts = null; allEntries.push(e); });
    updateCounter();
    rebuildList();
    if (allEntries.length && !isMobile()) selectEntry(allEntries[0].Sequence);

    const source = new EventSource("/logs/stream");
    source.onmessage = (event) => {
      const entry = JSON.parse(event.data);
      pushEntry(entry);
      rebuildList();

      const el = listEl.querySelector('[data-seq="' + entry.Sequence + '"]');
      if (el) el.classList.add("new-flash");

      // auto-select on desktop; badge on mobile if viewing detail
      if (!isMobile()) {
        if (selectedSeq === null) selectEntry(entry.Sequence);
      } else {
        if (mobileView === "detail") {
          newCount++;
          newBadge.textContent = newCount > 9 ? "9+" : newCount;
          newBadge.classList.add("visible");
        } else {
          if (selectedSeq === null) selectEntry(entry.Sequence);
        }
      }
    };
  }

  init();
</script>
</body>
</html>`;
}

/**
 * 📩 IPN ENDPOINTS
 */
IPN_ROUTES.forEach((cfg) => {
  app.post(cfg.path, createIPNHandler({ routeName: cfg.path, telegramThreadId: cfg.telegramThreadId }));
});

/**
 * 📺 UI LOG ROUTES
 */
app.get("/logs", (req, res) => {
  res.type("html").send(renderLogPage());
});

app.get("/logs/history", (req, res) => {
  res.json({ logs: [...ipnLogs].reverse(), maxLogs: MAX_LOGS });
});

app.get("/logs/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  res.write("retry: 3000\n\n");
  sseClients.add(res);

  req.on("close", () => {
    sseClients.delete(res);
  });
});

app.get("/logs/:route", (req, res) => {
  res.type("html").send(renderLogPage());
});
/**
 * ❤️ HEALTH CHECK
 */
app.get("/", (req, res) => {
  res.send("IPN Server Running 🚀 | UI: /logs");
});

/**
 * 🚀 START SERVER
 */
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  logJSON("SERVER_START", {
    port: PORT,
    message: "Server started successfully",
    telegram: "https://t.me/zonkhanh",
    owner: "zonkhanh"
  });

  // 🔴 Alert Telegram khi server wake up
  sendServerWakeAlert();
});