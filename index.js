const express = require("express");
const crypto = require("crypto");
const { sendTelegram } = require("./ipn");

const app = express();
app.use(express.json());
const owner = "zonkhanh";
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
    {
        name: "Chè xôi bà Sáu",
        key: "7114514da32bc2c1c9956c508f608730464ab67b66ae66c649dbc6629f9bd035"
    }
].filter(item => item.key); // loại key null

// 🧠 in-memory store để hiển thị UI log
const MAX_LOGS = 500;
const ipnLogs = [];
const sseClients = new Set();
const duplicateCounter = new Map();
const telegramDedupe = new Map(); // key -> lastSentAtMs (best-effort)
let ipnSequence = 0;

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

const TELEGRAM_DEDUPE_TTL_MS = 15000;

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

function formatTelegramMessage(entry) {
    const { isInvalid } = getTelegramValidationState(entry);
    const statusIcon = isInvalid ? "❌" : "✅";
    const invalidTag = isInvalid ? " [INVALID]" : "";
    const prefix = `${statusIcon} [IPN-LOG]${invalidTag}`;
    const merchantLine = `✨ Merchant: ${entry?.merchant || "-"}`;
    const isMasterMerchantCard = entry?.validation?.profile === "master-merchant-card";
    const posLine = isMasterMerchantCard ? `\n🤖 POS: ${entry?.decrypted?.serialNo || "-"}` : "";
    const telegramPayload = {
        Sequence: entry?.Sequence ?? null,
        duplicateInfo: entry?.duplicateInfo ?? null,
        decrypted: entry?.decrypted ?? null,
        status: entry?.status ?? null,
        merchant: entry?.merchant ?? null,
        attempts: entry?.attempts ?? null,
        error: entry?.error ?? null,
        validation: entry?.validation ?? null
    };
    const prettyLog = JSON.stringify(telegramPayload, null, 2);

    return `${prefix}\n${merchantLine}${posLine}\n\n${prettyLog}`;
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

    const message = formatTelegramMessage(entry);
    const result = await sendTelegram(message, { maxRetries: 3, threadId: entry?.__telegramThreadId });

    if (!result.success) {
        const telegramErrorLog = buildTelegramErrorLog(entry, result);
        pushLog(telegramErrorLog);
        logJSON("TELEGRAM_ERROR", sanitizeLogForDisplay(telegramErrorLog));
    }
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
                logJSON("IPN_SUCCESS", sanitizeLogForDisplay(uiLog));

            } catch (err) {
                log.status = "error";
                log.error = err.message;
                const validation = validateIPNPayload(log.decrypted);
                const uiLog = buildLogEntry({ body, log, validation });
                uiLog.__telegramThreadId = telegramThreadId;
                uiLog.route = routeName;
                pushLog(uiLog);
                logJSON("IPN_ERROR", sanitizeLogForDisplay(uiLog));
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IPN Log Viewer</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #101010;
      color: #f5f5f5;
      padding: 20px;
    }
    .header {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }
    .title { font-size: 22px; font-weight: 700; }
    .badge {
      background: #2a2a2a;
      color: #d0d0d0;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
    }
    .legend { font-size: 12px; color: #d0d0d0; margin-bottom: 16px; }
    .logs { display: grid; gap: 12px; }
    .log-card {
      background: #1a1a1a;
      border: 1px solid #3a3a3a;
      border-radius: 12px;
      overflow: hidden;
      transition: transform 0.15s ease;
    }
    .log-card:hover {
      transform: translateY(-1px);
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 10px 12px;
      border-bottom: 1px dashed #3a3a3a;
      font-size: 12px;
    }
    .kv { color: #d0d0d0; }
    .content {
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .block-title { color: #f5f5f5; font-size: 13px; font-weight: 700; }
    pre {
      margin: 0;
      background: #0f0f0f;
      border: 1px solid #333333;
      border-radius: 10px;
      padding: 10px;
      overflow: auto;
      font-size: 12px;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .key, .string, .number {
      border-radius: 4px;
      padding: 1px 3px;
      transition: none;
    }
    .warn-list { margin: 0; padding-left: 18px; color: #f5f5f5; font-size: 12px; }
    .empty { color: #d0d0d0; font-size: 13px; border: 1px dashed #444444; border-radius: 10px; padding: 16px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title">IPN Log Viewer</div>
    <div class="badge" id="counter">0 log</div>
    <div class="badge">Realtime</div>
  </div>
  <div class="legend">
    Giao diện log đã được tối giản để tập trung đọc nội dung trên môi trường production.
  </div>
  <div class="logs" id="logs"></div>

  <script>
    const logsRoot = document.getElementById("logs");
    const counter = document.getElementById("counter");

    function esc(input) {
      return String(input)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }

    function highlightJSON(payload) {
      const json = JSON.stringify(payload, null, 2);
      const html = esc(json).replace(
        /("(?:\\\\u[a-fA-F0-9]{4}|\\\\[^u]|[^\\\\"])*")(\\s*:\\s*)|("(?:\\\\u[a-fA-F0-9]{4}|\\\\[^u]|[^\\\\"])*")|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d+)?(?:[eE][+\\-]?\\d+)?/g,
        (match, keyToken, sep, strToken) => {
          if (keyToken) {
            return '<span class="key">' + keyToken + '</span>' + sep;
          }
          if (strToken) return '<span class="string">' + strToken + '</span>';
          return '<span class="number">' + match + '</span>';
        }
      );
      return html;
    }

    function buildWarnings(validation) {
      if (!validation || !validation.applied) return "";
      if (validation.valid) return "<div class=\\"kv\\">Validation: PASS (" + validation.profile + ")</div>";
      const missing = (validation.missingFields || []).map(x => "<li>Missing: " + esc(x) + "</li>").join("");
      const errors = (validation.errors || []).map(x => "<li>Error: " + esc(x) + "</li>").join("");
      return "<div class=\\"kv\\">Validation: FAIL (" + esc(validation.profile) + ")</div><ul class=\\"warn-list\\">" + missing + errors + "</ul>";
    }

    function renderOne(entry, insertTop = false) {
      const card = document.createElement("div");
      card.className = "log-card";
      card.innerHTML = [
        '<div class="meta">',
          '<span class="kv">#' + esc(entry.Sequence) + '</span>',
          '<span class="kv">merchant: ' + esc(entry.merchant || "-") + '</span>',
          '<span class="kv">duplicate: ' + esc(entry.duplicateInfo || "first_time") + '</span>',
        '</div>',
        '<div class="content">',
          '<div><div class="block-title">Decrypted</div><pre>' + highlightJSON(entry.decrypted || {}) + '</pre></div>',
          '<div><div class="block-title">Validation</div>' + buildWarnings(entry.validation) + '</div>',
        '</div>'
      ].join("");

      if (insertTop && logsRoot.firstChild) {
        logsRoot.insertBefore(card, logsRoot.firstChild);
      } else {
        logsRoot.appendChild(card);
      }
    }

    async function init() {
      const res = await fetch("/logs/history");
      const data = await res.json();
      const items = data.logs || [];

      logsRoot.innerHTML = "";
      if (!items.length) {
        logsRoot.innerHTML = '<div class="empty">Chưa có IPN nào. Gửi request vào endpoint để xem realtime log.</div>';
      } else {
        items.forEach((item) => renderOne(item, false));
      }

      counter.textContent = items.length + " log";

      const source = new EventSource("/logs/stream");
      source.onmessage = (event) => {
        const log = JSON.parse(event.data);
        if (document.querySelector(".empty")) logsRoot.innerHTML = "";
        renderOne(log, true);
        const current = parseInt(counter.textContent, 10) || 0;
        counter.textContent = (current + 1) + " log";
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
    res.json({ logs: [...ipnLogs].reverse() });
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
    }); 