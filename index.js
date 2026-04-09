const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

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
        name: "MERCHANT_B",
        key: process.env.KEY_2
    },
    {
        name: "MERCHANT_C",
        key: process.env.KEY_3
    },
    {
        name: "MERCHANT_D",
        key: process.env.KEY_4
    },
    {
        name: "MERCHANT_E",
        key: process.env.KEY_5
    }
].filter(item => item.key); // loại key null

// 🧠 in-memory store để hiển thị UI log
const MAX_LOGS = 500;
const ipnLogs = [];
const sseClients = new Set();
const duplicateCounter = new Map();
let ipnSTT = 0;

/**
 * 🧾 LOG HELPER (JSON chuẩn 100%)
 */
function logJSON(type, data) {
    console.log(JSON.stringify({
        type,
        time: new Date().toISOString(),
        ...data
    }, null, 2)); // 👈 thêm null, 2
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
 * ✅ Validate CARD payload theo rule
 */
function validateCardPayload(data) {
    const paymentType = data?.paymentType;

    if (paymentType !== "CARD") {
        return {
            applied: false,
            profile: "normal",
            valid: true,
            missingFields: [],
            errors: []
        };
    }

    const hasCardOrigin = Object.prototype.hasOwnProperty.call(data, "cardOrigin");
    const isMasterMerchant = hasCardOrigin;
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
    const missingFields = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(data, field));

    const errors = [];
    const hasValue = (value) => value !== undefined && value !== null && value !== "";

    if (!hasValue(data?.orderId)) {
        errors.push("orderId must have data");
    }

    if (!hasValue(data?.referenceRefNo)) {
        errors.push("referenceRefNo must have data");
    } else if (hasValue(data?.orderId)) {
        if (data.referenceRefNo !== data.orderId) {
            errors.push("referenceRefNo must equal orderId");
        }
    }

    if (Object.prototype.hasOwnProperty.call(data, "extraData")) {
        if (!data.extraData || typeof data.extraData !== "object" || Array.isArray(data.extraData)) {
            errors.push("extraData must be an object");
        }
    }

    return {
        applied: true,
        profile: isMasterMerchant ? "master-merchant-card" : "merchant-card",
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
}

function getFingerprint(payload) {
    return crypto
        .createHash("sha256")
        .update(JSON.stringify(payload || {}))
        .digest("hex");
}

function buildLogEntry({ body, log, validation }) {
    ipnSTT += 1;
    const STT = ipnSTT;
    const fingerprint = getFingerprint(log.decrypted || body);
    const duplicateCount = (duplicateCounter.get(fingerprint) || 0) + 1;
    duplicateCounter.set(fingerprint, duplicateCount);
    const duplicateInfo = duplicateCount === 1 ? "first_time" : `duplicate_x${duplicateCount}`;

    return {
        STT,
        colorTag: STT % 7,
        duplicateInfo,
        ...log,
        validation,
        // raw: body,
        // fingerprint
    };
}

function sanitizeLogForDisplay(logEntry) {
    const output = { ...logEntry };
    delete output.timestamp;
    delete output.attempts;
    delete output.error;
    delete output.status;
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
    :root {
      --bg: #0b1020;
      --card: #121a30;
      --text: #e6ebff;
      --muted: #9fb0db;
      --ok: #2dd4bf;
      --warn: #f59e0b;
      --err: #ef4444;
      --dup: #f97316;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
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
      background: #1b2550;
      color: var(--muted);
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
    }
    .legend { font-size: 12px; color: var(--muted); margin-bottom: 16px; }
    .logs { display: grid; gap: 12px; }
    .ipn-separator {
      height: 4px;
      border-radius: 999px;
      opacity: 0.9;
    }
    .log-card {
      background: var(--card);
      border: 1px solid #29345f;
      border-radius: 12px;
      overflow: hidden;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .log-card:hover {
      transform: translateY(-1px);
      border-color: #4a5fa5;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 10px 12px;
      border-bottom: 1px dashed #2f3b6d;
      font-size: 12px;
    }
    .kv { color: var(--muted); }
    .content {
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .block-title { color: #c6d3ff; font-size: 13px; font-weight: 700; }
    pre {
      margin: 0;
      background: #0d152d;
      border: 1px solid #273766;
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
      transition: background 0.15s ease, color 0.15s ease;
    }
    .key:hover { background: rgba(100, 116, 255, 0.25); color: #dee4ff; }
    .field-amount:hover { background: rgba(16, 185, 129, 0.35); color: #d1fae5; }
    .field-retrieval:hover { background: rgba(245, 158, 11, 0.35); color: #fef3c7; }
    .warn-list { margin: 0; padding-left: 18px; color: #ffd0d0; font-size: 12px; }
    .empty { color: var(--muted); font-size: 13px; border: 1px dashed #33406f; border-radius: 10px; padding: 16px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title">IPN Log Viewer</div>
    <div class="badge" id="counter">0 log</div>
    <div class="badge">Realtime</div>
  </div>
  <div class="legend">
    Hover field <strong>amount</strong> và <strong>retrievalRefNo</strong> để kiểm tra nhanh. Mỗi IPN có separator màu riêng để dễ trace.
  </div>
  <div class="logs" id="logs"></div>

  <script>
    const colorPool = ["#22c55e", "#f59e0b", "#3b82f6", "#ec4899", "#8b5cf6", "#14b8a6", "#f43f5e"];
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
            const keyName = keyToken.slice(1, -1);
            let cls = "key";
            if (keyName === "amount") cls += " field-amount";
            if (keyName === "retrievalRefNo") cls += " field-retrieval";
            return '<span class="' + cls + '">' + keyToken + '</span>' + sep;
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
      const separator = document.createElement("div");
      separator.className = "ipn-separator";
      separator.style.background = colorPool[entry.colorTag % colorPool.length];

      const card = document.createElement("div");
      card.className = "log-card";
      card.innerHTML = [
        '<div class="meta">',
          '<span class="kv">#' + esc(entry.STT) + '</span>',
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
        logsRoot.insertBefore(separator, card);
      } else {
        logsRoot.appendChild(separator);
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
 * 📩 IPN ENDPOINT
 */
app.post("/zonkhanh", async (req, res) => {
    const body = req.body;

    // ✅ log raw chuẩn JSON
    // logJSON("IPN_RAW", { raw: body });

    // ✅ trả response ngay (QUAN TRỌNG)
    res.status(200).json({ status: "received" });

    // 👉 xử lý async phía sau
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
            const validation = validateCardPayload(decrypted);
            const uiLog = buildLogEntry({ body, log, validation });
            pushLog(uiLog);
            logJSON("IPN_SUCCESS", sanitizeLogForDisplay(uiLog));

        } catch (err) {
            log.status = "error";
            log.error = err.message;
            const validation = validateCardPayload(log.decrypted);
            const uiLog = buildLogEntry({ body, log, validation });
            pushLog(uiLog);
            logJSON("IPN_ERROR", sanitizeLogForDisplay(uiLog));
        }
    });
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
        message: "Server started successfully"
    });
});
