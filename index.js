require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const { sendTelegram } = require("./ipn");
// --- Tối ưu gửi Telegram: dùng queue để tránh nghẽn khi nhiều IPN đồng thời ---
const PQueue = require("p-queue").default || require("p-queue");
// Giới hạn: tối đa 5 message gửi đồng thời, 20 msg/giây
const telegramQueue = new PQueue({ concurrency: 5, interval: 1000, intervalCap: 20 });

const app = express();
app.use(express.json({ limit: "50kb" })); // Server có thể bị tấn công bằng payload khổng lồ

const { Redis } = require("@upstash/redis");

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const REDIS_KEY = "ipn:logs";
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
  {
    name: "Mèo Ba Tư",
    key: "79c416726ee73e529b681bf9247a76b639bea946b1abf53d6adf18658946d6d1"
  },

].filter(item => item.key); // loại key null

// 🧠 in-memory store để hiển thị UI log
const MAX_LOGS = 30000; // giới hạn log lưu trữ (cả Redis và in-memory)
const ipnLogs = [];
const sseClients = new Set();
const duplicateCounter = new Map();
const telegramDedupe = new Map(); // key -> lastSentAtMs (best-effort)
const TELEGRAM_DEDUPE_TTL_MS = 0;
let ipnSequence = 0;

async function initSequenceFromRedis() {
  try {
    const raw = await redis.lrange(REDIS_KEY, 0, 0); // lấy entry mới nhất
    if (raw && raw.length > 0) {
      const entry = typeof raw[0] === "string" ? JSON.parse(raw[0]) : raw[0];
      if (entry?.Sequence) {
        ipnSequence = entry.Sequence;
        console.log(`[INIT] ipnSequence restored to ${ipnSequence}`);
      }
    }
  } catch (err) {
    console.error("initSequenceFromRedis error:", err.message);
  }
}

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
  const message = `🟢 IPN Server online\n🕐 ${now}\n🌐 https://ipn-server.onrender.com`;
  await sendTelegram(message, { threadId: MONITOR_THREAD_ID });
}

// 🔴 Alert khi server tắt bình thường (SIGTERM từ Render khi deploy/restart)
process.on("SIGTERM", async () => {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });
  await sendTelegram(`🔴 IPN Server offline (SIGTERM)\n🕐 ${now}\n🌐 https://ipn-server.onrender.com`, {
    threadId: MONITOR_THREAD_ID
  });
  process.exit(0);
});

// 🔴 Alert khi server crash (uncaught exception)
process.on("uncaughtException", async (err) => {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });
  await sendTelegram(`💥 IPN Server crash\n🕐 ${now}\n❌ ${err.message}`, {
    threadId: MONITOR_THREAD_ID
  });
  process.exit(1);
});

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
    // (data.txnId || data.orderId || data.amount)
    (data.amount)
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

async function pushLog(entry) {
  // Vẫn giữ in-memory cho SSE realtime
  ipnLogs.push(entry);
  if (ipnLogs.length > MAX_LOGS) ipnLogs.shift();

  // Lưu Redis - gộp 2 lệnh thành 1 round-trip
  try {
    await redis.pipeline()
      .lpush(REDIS_KEY, JSON.stringify(entry))
      .ltrim(REDIS_KEY, 0, MAX_LOGS - 1)
      .exec();
  } catch (err) {
    console.error("Redis pushLog error:", err.message);
  }

  const eventData = `data: ${JSON.stringify(entry)}\n\n`;
  sseClients.forEach((res) => res.write(eventData));

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
  const uid = `${Sequence}_${Date.now()}`;

  return {
    Sequence,
    uid,
    duplicateInfo,
    receivedAt: Date.now(),
    ...log,
    validation,
    __fingerprint: fingerprint
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
  const uid = `${ipnSequence}_${Date.now()}`;

  return {
    decryptFailed: true,
    Sequence: ipnSequence,
    uid,
    route: routeName,
    receivedAt: Date.now(),
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

/**
 * 📩 IPN ENDPOINTS
 */
IPN_ROUTES.forEach((cfg) => {
  app.post(cfg.path, createIPNHandler({ routeName: cfg.path, telegramThreadId: cfg.telegramThreadId }));
});

/**
 * 📺 UI LOG ROUTES
 */
const LOG_PAGE_PATH = path.join(__dirname, "renderLogPage.html");

app.get("/logs", (req, res) => {
  res.sendFile(LOG_PAGE_PATH);
});

app.get("/logs/history", async (req, res) => {
  try {
    const raw = await redis.lrange(REDIS_KEY, 0, MAX_LOGS - 1);
    const logs = raw.map(item => typeof item === "string" ? JSON.parse(item) : item);
    res.json({ logs, maxLogs: MAX_LOGS });
  } catch (err) {
    console.error("Redis history error:", err.message);
    // fallback về in-memory nếu Redis lỗi
    res.json({ logs: [...ipnLogs].reverse(), maxLogs: MAX_LOGS });
  }
});

app.delete("/logs/clear", async (req, res) => {
  ipnLogs.length = 0;
  await redis.del(REDIS_KEY);
  res.json({ ok: true });
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
  res.sendFile(LOG_PAGE_PATH);
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

async function startServer() {
  await initSequenceFromRedis();
  app.listen(PORT, "0.0.0.0", () => {
    logJSON("SERVER_START", {
      port: PORT,
      message: "Server started successfully",
      telegram: "https://t.me/zonkhanh",
      owner: "zonkhanh"
    });
    sendServerWakeAlert();
  });
}
startServer();