require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const { sendTelegram } = require("./ipn");
const PQueue = require("p-queue").default || require("p-queue");
const telegramQueue = new PQueue({ concurrency: 5, interval: 1000, intervalCap: 20 });

const app = express();
app.use(express.json({ limit: "50kb" }));

app.use(express.static(path.join(__dirname, 'public')));

const { Redis } = require("@upstash/redis");
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// =========================
// REDIS KEYS
// =========================
const REDIS_KEY = "ipn:logs";
const REDIS_AES_KEYS = "dashboard:aes_keys";
const REDIS_IPN_ROUTES = "dashboard:ipn_routes";
const REDIS_DUPLICATE_COUNTER = "ipn:duplicate_counter"; // Hash: fingerprint -> {count, lastSeen}
const REDIS_TELEGRAM_DEDUPE = "ipn:telegram_dedupe";     // Hash: key -> timestamp
const DUPLICATE_TTL_SEC = 24 * 60 * 60;                 // 24h tính bằng giây cho Redis EXPIRE

// =========================
// SEED DATA (fallback khi Redis trống)
// =========================
const SEED_AES_KEYS = [
  { name: "Dunk SG", key: "616c1b1a28401f20692f27c34f1eb2609d6993c90a440e37744202e6bfaefce4" },
  { name: "Chè xôi bà Sáu", key: "7114514da32bc2c1c9956c508f608730464ab67b66ae66c649dbc6629f9bd035" },
  { name: "Tabby VA", key: "8b2392c1d6a66cde222ce9946d795134a84c6a22831f7d27f35af6e119504df9" },
  { name: "Fast Food KDC Kim Sơn", key: "049c05ad3f58adaa6def59cf7976656c00a7c5c4a63ba246432bcb3380cc9911" },
  { name: "Apple Store Hà Nội", key: "c30e2793d2e3f8e22be9f77cb84d4c0753159767f3d63f52944f69f2bdcedf8b" },
  { name: "Bánh kẹo 2", key: "fcdc9f6059a9d8867473ee787d3f131faea9926870569eb34c09751b117e3161" },
  { name: "Mèo Ba Tư", key: "79c416726ee73e529b681bf9247a76b639bea946b1abf53d6adf18658946d6d1" },
].filter(item => item.key);

const SEED_IPN_ROUTES = [
  { path: "/zonkhanh", telegramThreadId: 6 },
  { path: "/mie", telegramThreadId: 63 },
  { path: "/yfe", telegramThreadId: 65 },
];

// =========================
// DYNAMIC CONFIG (in-memory, loaded from Redis)
// =========================
// Đánh dấu seed items để UI có thể ẩn/hiện
const SEED_AES_KEY_KEYS = new Set(SEED_AES_KEYS.map(k => k.key));
const SEED_IPN_ROUTE_PATHS = new Set(SEED_IPN_ROUTES.map(r => r.path));

let aesKeyList = [...SEED_AES_KEYS];
let ipnRoutes = [...SEED_IPN_ROUTES];

// Dynamic Express router — swap khi config thay đổi
let dynamicRouter = express.Router();
app.use((req, res, next) => dynamicRouter(req, res, next));

// =========================
// DASHBOARD AUTH
// =========================
const IS_LOCAL = !process.env.RENDER; // Render.com tự set biến RENDER=true
const DASHBOARD_SECRET = process.env.DASHBOARD_SECRET || crypto.randomBytes(32).toString("hex");
// Map<token, expiresAt>
const activeSessions = new Map();

// Dọn session hết hạn mỗi 10 phút
setInterval(() => {
  const now = Date.now();
  for (const [token, exp] of activeSessions) {
    if (now > exp) activeSessions.delete(token);
  }
}, 10 * 60 * 1000);

/**
 * Tạo password hợp lệ cho thời điểm `date` (chấp nhận ±1 phút)
 * Format: khanh.nq1309{HH}{mm}
 */
function validDashboardPasswords(date) {
  // Tính giờ VN từ UTC để đồng nhất giữa local và server
  const utcMs = date.getTime();
  const vnOffsetMs = 7 * 60 * 60 * 1000; // UTC+7
  const vnMs = utcMs + vnOffsetMs;
  const vnDate = new Date(vnMs);

  const candidates = [];
  for (let delta = -1; delta <= 1; delta++) {
    const d = new Date(vnDate.getTime() + delta * 60000);
    const HH = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    candidates.push(`khanh.nq1309${HH}${mm}`);
  }
  return candidates;
}

function isValidPassword(password) {
  // Local dev: cho phép password "dev" để tiện test
  if (IS_LOCAL && password === "dev") return true;
  return validDashboardPasswords(new Date()).includes(password);
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function requireDashboardAuth(req, res, next) {
  const token = req.headers["x-dashboard-token"] || req.query._token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  const exp = activeSessions.get(token);
  if (!exp || Date.now() > exp) {
    activeSessions.delete(token);
    return res.status(401).json({ error: "Session expired" });
  }
  next();
}

// =========================
// CONFIG LOADER/SAVER
// =========================
async function loadConfigFromRedis() {
  try {
    const [rawKeys, rawRoutes] = await Promise.all([
      redis.get(REDIS_AES_KEYS),
      redis.get(REDIS_IPN_ROUTES),
    ]);

    if (rawKeys) {
      const parsed = typeof rawKeys === "string" ? JSON.parse(rawKeys) : rawKeys;
      if (Array.isArray(parsed) && parsed.length > 0) aesKeyList = parsed;
    } else {
      // Seed lên Redis lần đầu
      await redis.set(REDIS_AES_KEYS, JSON.stringify(SEED_AES_KEYS));
      console.log("[INIT] Seeded AES keys to Redis");
    }

    if (rawRoutes) {
      const parsed = typeof rawRoutes === "string" ? JSON.parse(rawRoutes) : rawRoutes;
      if (Array.isArray(parsed) && parsed.length > 0) ipnRoutes = parsed;
    } else {
      await redis.set(REDIS_IPN_ROUTES, JSON.stringify(SEED_IPN_ROUTES));
      console.log("[INIT] Seeded IPN routes to Redis");
    }

    console.log(`[INIT] Loaded ${aesKeyList.length} AES keys, ${ipnRoutes.length} IPN routes`);
  } catch (err) {
    console.error("[INIT] loadConfigFromRedis error:", err.message);
    console.log("[INIT] Falling back to hardcoded seed data");
  }
}

async function saveAesKeys() {
  await redis.set(REDIS_AES_KEYS, JSON.stringify(aesKeyList));
}

async function saveIpnRoutes() {
  await redis.set(REDIS_IPN_ROUTES, JSON.stringify(ipnRoutes));
}

// =========================
// CONSTANTS
// =========================
const MAX_LOGS = 30000;
const MONITOR_THREAD_ID = 1820;

// Redis write queue — tách khỏi critical path, SSE broadcast không chờ Redis
const redisWriteQueue = new PQueue({ concurrency: 1 });

// =========================
// IN-MEMORY STATE
// =========================
const ipnLogs = [];
const sseClients = new Set();
const duplicateCounter = new Map(); // Map<fingerprint, { count, lastSeen }>
const DUPLICATE_COUNTER_TTL_MS = 24 * 60 * 60 * 1000; // 24 giờ
const telegramDedupe = new Map();
const TELEGRAM_DEDUPE_TTL_MS = 0;
let ipnSequence = 0;

async function initSequenceFromRedis() {
  try {
    const raw = await redis.lrange(REDIS_KEY, 0, 0);
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

// Restore duplicateCounter từ Redis sau restart
async function initDuplicateCounterFromRedis() {
  try {
    const now = Date.now();
    const raw = await redis.hgetall(REDIS_DUPLICATE_COUNTER);
    if (!raw) return;
    let loaded = 0;
    for (const [fingerprint, val] of Object.entries(raw)) {
      const parsed = typeof val === "string" ? JSON.parse(val) : val;
      // Bỏ qua nếu đã quá TTL 24h
      if (now - (parsed.lastSeen || 0) > DUPLICATE_COUNTER_TTL_MS) continue;
      duplicateCounter.set(fingerprint, parsed);
      loaded++;
    }
    console.log(`[INIT] duplicateCounter restored: ${loaded} entries`);
  } catch (err) {
    console.error("initDuplicateCounterFromRedis error:", err.message);
  }
}

// Restore telegramDedupe từ Redis sau restart
async function initTelegramDedupeFromRedis() {
  try {
    const raw = await redis.hgetall(REDIS_TELEGRAM_DEDUPE);
    if (!raw) return;
    let loaded = 0;
    for (const [key, val] of Object.entries(raw)) {
      const ts = Number(val);
      if (!isNaN(ts)) { telegramDedupe.set(key, ts); loaded++; }
    }
    console.log(`[INIT] telegramDedupe restored: ${loaded} entries`);
  } catch (err) {
    console.error("initTelegramDedupeFromRedis error:", err.message);
  }
}

// Cleanup duplicateCounter sau 24h không thấy fingerprint
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of duplicateCounter.entries()) {
    if (now - val.lastSeen > DUPLICATE_COUNTER_TTL_MS) duplicateCounter.delete(key);
  }
}, 60 * 60 * 1000); // chạy mỗi 1 giờ

// =========================
// SERVER ALERTS
// =========================
async function sendServerWakeAlert() {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });
  const message = `🟢 IPN Server online\n🕐 ${now}\n🌐 https://ipn-server.onrender.com`;
  await sendTelegram(message, { threadId: MONITOR_THREAD_ID });
}

process.on("SIGTERM", async () => {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });
  const message = `🔴 IPN Server offline (SIGTERM)\n🕐 ${now}\n🌐 https://ipn-server.onrender.com`;

  try {
    await Promise.race([
      sendTelegram(message, { threadId: MONITOR_THREAD_ID }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Telegram timeout")), 4000))
    ]);
  } catch (_) {
    // Bỏ qua
  }

  process.exit(0);
});

const OWNER_TELEGRAM_ID = process.env.OWNER_TELEGRAM_ID

process.on("uncaughtException", async (err) => {
  const now = new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" });

  const message = `💥 IPN Server crash\n🕐 ${now}\n❌ ${err.message}\n\ncc: ${OWNER_TELEGRAM_ID}`;

  try {
    await Promise.race([
      sendTelegram(message, { threadId: MONITOR_THREAD_ID }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Telegram timeout")), 4000))
    ]);
  } catch (_) { }

  process.exit(1);
});

// =========================
// HELPERS
// =========================
function logJSON(type, data) {
  const frame = "-".repeat(72);
  console.log(frame);
  console.log(JSON.stringify({ type, ...data }, null, 2));
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

// =========================
// AES / DECRYPT
// =========================
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

// function isValidPayload(data) {
//   return data && typeof data === "object" && data.amount;
// }

function isValidPayload(data) {
  return data !== null && typeof data === "object" && !Array.isArray(data);
}

function decryptWithKeys(encryptedHex) {
  let attempts = 0;
  for (const item of aesKeyList) {
    attempts++;
    try {
      const data = decryptAES(encryptedHex, item.key);
      if (isValidPayload(data)) return { success: true, data, merchant: item.name, attempts };
    } catch (_) { }
  }
  return { success: false, attempts };
}

// =========================
// VALIDATION
// =========================
function validateIPNPayload(data) {
  const paymentType = data?.paymentType;
  const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const hasValue = (value) => value !== undefined && value !== null && value !== "";

  if (paymentType !== "CARD" && paymentType !== "QR") {
    return { applied: false, profile: "normal", valid: true, missingFields: [], errors: [] };
  }

  const errors = [];
  let profile = "normal";
  let missingFields = [];

  if (paymentType === "CARD") {
    const isMasterMerchant = hasOwn(data, "cardOrigin");
    const requiredMasterFields = [
      "requestId", "orderId", "paymentType", "transactionType", "txnId", "serialNo",
      "posEntryMode", "tid", "mid", "batchNo", "authIdResponse", "retrievalRefNo",
      "cardNo", "cardType", "bankCode", "invoiceNo", "requestAmount", "tipAmount",
      "billUrl", "originalTransactionDate", "createdUnixTime", "updatedUnixTime",
      "isSettle", "settleUnixTime", "isVoid", "voidUnixTime", "isReversal",
      "reversalUnixTime", "responseCode", "systemTraceNo", "cardOrigin", "extraData", "referenceRefNo"
    ];
    const requiredMerchantFields = [
      "requestId", "orderId", "amount", "tip", "paymentType", "narrative", "fromAccNo",
      "extraData", "authIdResponse", "retrievalRefNo", "cardNo", "referenceRefNo", "status"
    ];
    const requiredFields = isMasterMerchant ? requiredMasterFields : requiredMerchantFields;
    missingFields = requiredFields.filter((field) => !hasOwn(data, field));
    profile = isMasterMerchant ? "master-merchant-card" : "merchant-card";

    if (!hasValue(data?.orderId)) errors.push("orderId must have data");
    if (!hasValue(data?.referenceRefNo)) {
      errors.push("referenceRefNo must have data");
    } else if (hasValue(data?.orderId) && data.referenceRefNo !== data.orderId) {
      errors.push("referenceRefNo must equal orderId");
    }
    if (hasOwn(data, "extraData")) {
      if (!data.extraData || typeof data.extraData !== "object" || Array.isArray(data.extraData))
        errors.push("extraData must be an object");
    }
  }

  if (paymentType === "QR") {
    const isMasterMerchantQR = hasOwn(data, "detailTransaction");
    const requiredMasterQRFields = [
      "requestId", "orderId", "amount", "tip", "paymentType", "narrative",
      "fromAccNo", "accNo", "extraData", "detailTransaction"
    ];
    const requiredMerchantQRFields = [
      "requestId", "orderId", "amount", "tip", "paymentType", "narrative",
      "fromAccNo", "accNo", "trnRefNo", "extraData"
    ];
    const requiredFields = isMasterMerchantQR ? requiredMasterQRFields : requiredMerchantQRFields;
    missingFields = requiredFields.filter((field) => !hasOwn(data, field));
    profile = isMasterMerchantQR ? "master-merchant-qr" : "merchant-qr";

    if (!hasValue(data?.accNo)) errors.push("accNo must have data");
    if (hasOwn(data, "extraData")) {
      if (!data.extraData || typeof data.extraData !== "object" || Array.isArray(data.extraData))
        errors.push("extraData must be an object");
    }
    if (isMasterMerchantQR) {
      const detail = data?.detailTransaction;
      if (!detail || typeof detail !== "object" || Array.isArray(detail)) {
        errors.push("detailTransaction must be an object");
      } else {
        const requiredDetailFields = [
          "externalRefNo", "trnRefNo", "acEntrySrNo", "accNo", "source", "ccy", "drcr",
          "lcyAmount", "valueDt", "txnInitDt", "relatedAccount", "relatedAccountName",
          "narrative", "clientUserID", "channel", "fromAccNo", "fromAccName",
          "fromBankCode", "fromBankName", "napasTraceId"
        ];
        const missingDetailFields = requiredDetailFields
          .filter((field) => !hasOwn(detail, field))
          .map((field) => `detailTransaction.${field}`);
        missingFields = missingFields.concat(missingDetailFields);
      }
    }
  }

  return {
    applied: true, profile,
    valid: missingFields.length === 0 && errors.length === 0,
    missingFields, errors
  };
}

// =========================
// LOG HELPERS
// =========================
function pushLog(entry) {
  // 1. Cập nhật in-memory ngay lập tức
  ipnLogs.push(entry);
  if (ipnLogs.length > MAX_LOGS) ipnLogs.shift();

  // 2. Broadcast SSE ngay — không chờ Redis
  const eventData = `data: ${JSON.stringify(entry)}\n\n`;
  sseClients.forEach((res) => res.write(eventData));

  // 3. Telegram ngay (async, không block)
  if (!entry.__skipTelegram) void pushLogToTelegram(entry);

  // 4. Redis write chạy ngầm qua queue — không block SSE
  redisWriteQueue.add(async () => {
    try {
      await redis.pipeline()
        .lpush(REDIS_KEY, JSON.stringify(entry))
        .ltrim(REDIS_KEY, 0, MAX_LOGS - 1)
        .exec();
    } catch (err) {
      console.error("Redis pushLog error:", err.message);
    }
  });
}

function getTelegramValidationState(entry) {
  const profile = entry?.validation?.profile;
  const isCardProfile = profile === "master-merchant-card" || profile === "merchant-card";
  const isInvalid = isCardProfile && entry?.validation?.applied && !entry?.validation?.valid;
  return { isCardProfile, isInvalid };
}

function formatTelegramMessage(entry) {
  if (entry?.decryptFailed) {
    const prefix = "⚠️ [IPN-LOG] Decrypt failed";
    const routeLine = `✈️ Route: ${entry?.route || "-"}`;
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
    validation: entry?.validation || { applied: false, profile: "normal", valid: true, missingFields: [], errors: [] },
    telegram: { error: errorInfo?.error?.message || "Unknown telegram error", attempt: errorInfo?.attempt || 0 },
    __skipTelegram: true
  };
}

async function pushLogToTelegram(entry) {
  const threadId = entry?.__telegramThreadId ?? 4742;  // ← đổi "default" thành 4742
  const fingerprint = entry?.__fingerprint;
  if (fingerprint) {
    const key = `${threadId}|${fingerprint}`;
    const now = Date.now();
    const last = telegramDedupe.get(key);
    if (last && now - last < TELEGRAM_DEDUPE_TTL_MS) return;
    telegramDedupe.set(key, now);
  }
  telegramQueue.add(async () => {
    const message = formatTelegramMessage(entry);
    const result = await sendTelegram(message, { maxRetries: 3, threadId: threadId });  // ← dùng threadId đã resolve ở trên
    if (!result.success) {
      const telegramErrorLog = buildTelegramErrorLog(entry, result);
      pushLog(telegramErrorLog);
      logJSON("TELEGRAM_ERROR", sanitizeLogForDisplay(telegramErrorLog));
    }
  });
}

function getFingerprint(payload) {
  return crypto.createHash("sha256").update(JSON.stringify(payload || {})).digest("hex");
}

function buildLogEntry({ body, log, validation }) {
  ipnSequence += 1;
  const Sequence = ipnSequence;
  const fingerprint = getFingerprint(log.decrypted || body);

  const existing = duplicateCounter.get(fingerprint);
  const duplicateCount = (existing?.count || 0) + 1;
  const lastSeen = Date.now();
  duplicateCounter.set(fingerprint, { count: duplicateCount, lastSeen });

  // Persist vào Redis ngầm — không block flow chính
  redisWriteQueue.add(async () => {
    try {
      await redis.hset(REDIS_DUPLICATE_COUNTER, { [fingerprint]: JSON.stringify({ count: duplicateCount, lastSeen }) });
      // Gia hạn TTL mỗi lần có activity
      await redis.expire(REDIS_DUPLICATE_COUNTER, DUPLICATE_TTL_SEC);
    } catch (err) {
      console.error("Redis duplicateCounter persist error:", err.message);
    }
  });

  const duplicateInfo = duplicateCount === 1 ? "first_time" : `duplicate_x${duplicateCount}`;
  const uid = `${Sequence}_${Date.now()}`;
  return { Sequence, uid, duplicateInfo, receivedAt: Date.now(), ...log, validation, __fingerprint: fingerprint };
}

function buildDecryptFailedLogEntry({ body, routeName, telegramThreadId }) {
  ipnSequence += 1;
  const rawData = body?.data !== undefined && body?.data !== null ? String(body.data) : JSON.stringify(body ?? {});
  const fingerprint = getFingerprint({ raw: rawData });
  const uid = `${ipnSequence}_${Date.now()}`;
  return {
    decryptFailed: true, Sequence: ipnSequence, uid, route: routeName,
    receivedAt: Date.now(), rawData, error: "All keys failed",
    __fingerprint: fingerprint, __telegramThreadId: telegramThreadId
  };
}

function sanitizeLogForDisplay(logEntry) {
  const output = { ...logEntry };
  delete output.timestamp; delete output.attempts; delete output.error;
  delete output.status; delete output.__skipTelegram;
  delete output.__telegramThreadId; delete output.__fingerprint;
  return output;
}

// =========================
// IPN HANDLER FACTORY
// =========================
function createIPNHandler({ routeName, telegramThreadId }) {
  return (req, res) => {
    const body = req.body;
    // res.status(200).json({ status: "received" });
    res.status(200).json({ code: "00" });
    setImmediate(() => {
      const log = { decrypted: null, status: "pending", merchant: null, attempts: 0, error: null };
      try {
        // const encryptedHex = body?.data;
        const encryptedHex = typeof body?.data === "string" ? body.data.trim() : body?.data;
        if (!encryptedHex) throw new Error("Missing data field");
        const result = decryptWithKeys(encryptedHex);
        log.attempts = result.attempts;
        if (!result.success) throw new Error("All keys failed");
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
          logJSON("IPN_ERROR", { route: routeName, error: err.message, rawData: body?.data ?? body });
        } else {
          log.status = "error"; log.error = err.message;
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

// =========================
// DYNAMIC ROUTER — rebuild khi config thay đổi
// =========================
function rebuildDynamicRouter() {
  const router = express.Router();
  ipnRoutes.forEach((cfg) => {
    router.post(cfg.path, createIPNHandler({
      routeName: cfg.path,
      telegramThreadId: cfg.telegramThreadId ?? 4742
    }));
  });
  dynamicRouter = router;
  console.log(`[ROUTER] Rebuilt with ${ipnRoutes.length} IPN routes:`, ipnRoutes.map(r => r.path));
}

// =========================
// STATIC ROUTES (log UI)
// =========================
const LOG_PAGE_PATH = path.join(__dirname, "renderLogPage.html");
const DASHBOARD_PAGE_PATH = path.join(__dirname, "dashboard.html");

app.get("/logs", (req, res) => res.sendFile(LOG_PAGE_PATH));

// QUAN TRỌNG: /logs/history và /logs/stream phải đứng TRƯỚC /logs/:route
// vì Express match theo thứ tự — nếu /:route đứng trước, "history" và "stream"
// sẽ bị bắt như route param thay vì vào đúng handler.

app.get("/logs/history", async (req, res) => {
  try {
    const start = Number(req.query.start || 0);
    const limit = Number(req.query.limit || 200);

    const [raw, total] = await Promise.all([
      redis.lrange(REDIS_KEY, start, start + limit - 1),
      redis.llen(REDIS_KEY)
    ]);

    const logs = raw.map(item =>
      typeof item === "string" ? JSON.parse(item) : item
    );

    res.json({
      logs,
      start,
      limit,
      hasMore: raw.length === limit,
      total
    });
  } catch (err) {
    console.error("Redis history error:", err.message);
    res.json({
      logs: [...ipnLogs].slice(0, 200),
      start: 0,
      limit: 200,
      hasMore: false
    });
  }
});


app.delete("/logs/clear", async (req, res) => {
  ipnLogs.length = 0;
  await Promise.all([
    redis.del(REDIS_KEY),
    redis.del("ipn:route_counts"),
  ]);
  res.json({ ok: true });
});

app.get("/logs/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no"); // ← THÊM DÒNG NÀY
  res.flushHeaders();
  res.write("retry: 3000\n\n");
  sseClients.add(res);
  req.on("close", () => sseClients.delete(res));
});

app.get("/logs/count", async (req, res) => {
  try {
    const route = req.query.route;
    if (!route) {
      const total = await redis.llen(REDIS_KEY);
      return res.json({ total });
    }
    const count = await redis.hget("ipn:route_counts", route);
    res.json({ total: Number(count) || 0 });
  } catch (err) {
    res.json({ total: null });
  }
});

// Phải đứng SAU /logs/history, /logs/stream, /logs/clear
app.get("/logs/:route", (req, res) => {
  const requestedRoute = "/" + req.params.route;
  const routeExists = ipnRoutes.some(r => r.path === requestedRoute);
  if (!routeExists) {
    return res.status(404).sendFile(path.join(__dirname, "public", "404-notfound.html"));
  }
  res.sendFile(LOG_PAGE_PATH);
});

// =========================
// DASHBOARD ROUTES
// =========================
app.get("/dashboard", (req, res) => res.sendFile(DASHBOARD_PAGE_PATH));

// Login
app.post("/dashboard/login", (req, res) => {
  const { password } = req.body;
  if (!password || !isValidPassword(password)) {
    return res.status(401).json({ error: "Sai mật khẩu hoặc đã hết hiệu lực" });
  }
  const token = generateToken();
  activeSessions.set(token, Date.now() + 60 * 60 * 1000); // 1 giờ
  res.json({ token });
});

// Verify token
app.get("/dashboard/verify", requireDashboardAuth, (req, res) => {
  res.json({ ok: true });
});

// --- AES Keys API ---
app.get("/dashboard/aes-keys", requireDashboardAuth, (req, res) => {
  // Trả về list nhưng mask key (chỉ show 8 ký tự đầu + ... + 8 cuối)
  const masked = aesKeyList.map((item, idx) => ({
    idx,
    name: item.name,
    keyPreview: item.key.length > 16
      ? item.key.slice(0, 8) + "..." + item.key.slice(-8)
      : "***",
    isSeed: SEED_AES_KEY_KEYS.has(item.key)
  }));
  res.json({ keys: masked });
});

app.post("/dashboard/aes-keys", requireDashboardAuth, async (req, res) => {
  const { name, key } = req.body;
  if (!name || typeof name !== "string" || !name.trim())
    return res.status(400).json({ error: "Thiếu tên merchant" });
  if (!key || typeof key !== "string" || !/^[0-9a-fA-F]{64}$/.test(key.trim()))
    return res.status(400).json({ error: "AES key phải là HEX 64 ký tự (32 bytes)" });
  if (aesKeyList.some(k => k.key === key.trim()))
    return res.status(400).json({ error: "Key này đã tồn tại" });

  aesKeyList.push({ name: name.trim(), key: key.trim() });
  await saveAesKeys();
  logJSON("DASHBOARD", { action: "ADD_AES_KEY", name: name.trim() });
  res.json({ ok: true, total: aesKeyList.length });
});

app.delete("/dashboard/aes-keys/:idx", requireDashboardAuth, async (req, res) => {
  const idx = Number(req.params.idx);
  if (isNaN(idx) || idx < 0 || idx >= aesKeyList.length)
    return res.status(400).json({ error: "Index không hợp lệ" });
  const removed = aesKeyList.splice(idx, 1)[0];
  await saveAesKeys();
  logJSON("DASHBOARD", { action: "DELETE_AES_KEY", name: removed.name });
  res.json({ ok: true, removed: removed.name });
});

// --- IPN Routes API ---
app.get("/dashboard/ipn-routes", requireDashboardAuth, (req, res) => {
  const routes = ipnRoutes.map((r, i) => ({
    ...r,
    idx: i,
    isSeed: SEED_IPN_ROUTE_PATHS.has(r.path)
  }));
  res.json({ routes });
});

app.post("/dashboard/ipn-routes", requireDashboardAuth, async (req, res) => {
  let { path: routePath, telegramThreadId } = req.body;
  if (!routePath || typeof routePath !== "string")
    return res.status(400).json({ error: "Thiếu path" });
  if (!routePath.startsWith("/")) routePath = "/" + routePath;
  routePath = routePath.trim().replace(/\s/g, "");

  // Bảo vệ các route hệ thống: exact match "/" và prefix match cho /logs, /dashboard
  const isRootPath = routePath === "/";
  const isSystemPrefix = ["/logs", "/dashboard"].some(r => routePath === r || routePath.startsWith(r + "/"));
  if (isRootPath || isSystemPrefix)
    return res.status(400).json({ error: `Path '${routePath}' là route hệ thống, không được dùng` });
  if (ipnRoutes.some(r => r.path === routePath))
    return res.status(400).json({ error: `Route '${routePath}' đã tồn tại` });

  // Default telegram thread id is 4742
  const threadId = telegramThreadId !== undefined && telegramThreadId !== ""
    ? Number(telegramThreadId)
    : 4742;

  ipnRoutes.push({ path: routePath, telegramThreadId: threadId });
  await saveIpnRoutes();
  rebuildDynamicRouter();
  logJSON("DASHBOARD", { action: "ADD_IPN_ROUTE", path: routePath, telegramThreadId: threadId });
  res.json({ ok: true, total: ipnRoutes.length });
});

app.delete("/dashboard/ipn-routes/:idx", requireDashboardAuth, async (req, res) => {
  const idx = Number(req.params.idx);
  if (isNaN(idx) || idx < 0 || idx >= ipnRoutes.length)
    return res.status(400).json({ error: "Index không hợp lệ" });
  const removed = ipnRoutes.splice(idx, 1)[0];
  await saveIpnRoutes();
  rebuildDynamicRouter();
  logJSON("DASHBOARD", { action: "DELETE_IPN_ROUTE", path: removed.path });
  res.json({ ok: true, removed: removed.path });
});

// =========================
// HEALTH CHECK
// =========================
app.get("/", (req, res) => res.send("IPN Server Running 🚀 | UI: /logs | Dashboard: /dashboard"));

// =========================
// 404 CATCH-ALL — PHẢI ĐỨNG CUỐI CÙNG sau tất cả routes
// =========================
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404-notfound.html"));
});

// =========================
// START
// =========================
const PORT = process.env.PORT || 3000;

async function startServer() {
  await loadConfigFromRedis();
  await initSequenceFromRedis();
  rebuildDynamicRouter();

  app.listen(PORT, "0.0.0.0", () => {
    logJSON("SERVER_START", {
      port: PORT,
      message: "Server started successfully",
      telegram: "https://t.me/zonkhanh",
      owner: "zonkhanh"
    });
    sendServerWakeAlert();

    // ← THÊM TẠM để test, xóa sau khi test xong
    // setTimeout(() => {
    //   throw new Error("Test uncaughtException — xóa dòng này sau khi test");
    // }, 3000); // throw sau 3s để server kịp start
  });
}

startServer();