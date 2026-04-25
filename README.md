# IPN Server — Technical README

## Tổng quan

Server Node.js/Express nhận IPN (Instant Payment Notification) được mã hóa AES-256-CBC từ nhiều merchant, giải mã, validate, lưu trữ và phân phối đến 3 đích: Redis (Upstash), Telegram Bot, và Log UI realtime.

**Điểm khác biệt so với phiên bản cũ:**
- AES keys & IPN routes **không còn hardcode** — được load từ Redis và quản lý qua Dashboard
- Có **Dashboard** với xác thực time-based password để quản lý config động
- Response gateway đổi từ `{ status: "received" }` → `{ code: "00" }`
- Default Telegram thread khi không cấu hình: **4742** (thay vì thread 6)
- `duplicateCounter` và `telegramDedupe` được **persist sang Redis** và restore sau restart
- MAX_LOGS tăng từ 10,000 → **30,000** entries

---

## Luồng xử lý End-to-End

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PAYMENT GATEWAY                                 │
│              POST /<route>                                              │
│              body: { data: "<encrypted_hex>" }                          │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  1. RESPONSE NGAY LẬP TỨC                                               │
│     res.status(200).json({ code: "00" })                                │
│     → Tránh gateway timeout, toàn bộ xử lý chạy trong setImmediate()    │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │  setImmediate()
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  2. DECRYPT — decryptWithKeys(encryptedHex)                             │
│                                                                         │
│   Thử lần lượt từng key trong aesKeyList (load động từ Redis):          │
│                                                                         │
│   ┌──────────────────────────────────────────────────┐                  │
│   │  aesKeyList  (seed mặc định — có thể thêm/xóa    │                  │
│   │              qua Dashboard)                       │                  │
│   │  ├─ Dunk SG               (key #1)               │                  │
│   │  ├─ Chè xôi bà Sáu        (key #2)               │                  │
│   │  ├─ Tabby VA              (key #3)               │                  │
│   │  ├─ Fast Food KDC Kim Sơn (key #4)               │                  │
│   │  ├─ Apple Store Hà Nội    (key #5)               │                  │
│   │  ├─ Bánh kẹo 2            (key #6)               │                  │
│   │  └─ Mèo Ba Tư             (key #7)               │                  │
│   └──────────────────────────────────────────────────┘                  │
│                                                                         │
│   Algorithm: AES-256-CBC                                                │
│   Format:    IV (16 bytes) || CipherText — đều dạng HEX                 │
│   Input:     body.data.trim() — có xử lý trailing whitespace            │
│   Kết quả:   JSON object sau khi decrypt + isValidPayload() check       │
│              (object, không phải null hoặc Array)                       │
│                                                                         │
│   ┌──────────────────┐    ┌──────────────────────────────────────────┐  │
│   │  SUCCESS         │    │  FAILED (all keys failed)                │  │
│   │  → merchant xác  │    │  → buildDecryptFailedLogEntry()          │  │
│   │    định được     │    │  → lưu rawData, route, Sequence          │  │
│   └────────┬─────────┘    └──────────────┬───────────────────────────┘  │
└────────────┼─────────────────────────────┼─────────────────────────────┘
             │                             │
             ▼                             ▼
┌────────────────────────┐   ┌────────────────────────────────────────┐
│  3. VALIDATE           │   │  pushLog() → path: DECRYPT FAILED      │
│  validateIPNPayload()  │   │  ⚠️ Telegram: raw data + route         │
│                        │   └────────────────────────────────────────┘
│  Chỉ áp dụng cho       │
│  paymentType CARD/QR   │
│  (non-CARD/QR trả về   │
│  applied: false,       │
│  valid: true — skip)   │
│                        │
│  CARD profiles:        │
│  ├─ master-merchant-card│
│  │  (detect: có field  │
│  │   cardOrigin)       │
│  └─ merchant-card      │
│                        │
│  QR profiles:          │
│  ├─ master-merchant-qr │
│  │  (detect: có field  │
│  │   detailTransaction)│
│  └─ merchant-qr        │
│                        │
│  Kiểm tra CARD:        │
│  • Required fields     │
│  • orderId có data     │
│  • referenceRefNo có   │
│    data & == orderId   │
│  • extraData là object │
│                        │
│  Kiểm tra QR:          │
│  • Required fields     │
│  • accNo có data       │
│  • extraData là object │
│  • detailTransaction   │
│    là object (master)  │
│  • 19 sub-fields của   │
│    detailTransaction   │
│    (master QR)         │
│                        │
│  Kết quả:              │
│  { applied, profile,   │
│    valid,              │
│    missingFields,      │
│    errors }            │
└──────────┬─────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  4. BUILD LOG ENTRY — buildLogEntry()                                   │
│                                                                         │
│  • ipnSequence++ (global counter, restore từ Redis khi restart)         │
│  • uid = Sequence + "_" + Date.now()                                    │
│  • fingerprint = SHA-256 của decrypted payload                          │
│  • duplicateCounter tăng lên (in-memory + persist Redis ngầm)           │
│  • duplicateInfo: "first_time" | "duplicate_x{N}"                       │
│  • gắn: route, merchant, __telegramThreadId, __fingerprint              │
│  • receivedAt = Date.now()                                              │
└──────────┬──────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  5. pushLog(entry) — phân phối đến 3 đích THEO THỨ TỰ ƯU TIÊN           │
└──────┬──────────────────────┬───────────────────────┬───────────────────┘
       │ (1) ngay lập tức     │ (2) ngay lập tức      │ (3) chạy ngầm
       ▼                      ▼                       ▼
┌──────────────┐   ┌──────────────────────┐   ┌──────────────────────────┐
│  A. IN-MEMORY│   │  B. SSE STREAM       │   │  C. REDIS (Upstash)      │
│  ipnLogs[]   │   │  (realtime UI)       │   │                          │
│              │   │                      │   │  redisWriteQueue         │
│  push + shift│   │  sseClients.forEach  │   │  concurrency: 1          │
│  max 30,000  │   │  res.write(data)     │   │  (serialize writes)      │
│              │   │                      │   │                          │
│  Fallback khi│   │  Browser nhận        │   │  pipeline:               │
│  Redis lỗi   │   │  realtime qua        │   │  LPUSH + LTRIM           │
│              │   │  EventSource         │   │  max 30,000 entries      │
└──────────────┘   │  retry: 3000ms       │   │                          │
                   └──────────────────────┘   │  Persist qua restart     │
                                              └──────────────────────────┘
       │ (4) async, không block SSE
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  D. TELEGRAM BOT — pushLogToTelegram()                                   │
│                                                                          │
│  Dedupe check: telegramDedupe Map (TTL = 0ms, hiện tắt)                 │
│  key: "{threadId}|{fingerprint}"                                         │
│                                                                          │
│  Queue: PQueue  concurrency: 5 | rate: 20msg/s per 1000ms               │
│                                                                          │
│  sendTelegram()  maxRetries: 3                                           │
│                                                                          │
│  Thread routing — lấy từ __telegramThreadId (set theo config route):    │
│  /zonkhanh → thread 6      /mie → thread 63    /yfe → thread 65         │
│  route mới tạo qua Dashboard → thread được set khi tạo (default: 4742) │
│                                                                          │
│  Format message:                                                         │
│    Decrypt thành công:   ✅/❌ [IPN-LOG] hoặc ❌ [IPN-LOG] [INVALID]    │
│      🐳 Merchant: <tên>                                                  │
│      🤖 POS: <serialNo>   (chỉ khi profile = master-merchant-card)      │
│      📋 Validation [<profile>]: PASS | FAIL                              │
│         • Missing: <field> / • <error message>                           │
│      Decrypted: <JSON đẹp>                                               │
│                                                                          │
│    Decrypt thất bại:     ⚠️ [IPN-LOG] Decrypt failed                    │
│      ✈️ Route: <route>                                                   │
│      raw data: <string>                                                  │
│                                                                          │
│  Nếu gửi FAIL:                                                           │
│    → buildTelegramErrorLog() → pushLog(__skipTelegram: true)             │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Dynamic Config — Dashboard

Routes và AES keys **không còn hardcode trong code**. Toàn bộ config được lưu trên Redis và load vào bộ nhớ khi server start. Khi thay đổi, `dynamicRouter` được rebuild tức thì mà không cần restart.

```
Server Start
    │
    ├─ loadConfigFromRedis()
    │   ├─ Đọc dashboard:aes_keys  → aesKeyList[]
    │   │   └─ Nếu Redis trống → seed 7 merchants mặc định → lưu Redis
    │   └─ Đọc dashboard:ipn_routes → ipnRoutes[]
    │       └─ Nếu Redis trống → seed 3 routes mặc định → lưu Redis
    │
    ├─ initSequenceFromRedis()   → restore ipnSequence
    ├─ initDuplicateCounterFromRedis() → restore duplicateCounter (TTL 24h)
    ├─ initTelegramDedupeFromRedis()  → restore telegramDedupe
    │
    └─ rebuildDynamicRouter()
        └─ Tạo Express Router mới với tất cả routes từ ipnRoutes[]
           (swap vào dynamicRouter — zero downtime)

Thêm/xóa AES key hoặc route qua Dashboard API:
    └─ Cập nhật aesKeyList[] / ipnRoutes[] in-memory
    └─ saveAesKeys() / saveIpnRoutes() → Redis
    └─ rebuildDynamicRouter() (chỉ với route changes)
```

---

## Dashboard — `/dashboard`

Trang quản trị được bảo vệ bằng **time-based password**.

### Xác thực

| Cơ chế | Mô tả |
|---|---|
| Password format | `khanh.nq1309{HH}{mm}` — theo giờ VN (UTC+7), chấp nhận ±1 phút |
| Local dev | Password `"dev"` luôn hợp lệ khi không có biến `RENDER` |
| Session | Token 32-byte hex, TTL 1 giờ, lưu in-memory `activeSessions` Map |
| Header | `X-Dashboard-Token: <token>` hoặc query `?_token=<token>` |
| Cleanup | Session hết hạn tự dọn mỗi 10 phút |

### Dashboard API

| Endpoint | Method | Mô tả |
|---|---|---|
| `POST /dashboard/login` | Auth | Đổi password → nhận token |
| `GET /dashboard/verify` | Auth | Kiểm tra token còn hợp lệ |
| `GET /dashboard/aes-keys` | AES | Xem danh sách merchants (key bị mask) |
| `POST /dashboard/aes-keys` | AES | Thêm merchant mới (validate HEX 64 ký tự) |
| `DELETE /dashboard/aes-keys/:idx` | AES | Xóa merchant theo index |
| `GET /dashboard/ipn-routes` | Routes | Xem danh sách IPN routes |
| `POST /dashboard/ipn-routes` | Routes | Thêm route mới + rebuild router |
| `DELETE /dashboard/ipn-routes/:idx` | Routes | Xóa route + rebuild router |

**Bảo vệ routes hệ thống:** Không thể tạo route trùng với `/`, `/logs`, `/dashboard` hoặc bất kỳ sub-path nào của chúng.

---

## Log UI — `/logs`

```
Browser mở /logs hoặc /logs/:route
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  GET /logs/history?start=0&limit=200                │
│  ← Redis.lrange("ipn:logs", start, start+limit-1)  │
│  ← Trả về { logs, start, limit, hasMore, total }   │
│  ← fallback: ipnLogs[] in-memory nếu Redis lỗi     │
└──────────────────────┬──────────────────────────────┘
                       │ load history (phân trang)
                       ▼
┌─────────────────────────────────────────────────────┐
│  EventSource("/logs/stream")                        │
│  ← SSE keep-alive, header X-Accel-Buffering: no    │
│  ← retry: 3000ms nếu disconnect                    │
│  ← nhận entry mới realtime qua sseClients.write()  │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  UI Features                                        │
│                                                     │
│  • Filter: All / Success / Failed / Duplicate       │
│  • Filter theo route: /logs/:route                  │
│    - 404 nếu route không tồn tại trong ipnRoutes[]  │
│  • GET /logs/count?route=<path> — đếm theo route   │
│    (dùng Redis Hash ipn:route_counts)               │
│  • Tab title: "IPN Log Viewer +N" (unread count)   │
│    - Đếm theo route nếu đang xem /logs/:route      │
│    - Lưu readUids vào localStorage (per browser)   │
│  • Chấm xanh trên list item = chưa đọc            │
│    - Ẩn khi click xem                              │
│  • Copy JSON decrypted payload                     │
│  • Clear: xóa UI + Redis ipn:logs                  │
│           + Redis ipn:route_counts                 │
│  • SSE auto-select entry mới nhất (desktop)        │
│  • Mobile: badge đếm IPN mới khi đang xem detail  │
└─────────────────────────────────────────────────────┘
```

---

## Server Lifecycle Alerts (Telegram)

```
Server start      →  🟢 "IPN Server online + URL"       → MONITOR_THREAD_ID (1820)
SIGTERM           →  🔴 "IPN Server offline (SIGTERM)"  → MONITOR_THREAD_ID (1820)
                     (timeout 4s, process.exit sau đó)
uncaughtException →  💥 "IPN Server crash + message     → MONITOR_THREAD_ID (1820)
                         + cc: @OWNER_TELEGRAM_ID"
                     (timeout 4s, process.exit(1) sau đó)
```

---

## Cấu trúc Routes

### Static (hardcode)

| Route | Method | Mô tả |
|---|---|---|
| `GET /` | Health | Health check + link UI |
| `GET /logs` | UI | Log viewer toàn bộ |
| `GET /logs/:route` | UI | Log viewer filter theo route (404 nếu route chưa tạo) |
| `GET /logs/history` | API | Lấy lịch sử từ Redis, hỗ trợ phân trang `?start&limit` |
| `GET /logs/stream` | SSE | Realtime stream |
| `GET /logs/count` | API | Đếm tổng hoặc theo route |
| `DELETE /logs/clear` | API | Xóa log (Redis `ipn:logs` + `ipn:route_counts`) |
| `GET /dashboard` | UI | Dashboard quản trị |
| `POST /dashboard/login` | Auth | Đăng nhập |
| `GET /dashboard/verify` | Auth | Verify token |
| `GET /dashboard/aes-keys` | API | Xem AES keys |
| `POST /dashboard/aes-keys` | API | Thêm AES key |
| `DELETE /dashboard/aes-keys/:idx` | API | Xóa AES key |
| `GET /dashboard/ipn-routes` | API | Xem IPN routes |
| `POST /dashboard/ipn-routes` | API | Thêm IPN route |
| `DELETE /dashboard/ipn-routes/:idx` | API | Xóa IPN route |

### Dynamic IPN Routes (load từ Redis, rebuild khi thay đổi)

| Route | Telegram Thread | Loại |
|---|---|---|
| `POST /zonkhanh` | 6 | Seed |
| `POST /mie` | 63 | Seed |
| `POST /yfe` | 65 | Seed |
| `POST /<route mới>` | `telegramThreadId` khi tạo (default: **4742**) | Dynamic |

> Routes tạo qua Dashboard được lưu vào Redis `dashboard:ipn_routes` và tự động active sau `rebuildDynamicRouter()`, không cần restart server.

---

## Lưu trữ & Trạng thái

### Redis Keys

| Key | Kiểu | Mục đích | Giới hạn |
|---|---|---|---|
| `ipn:logs` | List | Persistent log storage | 30,000 entries (LTRIM) |
| `dashboard:aes_keys` | String (JSON) | Danh sách AES keys | — |
| `dashboard:ipn_routes` | String (JSON) | Danh sách IPN routes | — |
| `ipn:duplicate_counter` | Hash | fingerprint → {count, lastSeen} | TTL 24h (EXPIRE) |
| `ipn:telegram_dedupe` | Hash | key → timestamp | — |
| `ipn:route_counts` | Hash | route → count | Xóa khi clear logs |

### In-Memory State

| Thành phần | Kiểu | Mục đích | Persist? |
|---|---|---|---|
| `ipnLogs[]` | Array | SSE push & fallback Redis | ❌ (reset khi restart) |
| `sseClients` | Set | Browser đang kết nối SSE | ❌ |
| `duplicateCounter` | Map | Đếm duplicate theo fingerprint (TTL 24h) | ✅ Redis Hash |
| `telegramDedupe` | Map | Chống gửi Telegram trùng (TTL = 0ms, tắt) | ✅ Redis Hash |
| `ipnSequence` | Number | Counter tăng dần | ✅ Restore từ entry mới nhất |
| `activeSessions` | Map | Token → expiresAt | ❌ |
| `aesKeyList` | Array | AES keys hiện tại | ✅ Redis String |
| `ipnRoutes` | Array | IPN routes hiện tại | ✅ Redis String |
| `dynamicRouter` | Router | Express router, rebuild khi route thay đổi | ❌ |

---

## Sequence vs Total Requests

`Sequence` là counter tăng dần được **restore từ entry mới nhất trong Redis** khi server restart. `Total requests` là tổng số entry thực tế trong Redis tích lũy qua mọi session. Hai con số này **độc lập nhau theo thiết kế** — không phải bug.

---

## Khởi động Server

```
startServer()
    ├─ loadConfigFromRedis()          // load aesKeyList & ipnRoutes
    ├─ initSequenceFromRedis()        // restore ipnSequence
    ├─ rebuildDynamicRouter()         // đăng ký IPN routes lên Express
    └─ app.listen(PORT, "0.0.0.0")
        └─ sendServerWakeAlert()      // Telegram notify online
```

> `initDuplicateCounterFromRedis()` và `initTelegramDedupeFromRedis()` **không được gọi trong `startServer()`** theo code hiện tại — chỉ được định nghĩa. Cần thêm vào `startServer()` nếu muốn restore đầy đủ sau restart.

---

## Environment Variables

```env
# Redis (Upstash)
UPSTASH_REDIS_REST_URL=https://xxx.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_token_here

# Telegram
TELEGRAM_BOT_TOKEN=123456:your_bot_token_here
TELEGRAM_CHAT_ID=-100xxxxxxxxxx
TELEGRAM_TOPIC_ID=6

# Dashboard
DASHBOARD_SECRET=random_fallback_nếu_không_set   # hiện chưa dùng trực tiếp

# Monitoring
OWNER_TELEGRAM_ID=@username                        # cc vào crash alert

# Server
PORT=3000

# Tự động set bởi Render.com (dùng để detect môi trường)
RENDER=true
```

---

## Quản lý Merchants & Routes

### Thêm merchant mới (qua Dashboard UI hoặc API)

```http
POST /dashboard/aes-keys
X-Dashboard-Token: <token>
Content-Type: application/json

{ "name": "Tên merchant", "key": "64_ky_tu_hex_aes_256_key" }
```

Validate: key phải đúng regex `/^[0-9a-fA-F]{64}$/`, không trùng key đã có.

### Thêm IPN route mới (qua Dashboard UI hoặc API)

```http
POST /dashboard/ipn-routes
X-Dashboard-Token: <token>
Content-Type: application/json

{ "path": "/ten-route", "telegramThreadId": 123 }
```

- `telegramThreadId` mặc định là **4742** nếu bỏ trống.
- Không được dùng `/`, `/logs*`, `/dashboard*`.
- Route active ngay lập tức, không cần restart.

### Xóa merchant / route

```http
DELETE /dashboard/aes-keys/:idx
DELETE /dashboard/ipn-routes/:idx
X-Dashboard-Token: <token>
```

---

## Seed Data mặc định

### AES Keys (7 merchants)

| # | Merchant |
|---|---|
| 1 | Dunk SG |
| 2 | Chè xôi bà Sáu |
| 3 | Tabby VA |
| 4 | Fast Food KDC Kim Sơn |
| 5 | Apple Store Hà Nội |
| 6 | Bánh kẹo 2 |
| 7 | Mèo Ba Tư |

### IPN Routes (3 routes seed)

| Path | Telegram Thread |
|---|---|
| `/zonkhanh` | 6 |
| `/mie` | 63 |
| `/yfe` | 65 |

Seed data chỉ được ghi lên Redis **một lần duy nhất** khi key Redis trống. Sau đó Redis là source of truth.