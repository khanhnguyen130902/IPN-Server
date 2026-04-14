# IPN Server — Technical README

## Tổng quan

Server Node.js/Express nhận IPN (Instant Payment Notification) được mã hóa AES-256-CBC từ nhiều merchant, giải mã, validate, lưu trữ và phân phối đến 3 đích: Redis (Upstash), Telegram Bot, và Log UI realtime.

---

## Luồng xử lý End-to-End

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PAYMENT GATEWAY                                 │
│              POST /route                                                │
│              body: { data: "<encrypted_hex>" }                          │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  1. RESPONSE NGAY LẬP TỨC                                               │
│     res.status(200).json({ status: "received" })                        │
│     → Tránh gateway timeout, toàn bộ xử lý chạy trong setImmediate()    │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │  setImmediate()
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  2. DECRYPT — decryptWithKeys(encryptedHex)                             │
│                                                                         │
│   Thử lần lượt từng key trong AES_KEY_LIST (tối đa 6 merchants):        │
│                                                                         │
│   ┌─────────────────────────────────────┐                               │
│   │  AES_KEY_LIST                       │                               │
│   │  ├─ Dunk SG          (key #1)       │                               │
│   │  ├─ Chè xôi bà Sáu  (key #2)       │                                │
│   │  ├─ Tabby VA         (key #3)       │                               │
│   │  ├─ Fast Food KDC    (key #4)       │                               │
│   │  ├─ Apple Store HN   (key #5)       │                               │
│   │  └─ Bánh kẹo 2       (key #6)       │                               │
│   └─────────────────────────────────────┘                               │
│                                                                         │
│   Algorithm: AES-256-CBC                                                │
│   Format:    IV (16 bytes) || CipherText — đều dạng HEX                 │
│   Kết quả:   JSON object sau khi decrypt                                │
│                                                                         │
│   ┌──────────────────┐    ┌──────────────────────────────────────────┐  │
│   │  SUCCESS         │    │  FAILED (all keys failed)                │  │
│   │  → merchant xác  │    │  → buildDecryptFailedLogEntry()          │  │
│   │    định được     │    │  → lưu rawData, route, Sequence          │  │
│   └────────┬─────────┘    └─────────────────┬────────────────────────┘  │
└────────────┼──────────────────────────────────┼────────────────────────-┘
             │                                  │
             ▼                                  ▼
┌────────────────────────┐         ┌────────────────────────────────────┐
│  3. VALIDATE           │         │  pushLog() → path: DECRYPT FAILED  │
│  validateIPNPayload()  │         │  ⚠️ Telegram: raw data + route     │
│                        │         └────────────────────────────────────┘
│  Chỉ áp dụng cho       │
│  paymentType CARD/QR   │
│                        │
│  CARD profiles:        │
│  ├─ master-merchant-card│
│  │  (có field cardOrigin)│
│  └─ merchant-card      │
│                        │
│  QR profiles:          │
│  ├─ master-merchant-qr │
│  │  (có detailTransaction)│
│  └─ merchant-qr        │
│                        │
│  Kiểm tra:             │
│  • Required fields     │
│  • orderId có data     │
│  • referenceRefNo ==   │
│    orderId (CARD)      │
│  • extraData là object │
│  • accNo có data (QR)  │
│  • detailTransaction   │
│    fields (master QR)  │
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
│  • duplicateInfo: "first_time" | "duplicate_x{N}"                      │
│  • gắn: route, merchant, __telegramThreadId, __fingerprint              │
└──────────┬──────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  5. pushLog(entry) — phân phối đến 3 đích ĐỒNG THỜI                    │
└──────┬──────────────────────┬───────────────────────┬───────────────────┘
       │                      │                       │
       ▼                      ▼                       ▼
┌──────────────┐   ┌──────────────────────┐   ┌──────────────────────────┐
│  A. REDIS    │   │  B. SSE STREAM       │   │  C. TELEGRAM BOT         │
│  (Upstash)   │   │  (realtime UI)       │   │                          │
│              │   │                      │   │  pushLogToTelegram()     │
│  pipeline:   │   │  sseClients.forEach  │   │                          │
│  LPUSH +     │   │  res.write(data)     │   │  Dedupe check:           │
│  LTRIM       │   │                      │   │  telegramDedupe Map      │
│  max 10000   │   │  Browser nhận        │   │  (TTL=0ms, hiện tắt)    │
│              │   │  realtime qua        │   │                          │
│  Persist     │   │  EventSource         │   │  Queue: PQueue           │
│  qua restart │   │  retry: 3000ms       │   │  concurrency: 5          │
└──────────────┘   └──────────────────────┘   │  rate: 20msg/s           │
                                              │                          │
                                              │  sendTelegram()          │
                                              │  maxRetries: 3           │
                                              │                          │
                                              │  Thread routing:         │
                                              │  /zonkhanh → default     │
                                              │  /mie      → thread 63   │
                                              │  /yfe      → thread 65   │
                                              │                          │
                                              │  Message format:         │
                                              │  ✅/❌ [IPN-LOG]        │
                                              │  🐳 Merchant            │
                                              │  🤖 POS (master card)   │
                                              │  📋 Validation status    │
                                              │  Decrypted JSON          │
                                              │                          │
                                              │  Nếu gửi FAIL:           │
                                              │  → buildTelegramErrorLog │
                                              │  → pushLog lại           │
                                              │    (__skipTelegram: true) │
                                              └──────────────────────────┘
```

---

## Log UI — `/logs`

```
Browser mở /logs
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  GET /logs/history                                  │
│  ← Redis.lrange("ipn:logs", 0, 9999)               │
│  ← fallback: ipnLogs[] in-memory nếu Redis lỗi     │
└──────────────────────┬──────────────────────────────┘
                       │ load history
                       ▼
┌─────────────────────────────────────────────────────┐
│  EventSource("/logs/stream")                        │
│  ← SSE keep-alive connection                        │
│  ← retry: 3000ms nếu disconnect                    │
│  ← nhận entry mới realtime qua sseClients.write()  │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  UI Features                                        │
│                                                     │
│  • Filter: All / Success / Failed / Duplicate       │
│  • Filter theo route: /logs/zonkhanh                │
│  • Tab title: "IPN Log Viewer +N" (unread count)    │
│    - Đếm theo route nếu đang xem /logs/:route       │
│    - Lưu readUids vào localStorage (per browser)    │
│  • Chấm xanh trên list item = chưa đọc             │
│    - Ẩn khi click xem                              │
│  • Copy JSON decrypted payload                      │
│  • Clear: xóa UI + Redis + localStorage             │
│  • SSE auto-select entry mới nhất (desktop)         │
│  • Mobile: badge đếm IPN mới khi đang xem detail   │
└─────────────────────────────────────────────────────┘
```

---

## Server Lifecycle Alerts (Telegram)

```
Server start      →  🟢 "IPN Server online"          → MONITOR_THREAD_ID (1820)
SIGTERM           →  🔴 "IPN Server offline (SIGTERM)"→ MONITOR_THREAD_ID (1820)
uncaughtException →  💥 "IPN Server crash" + message  → MONITOR_THREAD_ID (1820)
```

---

## Cấu trúc Routes

| Route | Method | Mô tả |
|---|---|---|
| `POST /zonkhanh` | IPN | Nhận IPN, Telegram default thread |
| `POST /mie` | IPN | Nhận IPN, Telegram thread 63 |
| `POST /yfe` | IPN | Nhận IPN, Telegram thread 65 |
| `GET /logs` | UI | Log viewer toàn bộ |
| `GET /logs/:route` | UI | Log viewer filter theo route |
| `GET /logs/history` | API | Lấy lịch sử từ Redis |
| `GET /logs/stream` | SSE | Realtime stream |
| `DELETE /logs/clear` | API | Xóa toàn bộ log (Redis + memory) |
| `GET /` | Health | Health check |

---

## Lưu trữ & Trạng thái

| Thành phần | Loại | Mục đích |
|---|---|---|
| `ipnLogs[]` | In-memory Array | SSE push realtime, fallback khi Redis lỗi |
| `sseClients` | In-memory Set | Danh sách browser đang kết nối SSE |
| `duplicateCounter` | In-memory Map | Đếm số lần trùng lặp theo fingerprint |
| `telegramDedupe` | In-memory Map | Chống gửi Telegram trùng (TTL=0, hiện tắt) |
| `ipnSequence` | In-memory Number | Counter tăng dần, restore từ Redis khi restart |
| Redis `ipn:logs` | Upstash List | Persistent storage, tối đa 10,000 entries |
| `localStorage` | Browser | Lưu readUids per browser, không đồng bộ server |

---

## Sequence vs Total Requests

`Sequence` là counter tăng dần được restore từ entry mới nhất trong Redis khi server restart. `Total requests` là tổng số entry thực tế trong Redis tích lũy qua mọi session. Hai con số này **độc lập nhau theo thiết kế** — không phải bug.

---

## Environment Variables

```env
UPSTASH_REDIS_REST_URL=https://xxx.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_token_here
TELEGRAM_BOT_TOKEN=123456:your_bot_token_here
TELEGRAM_CHAT_ID=-100xxxxxxxxxx
TELEGRAM_TOPIC_ID=6
PORT=3000
```

---

## Thêm merchant mới

Thêm vào `AES_KEY_LIST` trong `index.js`:
```js
{ name: "Tên merchant", key: "64_ky_tu_hex_aes_256_key" }
```

## Thêm route/Telegram thread mới

Thêm vào `IPN_ROUTES` trong `index.js`:
```js
{ path: "/route-moi", telegramThreadId: 123 }
```
