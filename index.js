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

// 👉 idempotent (tránh xử lý trùng IPN)
const processed = new Set();

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
 * 📩 IPN ENDPOINT
 */
app.post("/zonkhanh", async (req, res) => {
    const body = req.body;

    // ✅ log raw chuẩn JSON
    logJSON("IPN_RAW", { raw: body });

    // ✅ trả response ngay (QUAN TRỌNG)
    res.status(200).json({ status: "received" });

    // 👉 xử lý async phía sau
    setImmediate(() => {
        const log = {
            // raw: body,
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

            // 👉 idempotent check
            const id =
                decrypted.txnId ||
                decrypted.orderId ||
                JSON.stringify(decrypted);

            if (processed.has(id)) {
                log.status = "duplicate";
                logJSON("IPN_DUPLICATE", log);
                return;
            }

            processed.add(id);

            logJSON("IPN_SUCCESS", log);

        } catch (err) {
            log.status = "error";
            log.error = err.message;

            logJSON("IPN_ERROR", log);
        }
    });
});

/**
 * ❤️ HEALTH CHECK
 */
app.get("/", (req, res) => {
    res.send("IPN Server Running 🚀");
});

/**
 * 🚀 START SERVER
 */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    logJSON("SERVER_START", {
        port: PORT,
        message: "Server started successfully"
    });
});
