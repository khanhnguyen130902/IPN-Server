const express = require("express");
const app = express();

app.use(express.json());

const processed = new Set(); // idempotent demo

app.post("/ipn", async (req, res) => {
    const data = req.body;

    console.log("📥 IPN received:", JSON.stringify(data));

    // 👉 trả 200 NGAY (quan trọng)
    res.status(200).json({ status: "received" });

    // 👉 xử lý async phía sau
    setImmediate(() => {
        try {
            const id = data.txnId || JSON.stringify(data);

            if (processed.has(id)) {
                console.log("⚠️ Duplicate IPN:", id);
                return;
            }

            processed.add(id);

            console.log("✅ Processing IPN:", id);

            // TODO: xử lý business logic ở đây

        } catch (err) {
            console.error("❌ Error processing IPN:", err);
        }
    });
});

app.get("/", (req, res) => {
    res.send("IPN Server Running 🚀");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
