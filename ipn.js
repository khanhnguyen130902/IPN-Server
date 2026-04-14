const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || "-1003979672209";
const DEFAULT_MESSAGE_THREAD_ID = Number(process.env.TELEGRAM_TOPIC_ID || "6");

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendTelegram(message, options = {}) {
    if (!BOT_TOKEN) {
        return { success: false, attempt: 0, error: new Error("Missing TELEGRAM_BOT_TOKEN env var") };
    }

    const threadId =
        options.threadId === undefined || options.threadId === null
            ? DEFAULT_MESSAGE_THREAD_ID
            : Number(options.threadId);

    let attempt = 0;

    while (true) {
        attempt++;

        try {
            const response = await fetch(
                `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        chat_id: CHAT_ID,
                        message_thread_id: threadId,
                        text: message
                    }),
                    signal: AbortSignal.timeout(10000)
                }
            );

            const data = await response.json();

            if (response.ok) {
                return { success: true, attempt };
            }

            // 🚨 HANDLE TELEGRAM ERROR
            if (response.status === 429) {
                const retryAfter = data?.parameters?.retry_after || 5;

                console.warn(`⚠️ Rate limited. Retry after ${retryAfter}s`);

                await delay((retryAfter + 1) * 1000);
                continue; // retry vô hạn nhưng đúng luật
            }

            // ❌ các lỗi khác -> không retry
            return {
                success: false,
                attempt,
                error: data
            };

        } catch (err) {
            // ✅ network error → retry với backoff
            if (attempt >= 5) {
                return {
                    success: false,
                    attempt,
                    error: err
                };
            }

            const backoff = Math.min(1000 * 2 ** attempt, 10000);
            await delay(backoff);
        }
    }
}


module.exports = {
    sendTelegram
};