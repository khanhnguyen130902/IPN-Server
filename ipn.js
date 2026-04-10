const BOT_TOKEN = "8489600440:AAHOFGM-xj9x8bc5GtfK6r2bTdwStI4iqeQ";
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || "-1003979672209";
const MESSAGE_THREAD_ID = Number(process.env.TELEGRAM_TOPIC_ID || "6");

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendTelegram(message, options = {}) {
    const maxRetries = options.maxRetries || 3;
    const retryDelayMs = options.retryDelayMs || 500;

    let lastError = null;
    for (let attempt = 1; attempt <= maxRetries; attempt += 1) {
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
                        message_thread_id: MESSAGE_THREAD_ID,
                        text: message
                    }),
                    signal: AbortSignal.timeout(10000)
                }
            );

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Telegram API error ${response.status}: ${errorText}`);
            }

            return { success: true, attempt };
        } catch (err) {
            lastError = err;

            if (attempt < maxRetries) {
                await delay(retryDelayMs * attempt);
            }
        }
    }

    return {
        success: false,
        attempt: maxRetries,
        error: lastError
    };
}

module.exports = {
    sendTelegram
};