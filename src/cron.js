// ============================================
// CRON HANDLER
// Scheduled tasks for Edge Manager
// ============================================

export async function handleCron(env) {
    console.log('[Cron] Running scheduled tasks...');

    try {
        // 1. Disable expired users
        await disableExpiredUsers(env);

        // 2. Reset bandwidth (daily/weekly/monthly)
        await resetBandwidth(env);

        // 3. Send expiry warnings
        await sendExpiryWarnings(env);

        // 4. Clean old logs (older than 30 days)
        await cleanOldLogs(env);

        // 5. Process notification queue
        await processNotifications(env);

        console.log('[Cron] All tasks completed');
    } catch (e) {
        console.error('[Cron] Error:', e);
    }
}

async function disableExpiredUsers(env) {
    if (!env.DB) return;

    try {
        const result = await env.DB.prepare(`
            UPDATE users SET is_active = 0
            WHERE expires_at IS NOT NULL
            AND expires_at <= datetime('now')
            AND is_active = 1
        `).run();

        if (result.meta?.changes > 0) {
            console.log(`[Cron] Disabled ${result.meta.changes} expired users`);

            // Queue notifications for expired users
            const expired = await env.DB.prepare(`
                SELECT id, username, telegram_id FROM users
                WHERE expires_at IS NOT NULL
                AND expires_at <= datetime('now')
                AND expires_at > datetime('now', '-1 day')
            `).all();

            for (const user of expired.results) {
                if (user.telegram_id) {
                    await env.DB.prepare(`
                        INSERT INTO notification_queue (user_id, type, message)
                        VALUES (?, 'expiry', ?)
                    `).bind(user.id, `⏰ اشتراک شما منقضی شده است. برای تمدید با پشتیبانی تماس بگیرید.`).run();
                }
            }
        }
    } catch (e) {
        console.error('[Cron] Disable expired error:', e);
    }
}

async function resetBandwidth(env) {
    if (!env.DB) return;

    try {
        // Check last reset time
        const setting = await env.DB.prepare(
            "SELECT value FROM settings WHERE key = 'last_bandwidth_reset'"
        ).first();

        const lastReset = setting?.value ? new Date(setting.value) : new Date(0);
        const now = new Date();
        const daysSinceReset = (now - lastReset) / (1000 * 60 * 60 * 24);

        // Reset daily
        if (daysSinceReset >= 1) {
            const result = await env.DB.prepare(`
                UPDATE users SET used_bandwidth_bytes = 0
                WHERE bandwidth_reset_period = 'daily'
                AND is_active = 1
            `).run();

            if (result.meta?.changes > 0) {
                console.log(`[Cron] Daily bandwidth reset for ${result.meta.changes} users`);
            }
        }

        // Reset weekly
        if (daysSinceReset >= 7) {
            const result = await env.DB.prepare(`
                UPDATE users SET used_bandwidth_bytes = 0
                WHERE bandwidth_reset_period = 'weekly'
                AND is_active = 1
            `).run();

            if (result.meta?.changes > 0) {
                console.log(`[Cron] Weekly bandwidth reset for ${result.meta.changes} users`);
            }
        }

        // Reset monthly
        if (daysSinceReset >= 30) {
            const result = await env.DB.prepare(`
                UPDATE users SET used_bandwidth_bytes = 0
                WHERE bandwidth_reset_period = 'monthly'
                AND is_active = 1
            `).run();

            if (result.meta?.changes > 0) {
                console.log(`[Cron] Monthly bandwidth reset for ${result.meta.changes} users`);
            }

            // Update last reset time
            await env.DB.prepare(`
                INSERT OR REPLACE INTO settings (key, value)
                VALUES ('last_bandwidth_reset', ?)
            `).bind(now.toISOString()).run();
        }
    } catch (e) {
        console.error('[Cron] Reset bandwidth error:', e);
    }
}

async function sendExpiryWarnings(env) {
    if (!env.DB) return;

    try {
        const warningDays = parseInt(
            (await env.DB.prepare("SELECT value FROM settings WHERE key = 'expiry_warning_days'").first())?.value || '7'
        );

        const users = await env.DB.prepare(`
            SELECT id, username, telegram_id, expires_at FROM users
            WHERE expires_at IS NOT NULL
            AND expires_at > datetime('now')
            AND expires_at <= datetime('now', '+' || ? || ' days')
            AND is_active = 1
        `).bind(warningDays).all();

        for (const user of users.results) {
            if (user.telegram_id) {
                const daysLeft = Math.ceil((new Date(user.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
                await env.DB.prepare(`
                    INSERT INTO notification_queue (user_id, type, message)
                    VALUES (?, 'expiry_warning', ?)
                `).bind(user.id, `⏰ اشتراک شما تا ${daysLeft} روز دیگر منقضی میشود. برای تمدید اقدام کنید.`).run();
            }
        }

        if (users.results.length > 0) {
            console.log(`[Cron] Queued ${users.results.length} expiry warnings`);
        }
    } catch (e) {
        console.error('[Cron] Expiry warnings error:', e);
    }
}

async function cleanOldLogs(env) {
    if (!env.DB) return;

    try {
        const result = await env.DB.prepare(`
            DELETE FROM connection_logs
            WHERE created_at < datetime('now', '-30 days')
        `).run();

        if (result.meta?.changes > 0) {
            console.log(`[Cron] Cleaned ${result.meta.changes} old log entries`);
        }
    } catch (e) {
        console.error('[Cron] Clean logs error:', e);
    }
}

async function processNotifications(env) {
    if (!env.DB) return;

    try {
        const pending = await env.DB.prepare(`
            SELECT n.*, u.telegram_id, u.username
            FROM notification_queue n
            LEFT JOIN users u ON n.user_id = u.id
            WHERE n.sent = 0
            LIMIT 10
        `).all();

        const botToken = (await env.DB.prepare("SELECT value FROM settings WHERE key = 'telegram_bot_token'").first())?.value;

        if (!botToken || pending.results.length === 0) return;

        for (const notif of pending.results) {
            try {
                if (notif.telegram_id) {
                    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: notif.telegram_id,
                            text: notif.message,
                            parse_mode: 'HTML'
                        })
                    });
                }

                await env.DB.prepare(
                    'UPDATE notification_queue SET sent = 1 WHERE id = ?'
                ).bind(notif.id).run();
            } catch (e) {
                console.error(`[Cron] Notification send error: ${e.message}`);
            }
        }

        console.log(`[Cron] Processed ${pending.results.length} notifications`);
    } catch (e) {
        console.error('[Cron] Process notifications error:', e);
    }
}
