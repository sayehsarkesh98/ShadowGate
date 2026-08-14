// ============================================
// INTEGRATION GUIDE
// How to integrate the new management system
// into the existing edge-tunnel-managed.js
// ============================================

// STEP 1: Add imports at the top of edge-tunnel-managed.js
// (after the existing constants, around line 18)
/*
import { mgmtHandleRequest, mgmtValidateUUID, mgmtTrackBandwidth, 获取活跃UUID列表, clearUUIDCache } from './management.js';
import { handleCron } from './cron.js';
*/

// STEP 2: Replace the old management functions with imports
// Remove these functions from edge-tunnel-managed.js:
// - mgmtValidateUUID (line ~29)
// - mgmtTrackBandwidth (line ~62)
// - mgmtGenerateUUID (line ~93)
// - mgmtCorsHeaders (line ~102)
// - mgmtJsonResponse (line ~111)
// - mgmtHandleLogin (line ~123)
// - mgmtVerifyAuth (line ~151)
// - mgmtGetStats (line ~164)
// - mgmtGetUsers (line ~185)
// - mgmtCreateUser (line ~198)
// - mgmtDeleteUser (line ~219)
// - mgmtGetUserStatus (line ~229)
// - mgmtTrackBandwidthAPI (line ~262)
// - mgmtGenerateSubscriptionUrl (line ~279)
// - mgmtTestConnection (line ~313)
// - mgmtGetUserConfigs (line ~332)
// - mgmtAdminHTML (line ~361)
// - mgmtStatusHTML (line ~674)
// - mgmtHandleRequest (line ~777)

// STEP 3: Add scheduled event handler
// Add this to the export default block at the end:
/*
export default {
    async fetch(request, env, ctx) {
        // ... existing code ...
        // The mgmtHandleRequest call stays the same
    },

    // NEW: Add scheduled handler for Cron Triggers
    async scheduled(event, env, ctx) {
        ctx.waitUntil(handleCron(env));
    }
};
*/

// STEP 4: Keep the existing management route handler call
// This line stays unchanged:
// const mgmtResponse = await mgmtHandleRequest(request, env, ctx);
// if (mgmtResponse) return mgmtResponse;

// STEP 5: Keep the existing UUID validation and bandwidth tracking
// These calls stay the same but now use the imported functions:
// - mgmtValidateUUID(env, uuid) → from management.js
// - mgmtTrackBandwidth(env, matchedUUID, requestCount) → from management.js
// - 获取活跃UUID列表(env) → from management.js

// STEP 6: Add Cron Trigger to wrangler.toml
/*
[[triggers]]
crons = ["0 0 * * *"]  # Run daily at midnight
*/

// ============================================
// IMPORTANT: DO NOT MODIFY THESE SECTIONS
// ============================================
// The following sections must remain EXACTLY as they are:
//
// 1. The main Edge Tunnel proxy logic (处理WS请求, 处理gRPC请求, etc.)
// 2. The VLESS/Trojan/Shadowsocks parsing functions
// 3. The TLS/SSL handling code
// 4. The subscription (/sub) endpoint handling
// 5. The WebSocket upgrade handling
// 6. The gRPC/XHTTP handling
// 7. All the Chinese-named utility functions
//
// These are the core proxy functions that make Edge Tunnel work.
// Only the management layer (mgmt* functions) should be replaced.
