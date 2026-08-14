#!/usr/bin/env python3
"""
Fix duplicate function declarations in edge-tunnel-managed.js
Remove old management functions that are now in the new management module
"""

import re

def fix():
    with open('src/edge-tunnel-managed.js', 'r', encoding='utf-8-sig') as f:
        content = f.read()

    # Find the old management section
    # It starts after the Edge Tunnel constants and before the new management code
    # The old management functions are between the Edge Tunnel entry point marker and the new management code

    # Find the Edge Tunnel entry point
    edge_tunnel_marker = "///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////"
    edge_tunnel_pos = content.find(edge_tunnel_marker)

    # Find the new management system marker
    new_mgmt_marker = "// ============================================\n// EDGE TUNNEL MANAGEMENT SYSTEM v2"
    new_mgmt_pos = content.find(new_mgmt_marker)

    if edge_tunnel_pos == -1 or new_mgmt_pos == -1:
        print(f"ERROR: Could not find markers. edge_tunnel_pos={edge_tunnel_pos}, new_mgmt_pos={new_mgmt_pos}")
        return

    # The old management code is between edge_tunnel_pos and new_mgmt_pos
    # But we need to be careful - the old code includes the Edge Tunnel entry point comment
    # and the management functions that follow it

    # Actually, looking at the original structure:
    # 1. Edge Tunnel constants (lines 1-18)
    # 2. Old management functions (lines 19-905)
    # 3. Export default (line 908)
    # 4. Edge Tunnel proxy functions (lines 1472+)

    # The build script added the new management code before the export default
    # But the old management code is still there

    # Let's find the exact boundaries
    # The old management code starts with "const Version = " and ends just before export default

    # Find the first management function (mgmtValidateUUID)
    old_mgmt_start = content.find("async function mgmtValidateUUID")
    if old_mgmt_start == -1:
        print("ERROR: Could not find old mgmtValidateUUID")
        return

    # Find the end of the old management code (just before export default)
    export_default_pos = content.find("export default {")
    if export_default_pos == -1:
        print("ERROR: Could not find export default")
        return

    # The old management code is from old_mgmt_start to export_default_pos
    # But we need to keep the Edge Tunnel entry point comment

    # Actually, let's be more precise
    # The old management functions are:
    # - mgmtValidateUUID
    # - mgmtTrackBandwidth
    # - mgmtGenerateUUID
    # - mgmtCorsHeaders
    # - mgmtJsonResponse
    # - mgmtHandleLogin
    # - mgmtVerifyAuth
    # - mgmtGetStats
    # - mgmtGetUsers
    # - mgmtCreateUser
    # - mgmtDeleteUser
    # - mgmtGetUserStatus
    # - mgmtTrackBandwidthAPI
    # - mgmtGenerateSubscriptionUrl
    # - mgmtTestConnection
    # - mgmtGetUserConfigs
    # - mgmtAdminHTML
    # - mgmtStatusHTML
    # - mgmtHandleRequest
    # - activeUUIDsCache, activeUUIDsCacheTime, ACTIVE_UUID_CACHE_TTL
    # - 获取活跃UUID列表
    # - simpleHash

    # Let's find the start of the old management section
    # It starts after the Edge Tunnel entry point comment
    old_section_start = content.find("\n// ============================================\n// EDGE TUNNEL MANAGEMENT SYSTEM\n// Professional UUID Management & Admin Panel")
    if old_section_start == -1:
        # Try alternative
        old_section_start = content.find("\n// --- Management Constants ---")
        if old_section_start == -1:
            print("ERROR: Could not find old management section start")
            return

    # Find where the old management section ends
    # It should end just before the new management section or the export default
    # Let's find the last old management function

    # The old management functions end with mgmtHandleRequest
    # Find the end of mgmtHandleRequest
    old_mgmt_handle_end = content.find("\n\n\n// ============================================\n// EDGE TUNNEL MANAGEMENT SYSTEM v2")
    if old_mgmt_handle_end == -1:
        # Try finding the new management marker
        old_mgmt_handle_end = content.find(new_mgmt_marker)
        if old_mgmt_handle_end == -1:
            print("ERROR: Could not find end of old management section")
            return

    # Remove the old management section
    new_content = content[:old_section_start] + content[old_mgmt_handle_end:]

    # Now we need to remove the duplicate functions from the new management section
    # The new management section has these functions that also exist in the old code:
    # - activeUUIDsCache, activeUUIDsCacheTime, ACTIVE_UUID_CACHE_TTL
    # - 获取活跃UUID列表
    # - simpleHash

    # Find and remove these from the new management section
    # They should be in the management.js part

    # Remove activeUUIDsCache declarations from the new management code
    # (they're now at the top of the new management section)
    new_content = re.sub(
        r'let activeUUIDsCache = null;\nlet activeUUIDsCacheTime = 0;\nconst ACTIVE_UUID_CACHE_TTL = 60 \* 1000;.*?async function 获取活跃UUID列表\(env\) \{.*?\n\}',
        '',
        new_content,
        flags=re.DOTALL
    )

    # Remove simpleHash function from the new management code
    # (it's duplicated)
    # Find the last simpleHash function and remove it
    # Keep the first one (in the new management section)

    # Write the fixed content
    with open('src/edge-tunnel-managed.js', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Fixed! Removed old management section. New size: {len(new_content)} bytes")

if __name__ == '__main__':
    fix()
