#!/usr/bin/env python3
"""
Build script for Edge Manager
Integrates new management system with existing Edge Tunnel code
"""

import re
import sys

def build():
    # Read the original file
    with open('src/edge-tunnel-managed.js', 'r', encoding='utf-8-sig') as f:
        original = f.read()

    # Read the new management module
    with open('src/management.js', 'r', encoding='utf-8') as f:
        management = f.read()

    # Read the cron handler
    with open('src/cron.js', 'r', encoding='utf-8') as f:
        cron = f.read()

    # Read the migration module
    with open('src/migrations.js', 'r', encoding='utf-8') as f:
        migrations = f.read()

    # Find the management section boundaries
    # The management code starts after the main constants and before the main entry point
    # Look for the marker comments
    management_start = original.find('// ============================================\n// EDGE TUNNEL MANAGEMENT SYSTEM')
    if management_start == -1:
        print("ERROR: Could not find management system start marker")
        sys.exit(1)

    # Find where the management HTML functions end and the main entry point begins
    # Look for the export default block
    export_default = original.find('export default {')
    if export_default == -1:
        print("ERROR: Could not find export default block")
        sys.exit(1)

    # Find the last management function before export default
    # We need to find where mgmtHandleRequest ends
    mgmt_handle_end = original.find('\n\n// --- Management Route Handler ---', management_start)
    if mgmt_handle_end == -1:
        # Try alternative marker
        mgmt_handle_end = original.find('\nasync function mgmtHandleRequest', management_start)

    # Find the end of mgmtHandleRequest function
    # Look for the next major section after it
    next_section = original.find('\n\n// --- Status Panel HTML ---', management_start)
    if next_section == -1:
        next_section = original.find('\n\nfunction mgmtStatusHTML', management_start)

    # Actually, let's be more precise
    # The management section runs from MANAGEMENT_SYSTEM marker to just before export default
    # But we need to keep the Edge Tunnel functions that come after

    # Better approach: find all mgmt* functions and replace them
    # The mgmt functions are from line ~29 to ~905

    # Find the exact boundaries
    # Start: after the Edge Tunnel constants (around line 18)
    # End: just before export default (around line 908)

    # Let's find the exact start - after the 特征码字典 section
    edge_tunnel_end = original.find("///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////")
    if edge_tunnel_end == -1:
        print("ERROR: Could not find Edge Tunnel entry point marker")
        sys.exit(1)

    # Find the actual start of management code
    mgmt_start_marker = '// ============================================\n// EDGE TUNNEL MANAGEMENT SYSTEM'
    mgmt_code_start = original.find(mgmt_start_marker)

    if mgmt_code_start == -1:
        print("ERROR: Could not find management code start")
        sys.exit(1)

    # Find where the old management code ends (just before export default)
    export_marker = '\nexport default {'
    export_pos = original.find(export_marker)

    if export_pos == -1:
        print("ERROR: Could not find export default")
        sys.exit(1)

    # Extract the three parts:
    # 1. Edge Tunnel code (before management)
    edge_tunnel_part = original[:mgmt_code_start]

    # 2. Export default and everything after
    export_part = original[export_pos:]

    # 3. Build the new management section
    new_management = f"""
// ============================================
// EDGE TUNNEL MANAGEMENT SYSTEM v2
// Professional VPN Management Panel
// ============================================

// --- Inline management functions (from management.js) ---
{management}

// --- Cron Handler (from cron.js) ---
{cron}

// --- Migration System (from migrations.js) ---
{migrations}

"""

    # Combine everything
    final = edge_tunnel_part + new_management + '\n' + export_part

    # Now we need to update the export default to include the scheduled handler
    # and fix the imports

    # Remove import statements (they won't work in a single file)
    final = re.sub(r"import \{[^}]+\} from '\./migrations\.js';", '', final)
    final = re.sub(r"import \{[^}]+\} from '\./management\.js';", '', final)
    final = re.sub(r"import \{[^}]+\} from '\./cron\.js';", '', final)

    # Update the mgmtHandleRequest call to use the new signature
    # Old: const mgmtResponse = await mgmtHandleRequest(request, env);
    # New: const mgmtResponse = await mgmtHandleRequest(request, env, ctx);
    final = final.replace(
        'const mgmtResponse = await mgmtHandleRequest(request, env);',
        'const mgmtResponse = await mgmtHandleRequest(request, env, ctx);'
    )

    # Add scheduled handler to export default
    # Find the closing of the fetch handler and add scheduled handler
    # Look for the end of the fetch handler
    fetch_end_marker = '};\n}};'
    if fetch_end_marker in final:
        final = final.replace(fetch_end_marker, '''};
	},

	// Cron Handler - Runs on schedule
	async scheduled(event, env, ctx) {
		ctx.waitUntil(handleCron(env));
	}
};''', 1)

    # Also try alternative closing pattern
    if 'async scheduled' not in final:
        # Find the last closing of the fetch handler
        last_brace = final.rfind('};')
        if last_brace > 0:
            # Insert scheduled handler before the last closing
            final = final[:last_brace] + '''
	},

	// Cron Handler - Runs on schedule
	async scheduled(event, env, ctx) {
		ctx.waitUntil(handleCron(env));
	}''' + final[last_brace:]

    # Write the output
    with open('src/edge-tunnel-managed.js', 'w', encoding='utf-8') as f:
        f.write(final)

    print(f"Build complete! Output: {len(final)} bytes")

if __name__ == '__main__':
    build()
