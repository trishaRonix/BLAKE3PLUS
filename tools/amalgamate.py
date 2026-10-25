#!/usr/bin/env python3
"""
Amalgamation script for BLAKE3PLUS.
Combines C sources into a single portable C translation unit (blake3plus_all.c)
and header for zero-friction vendoring and single-file inclusion.
"""

import os
import sys

HEADER = """/*
 * BLAKE3PLUS Amalgamated Source Distribution
 *
 * This file combines the portable core implementation of BLAKE3 and
 * BLAKE3PLUS multi-threading, cgroup detection, and memory protection
 * into a single C translation unit.
 *
 * SIMD assembly files (.S) may still be compiled alongside if desired,
 * or this file can be built with standard C flags (-O3 -pthread).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
"""

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
C_DIR = os.path.join(PROJECT_ROOT, "c")
OUT_C = os.path.join(C_DIR, "blake3plus_all.c")

SOURCES = [
    os.path.join(C_DIR, "blake3_impl.h"),
    os.path.join(C_DIR, "blake3_portable.c"),
    os.path.join(C_DIR, "blake3_dispatch.c"),
    os.path.join(C_DIR, "blake3.c"),
    os.path.join(C_DIR, "blake3plus.c"),
]

def main():
    print(f"[+] Generating {OUT_C}...")
    lines = [HEADER, "\n#define BLAKE3PLUS_AMALGAMATED 1\n\n"]
    
    seen_includes = set()
    local_headers = {"blake3.h", "blake3_impl.h", "blake3plus.h"}

    for src_path in SOURCES:
        if not os.path.exists(src_path):
            print(f"Error: {src_path} not found", file=sys.stderr)
            sys.exit(1)
            
        rel_path = os.path.relpath(src_path, PROJECT_ROOT)
        lines.append(f"\n/* --- Begin: {rel_path} --- */\n")
        
        with open(src_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "#define _GNU_SOURCE":
                    continue
                # Deduplicate standard system includes
                if stripped.startswith("#include <") and stripped.endswith(">"):
                    if stripped in seen_includes:
                        continue
                    seen_includes.add(stripped)
                    lines.append(line)
                elif stripped.startswith('#include "') and stripped.endswith('"'):
                    hdr = stripped.split('"')[1]
                    if hdr in local_headers:
                        # Keep blake3plus.h and blake3.h at top if needed or include once
                        if stripped in seen_includes:
                            continue
                        seen_includes.add(stripped)
                        lines.append(line)
                    else:
                        lines.append(line)
                else:
                    lines.append(line)
        lines.append(f"\n/* --- End: {rel_path} --- */\n")

    with open(OUT_C, "w", encoding="utf-8") as out:
        out.writelines(lines)

    size = os.path.getsize(OUT_C)
    print(f"[+] Successfully generated {OUT_C} ({size} bytes).")

if __name__ == "__main__":
    main()
