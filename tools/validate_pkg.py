#!/usr/bin/env python3
"""Static checks on the fuxiPkg tree before it reaches CI.

Verifies:
  1. every local INF referenced by fuxi.dsc, fuxi.fdf and Include/*.inc exists;
  2. every !include target exists;
  3. each .inf has the required [Defines] keys;
  4. MemoryMapLib regions are valid and non-overlapping (table order is preserved);
  5. no two .inf files share a FILE_GUID.
"""
import os
import re
import sys
import tomllib

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
PKG = os.path.join(ROOT, "Platforms", "Xiaomi", "fuxiPkg")

errors = []
warnings = []


def read(p):
    return open(p, encoding="utf-8", errors="replace").read()


def check_memory_map():
    mm = read(os.path.join(PKG, "Library", "MemoryMapLib", "MemoryMapLib.c"))
    mm = re.sub(r"/\*.*?\*/|//[^\n]*", "", mm, flags=re.S)
    table = re.search(r"gMemoryDescriptor\[\]\s*=\s*\{(.*?)\};", mm, re.S)
    if not table:
        errors.append("memory descriptor table missing or unparseable")
        return
    rows = re.findall(r"\{([^{}]*)\}", table.group(1))
    residue = re.sub(r"\{[^{}]*\}\s*,?", "", table.group(1)).strip()
    if residue:
        errors.append("unparsed content in memory descriptor table")
    regions = []
    for row in rows:
        fields = [v.strip() for v in row.split(",")]
        if len(fields) != 8 or not re.fullmatch(r'"[^"\n]+"', fields[0]):
            errors.append(f"unparseable memory descriptor: {row.strip()}")
            continue
        try:
            base, size = (int(v, 0) for v in fields[1:3])
        except ValueError:
            errors.append(f"non-literal memory range: {fields[0]}")
            continue
        name = fields[0][1:-1]
        if size <= 0 or base < 0 or base + size > 2**64:
            errors.append(f"invalid memory range: {name} {base:#x}+{size:#x}")
        if base % 4096 or size % 4096:
            errors.append(f"memory range not 4 KiB aligned: {name}")
        regions.append((base, size, name, *fields[3:]))

    if not regions or len(regions) > 128:
        errors.append(f"invalid memory descriptor count: {len(regions)}")
        return
    # SEC needs the heap first before MemoryPeim sorts the table in place.
    if regions[0][2] != "DXE Heap":
        errors.append("DXE Heap must be the first memory descriptor")
    ordered = sorted(regions)
    previous = ordered[0]
    for current in ordered[1:]:
        if previous[0] + previous[1] > current[0]:
            errors.append(f"overlap: {previous[2]} {previous[0]:#x}+{previous[1]:#x} vs {current[2]} {current[0]:#x}")
        if current[0] + current[1] > previous[0] + previous[1]:
            previous = current
    print(f"memory regions: {len(regions)}; covered: {sum(r[1] for r in regions) / 2**20:.0f} MiB")

    def named(name):
        matches = [r for r in regions if r[2] == name]
        if len(matches) != 1:
            errors.append(f"expected one {name} region, found {len(matches)}")
            return None
        return matches[0]

    try:
        with open(os.path.join(ROOT, "Resources", "Configs", "fuxi.toml"), "rb") as f:
            config = tomllib.load(f)
        fd = named("UEFI FD")
        if fd and (config["uefi_fd"]["base"], config["uefi_fd"]["size"]) != fd[:2]:
            errors.append("fuxi.toml FD base/size disagree with MemoryMapLib UEFI FD")
        if config["boot_image"]["header_version"] != 3:
            errors.append("fuxi requires Android boot image header version 3")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"invalid fuxi.toml: {exc}")

    dsc = read(os.path.join(PKG, "fuxi.dsc"))
    def pcd(name):
        match = re.search(r"^\s*\w+\." + name + r"\|\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*(?:#.*)?$", dsc, re.M)
        if not match:
            errors.append(f"missing numeric PCD: {name}")
            return 0
        return int(match.group(1), 0)

    stack = named("UEFI Stack")
    stack_base, stack_size = pcd("PcdCPUCoresStackBase"), pcd("PcdCPUCorePrimaryStackSize")
    if stack and (stack_size <= 0 or stack_base < stack[0] or stack_base + stack_size > stack[0] + stack[1]):
        errors.append("CPU stack PCD range exceeds UEFI Stack reservation")
    display = named("Display Reserved")
    width, height, depth = (pcd("PcdFrameBuffer" + n) for n in ("Width", "Height", "ColorDepth"))
    if display and (width <= 0 or height <= 0 or depth != 32 or width * height * 4 > display[1]):
        errors.append("framebuffer geometry exceeds Display Reserved or has unsupported depth")

    keys = read(os.path.join(PKG, "Drivers", "FuxiKeyInputDxe", "FuxiKeyInputDxe.c"))
    # FuxiSpmiKeys.h permits up to 1024 APIDs: the core's APID map ends
    # at 0x3000, and the EE0 observer bank spans 1024 * 0x20 bytes.
    # Cover every possible register access, not only the first word.
    for key, span in (("SPMI_CORE_BASE", 0x3000), ("SPMI_OBSRVR_BASE", 0x8000)):
        match = re.search(r"^#define\s+" + key + r"\s+(0x[0-9A-Fa-f]+)", keys, re.M)
        if not match:
            errors.append(f"missing key driver register base: {key}")
            continue
        address = int(match.group(1), 16)
        if not any(b <= address and address + span <= b + s and hob != "HobOnlyNoCacheSetting" and resource == "MMAP_IO"
                   for b, s, _, hob, resource, *_ in regions):
            errors.append(f"{key} {address:#x} has no mapped MMIO descriptor covering {span:#x} bytes")


def main():
    # ---- 1/2. references ----
    sources = ["fuxi.dsc", "fuxi.fdf"] + [
        os.path.join("Include", f) for f in os.listdir(os.path.join(PKG, "Include"))
    ]
    refs = set()
    includes = set()
    for rel in sources:
        p = os.path.join(PKG, rel)
        if not os.path.exists(p):
            errors.append(f"missing source file: {rel}")
            continue
        text = read(p)
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#"):
                continue
            m = re.match(r"!include\s+(\S+)", s)
            if m:
                includes.add(m.group(1))
                continue
            m = re.search(r"(fuxiPkg/[^\s|{}]+\.inf)\b", s)
            if m:
                refs.add(m.group(1))
            m = re.match(r"MemoryMapLib\|(fuxiPkg/\S+)", s)
            if m:
                refs.add(m.group(1))
            m = re.match(r"ConfigurationMapLib\|(fuxiPkg/\S+)", s)
            if m:
                refs.add(m.group(1))

    for inc in sorted(includes):
        # only package-relative includes can be checked here; KailuaPkg/,
        # QcomPkg/, SiliciumPkg/ come from the Mu-Silicium checkout
        if not inc.startswith("Include/"):
            continue
        cand = os.path.join(PKG, inc)
        if not os.path.exists(cand):
            errors.append(f"!include target missing: {inc}")

    for rel in sorted(refs):
        # fuxiPkg/... is relative to the package dir's parent
        cand = os.path.join(ROOT, "Platforms", "Xiaomi", rel)
        if not os.path.exists(cand):
            errors.append(f"referenced INF missing: {rel}")
    print(f"references checked: {len(refs)} INF, {len(includes)} include")

    # ---- 3/5. inf sanity ----
    guids = {}
    infs = []
    for dirpath, _, files in os.walk(PKG):
        for f in files:
            if f.endswith(".inf"):
                infs.append(os.path.join(dirpath, f))
    for p in infs:
        t = read(p)
        for key in ("BASE_NAME", "FILE_GUID", "MODULE_TYPE"):
            if key not in t:
                errors.append(f"{os.path.relpath(p, PKG)}: missing {key}")
        m = re.search(r"FILE_GUID\s*=\s*([0-9A-Fa-f-]{36})", t)
        if m:
            g = m.group(1).upper()
            if g in guids:
                errors.append(f"duplicate FILE_GUID {g}: {guids[g]} and {os.path.relpath(p, PKG)}")
            guids[g] = os.path.relpath(p, PKG)
        m = re.search(r"ENTRY_POINT\s*=\s*(\w+)", t)
        c = p[:-4] + ".c"
        if m and os.path.exists(c):
            body = read(c)
            if m.group(1) not in body:
                errors.append(f"{os.path.basename(c)}: entry point {m.group(1)} not found in source")
    print(f"inf files checked: {len(infs)}")

    # ---- 4. memory map and build layout ----
    check_memory_map()

    for w in warnings:
        print("WARN ", w)
    if errors:
        for e in errors:
            print("ERROR", e)
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
