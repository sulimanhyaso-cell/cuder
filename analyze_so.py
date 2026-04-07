from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile


def extract_ascii_strings(buf: bytes, minlen: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in buf:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur.clear()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    d = OrderedDict.fromkeys(items)
    return list(d.keys())


def main() -> None:
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "libe598.so"
    with open(path, "rb") as f:
        elf = ELFFile(f)

        ei_class = elf["e_ident"]["EI_CLASS"]
        ei_data = elf["e_ident"]["EI_DATA"]
        machine = elf["e_machine"]
        entry = elf["e_entry"]
        print(f"ELF: {ei_class} {ei_data} machine={machine}")
        print(f"Entry: 0x{entry:x}")
        print(f"Sections: {elf.num_sections()}")

        sec_names = [s.name for s in elf.iter_sections()]
        for name in [".dynsym", ".dynstr", ".rodata", ".text", ".data", ".bss"]:
            print(f"has {name}: {name in sec_names}")

        needed: list[str] = []
        rpath: str | None = None
        runpath: str | None = None
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif tag.entry.d_tag == "DT_RPATH":
                        rpath = tag.rpath
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        runpath = tag.runpath

        print(f"DT_NEEDED ({len(needed)}): {needed}")
        if rpath:
            print(f"RPATH: {rpath}")
        if runpath:
            print(f"RUNPATH: {runpath}")

        # Collect printable strings from common sections (best-effort)
        strings: list[str] = []
        for secname in [".rodata", ".dynstr", ".strtab"]:
            sec = elf.get_section_by_name(secname)
            if sec is None:
                continue
            strings.extend(extract_ascii_strings(sec.data(), 4))
        strings = dedupe_preserve_order(strings)

        keywords = [
            "FaceTec",
            "facetec",
            "Zoom",
            "ZoOm",
            "ZOOM",
            "3d",
            "3D",
            "liveness3d",
            "liveness",
            "liveliness",
            "blink",
            "micro",
            "parallax",
            "pose",
            "yaw",
            "pitch",
            "roll",
            "landmark",
            "occlusion",
            "glare",
            "reflection",
            "screen",
            "replay",
            "print",
            "mask",
            "deepfake",
            "attack",
            "spoof",
            "spoofing",
            "gyro",
            "gyroscope",
            "accelerometer",
            "inertial",
            "IMU",
            "Tab3",
            "tab3",
            "decision",
            "score",
            "challenge",
            "texture",
            "depth",
            "motion",
            "frame",
            "quality",
            "upload",
            "session",
            "audit",
            "reason",
            "code",
            "result",
            "status",
            "fail",
            "pass",
        ]

        hits: dict[str, list[str]] = {k: [] for k in keywords}
        for s in strings:
            low = s.lower()
            for k in keywords:
                if k.lower() in low:
                    hits[k].append(s)

        total_hits = sum(len(v) for v in hits.values())
        print(f"Keyword string hits total: {total_hits}")
        for k, v in hits.items():
            if not v:
                continue
            print(f"\n== {k} ({len(v)})")
            for line in v[:50]:
                print(line)

        ds = elf.get_section_by_name(".dynsym")
        if ds is None:
            print("\nNo .dynsym section found.")
            return

        sym_hits: list[str] = []
        needles = [
            "facetec",
            "zoom",
            "live",
            "liveness",
            "gyro",
            "accel",
            "imu",
            "tab",
            "decision",
            "spoof",
            "blink",
            "parallax",
            "motion",
            "frame",
            "quality",
            "session",
            "audit",
        ]
        for sym in ds.iter_symbols():
            n = sym.name
            if not n:
                continue
            ln = n.lower()
            if any(w in ln for w in needles):
                sym_hits.append(n)

        print(f"\nDynamic symbol keyword hits: {len(sym_hits)}")
        for n in sym_hits[:200]:
            print(n)


if __name__ == "__main__":
    main()

