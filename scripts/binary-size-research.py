#!/usr/bin/env python3
"""Measure fastctx ELF size and summarize Rust code-size experiments.

Use before stripping for symbol attribution. The stripped file, gzip size,
ELF sections and approximate named-symbol categories are measured separately.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path


def call(*args: str) -> str:
    return subprocess.check_output(args, text=True, errors="replace")


def mib(n: int) -> str:
    return f"{n / 1048576:.2f}"


def sections(path: Path) -> dict[str, int]:
    output = call("size", "--format=sysv", "--radix=10", str(path))
    result: dict[str, int] = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(\.\S+)\s+(\d+)\s+\d+\s*$", line)
        if match:
            result[match.group(1)] = int(match.group(2))
    if ".text" not in result:
        raise RuntimeError("size did not find an ELF .text section")
    return result


def group(name: str) -> str:
    if "ContentDeserializer" in name or "ContentVisitor" in name:
        return "serde ContentDeserializer/ContentVisitor"
    if "drop_in_place" in name:
        return "core::ptr::drop_in_place"
    if "fastctx_node::" in name:
        return "fastctx_node"
    if "fastctx_types::" in name:
        return "fastctx_types"
    if "fastctx_pdf::" in name or "pdf_oxide::" in name or "hayro" in name:
        return "PDF"
    if "fastctx_office::" in name or "office_oxide::" in name:
        return "Office"
    if "tokio::" in name:
        return "tokio"
    if "serde" in name:
        return "other serde"
    if "icu_" in name:
        return "ICU"
    if "fastctx_" in name or "fastctx::" in name:
        return "other fastctx"
    return "other / unattributed"


def symbol_report(path: Path, destination: Path) -> dict:
    # nm -C demangles Rust symbols on the runner's GNU binutils.
    symbols = call("nm", "-S", "--size-sort", "-C", "--defined-only", str(path))
    regex = re.compile(r"^[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+([tTwW])\s+(.+)$")
    categories: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    named: list[tuple[int, str, str]] = []
    for line in symbols.splitlines():
        match = regex.match(line.strip())
        if not match:
            continue
        size = int(match.group(1), 16)
        if size == 0:
            continue
        name = match.group(3)
        category = group(name)
        categories[category][0] += size
        categories[category][1] += 1
        named.append((size, category, name))
    if not named:
        raise RuntimeError("No Rust code symbols found; expected an unstripped Release binary")
    named.sort(reverse=True)
    with (destination / "symbol-groups.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["category", "symbol_bytes_approx", "count"])
        for key, (size, count) in sorted(categories.items(), key=lambda item: -item[1][0]):
            writer.writerow([key, size, count])
    (destination / "top-functions.txt").write_text(
        "\n".join(f"{mib(size):>9} MiB  {cat:<38} {name}" for size, cat, name in named[:150]) + "\n"
    )
    return {
        "symbol_count": len(named),
        "symbol_bytes_total_approx": sum(t[0] for t in named),
        "groups": {k: {"bytes_approx": v[0], "count": v[1]}
                   for k, v in sorted(categories.items(), key=lambda item: -item[1][0])},
    }


def analyze(args: argparse.Namespace) -> None:
    target = Path(args.binary).resolve()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    raw_sections = sections(target)
    (output / "readelf-sections.txt").write_text(call("readelf", "-W", "-S", str(target)))
    syms = symbol_report(target, output)

    stripped = output / "fastctx.stripped"
    subprocess.run(["zig", "objcopy", "--strip-all", str(target), str(stripped)], check=True)
    stripped_sections = sections(stripped)
    (output / "readelf-sections-stripped.txt").write_text(call("readelf", "-W", "-S", str(stripped)))
    with stripped.open("rb") as source, (output / "fastctx.stripped.gz").open("wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, compresslevel=6, mtime=0) as stream:
            shutil.copyfileobj(source, stream, 1024 * 1024)

    report = {
        "variant": args.variant,
        "source_sha": call("git", "rev-parse", "HEAD").strip(),
        "rustc": call("rustc", "+1.92.0", "--version").strip(),
        "profile": {
            "lto": os.environ.get("CARGO_PROFILE_RELEASE_LTO", ""),
            "codegen_units": os.environ.get("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", ""),
            "opt_level": os.environ.get("CARGO_PROFILE_RELEASE_OPT_LEVEL", ""),
            "debug": os.environ.get("CARGO_PROFILE_RELEASE_DEBUG", ""),
        },
        "unstripped_bytes": target.stat().st_size,
        "stripped_bytes": stripped.stat().st_size,
        "gzip6_bytes": (output / "fastctx.stripped.gz").stat().st_size,
        "sections": raw_sections,
        "stripped_sections": stripped_sections,
        "symbols": syms,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    # Preserve only reports in Actions artifacts, not the 200+ MiB executable.
    stripped.unlink()
    (output / "fastctx.stripped.gz").unlink()
    print(f"{args.variant}: unstripped={mib(report['unstripped_bytes'])} MiB, "
          f"stripped={mib(report['stripped_bytes'])} MiB, gzip={mib(report['gzip6_bytes'])} MiB, "
          f"text={mib(raw_sections['.text'])} MiB")


def compare(args: argparse.Namespace) -> None:
    reports = {}
    for path in Path(args.reports).rglob("report.json"):
        report = json.loads(path.read_text())
        reports[report["variant"]] = report
    if not reports:
        raise RuntimeError("No successful build reports were downloaded")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    rows = ["| Variant | Unstripped MiB | Stripped MiB | gzip -6 MiB | .text MiB | gzip vs baseline |",
            "|:--|--:|--:|--:|--:|--:|"]
    csv_rows = []
    baseline = reports.get("baseline")
    for key in ["baseline", "thin", "fat", "thin-size"]:
        if key not in reports:
            rows.append(f"| {key} | failed / unavailable | — | — | — | — |")
            continue
        r = reports[key]
        pct = f"{(r['gzip6_bytes'] / baseline['gzip6_bytes'] - 1) * 100:+.1f}%" if baseline else "n/a"
        rows.append(f"| {key} | {mib(r['unstripped_bytes'])} | {mib(r['stripped_bytes'])} | "
                    f"{mib(r['gzip6_bytes'])} | {mib(r['sections']['.text'])} | {pct} |")
        csv_rows.append({"variant": key, "unstripped_bytes": r["unstripped_bytes"],
                         "stripped_bytes": r["stripped_bytes"], "gzip6_bytes": r["gzip6_bytes"],
                         "text_bytes": r["sections"][".text"]})
    markdown = (
        "## fastctx binary-size study (Linux x86_64 musl)\n\n"
        f"Commit: {next(iter(reports.values()))['source_sha']}\n\n" +
        "\n".join(rows) +
        "\n\nThese are size-only experiments: no runtime or correctness benchmark beyond "
        "fastctx --version and bundled-file checks. The ELF symbol categories in each "
        "artifact are approximate and are not a substitute for a full link map.\n"
    )
    (output / "comparison.md").write_text(markdown)
    (output / "comparison.json").write_text(json.dumps(reports, indent=2) + "\n")
    with (output / "comparison.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["variant", "unstripped_bytes", "stripped_bytes",
                                               "gzip6_bytes", "text_bytes"])
        writer.writeheader()
        writer.writerows(csv_rows)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(markdown)
    print(markdown)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("--variant", required=True)
    a.add_argument("--binary", required=True)
    a.add_argument("--output", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--reports", required=True)
    c.add_argument("--output", required=True)
    args = parser.parse_args()
    globals()[args.command](args)


if __name__ == "__main__":
    main()
