#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path
from collections import Counter

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "languages",
    "assets",
    "dist",
    "build",
    "tests",
    "test",
}

ENTRYPOINT_PATTERNS = {
    "ajax_unauth": re.compile(r"""wp_ajax_nopriv_([A-Za-z0-9_\-]+)"""),
    "ajax_auth": re.compile(r"""wp_ajax_(?!nopriv_)([A-Za-z0-9_\-]+)"""),
    "admin_post_unauth": re.compile(r"""admin_post_nopriv_([A-Za-z0-9_\-]+)"""),
    "admin_post_auth": re.compile(r"""admin_post_(?!nopriv_)([A-Za-z0-9_\-]+)"""),
    "rest_route": re.compile(r"""\bregister_rest_route\s*\("""),
    "shortcode": re.compile(r"""\badd_shortcode\s*\("""),
}

SINK_PATTERNS = {
    "option_write": [
        re.compile(r"\bupdate_option\s*\("),
        re.compile(r"\badd_option\s*\("),
        re.compile(r"\bdelete_option\s*\("),
        re.compile(r"\bupdate_site_option\s*\("),
        re.compile(r"\badd_site_option\s*\("),
        re.compile(r"\bdelete_site_option\s*\("),
    ],

    "user_privilege": [
        re.compile(r"\bwp_insert_user\s*\("),
        re.compile(r"\bwp_update_user\s*\("),
        re.compile(r"->set_role\s*\("),
        re.compile(r"->add_role\s*\("),
        re.compile(r"->add_cap\s*\("),
        re.compile(r"\bwp_create_user\s*\("),
    ],

    "sql": [
        re.compile(r"\$wpdb\s*->\s*query\s*\("),
        re.compile(r"\$wpdb\s*->\s*get_results\s*\("),
        re.compile(r"\$wpdb\s*->\s*get_row\s*\("),
        re.compile(r"\$wpdb\s*->\s*get_var\s*\("),
        re.compile(r"\$wpdb\s*->\s*get_col\s*\("),
    ],

    "file_write_upload": [
        re.compile(r"\bfile_put_contents\s*\("),
        re.compile(r"\bfopen\s*\("),
        re.compile(r"\bmove_uploaded_file\s*\("),
        re.compile(r"\bwp_handle_upload\s*\("),
        re.compile(r"\bcopy\s*\("),
        re.compile(r"\brename\s*\("),
    ],

    "file_read": [
        re.compile(r"\breadfile\s*\("),
        re.compile(r"\bfile_get_contents\s*\("),
        re.compile(r"\bfopen\s*\("),
        re.compile(r"\bfile\s*\("),
    ],

    "file_delete": [
        re.compile(r"\bunlink\s*\("),
        re.compile(r"\brmdir\s*\("),
    ],

    "include": [
        re.compile(r"\binclude\s*(?:\(|\s)"),
        re.compile(r"\binclude_once\s*(?:\(|\s)"),
        re.compile(r"\brequire\s*(?:\(|\s)"),
        re.compile(r"\brequire_once\s*(?:\(|\s)"),
    ],

    "command_execution": [
        re.compile(r"\bexec\s*\("),
        re.compile(r"\bsystem\s*\("),
        re.compile(r"\bshell_exec\s*\("),
        re.compile(r"\bpassthru\s*\("),
        re.compile(r"\bproc_open\s*\("),
        re.compile(r"\bpopen\s*\("),
    ],

    "deserialization": [
        re.compile(r"\bunserialize\s*\("),
        re.compile(r"\bmaybe_unserialize\s*\("),
    ],
}

CONTROL_PATTERNS = {
    "capability": [
        re.compile(r"\bcurrent_user_can\s*\("),
        re.compile(r"\buser_can\s*\("),
    ],

    "nonce": [
        re.compile(r"\bcheck_ajax_referer\s*\("),
        re.compile(r"\bwp_verify_nonce\s*\("),
        re.compile(r"\bcheck_admin_referer\s*\("),
    ],

    "sql_parameterization": [
        re.compile(r"\$wpdb\s*->\s*prepare\s*\("),
    ],

    "upload_validation": [
        re.compile(r"\bwp_check_filetype\s*\("),
        re.compile(r"\bwp_check_filetype_and_ext\s*\("),
        re.compile(r"\bwp_handle_upload_prefilter\b"),
    ],

    "path_validation": [
        re.compile(r"\brealpath\s*\("),
        re.compile(r"\bwp_normalize_path\s*\("),
    ],

    "escaping": [
        re.compile(r"\besc_html\s*\("),
        re.compile(r"\besc_attr\s*\("),
        re.compile(r"\besc_url\s*\("),
        re.compile(r"\bwp_kses\s*\("),
        re.compile(r"\bwp_kses_post\s*\("),
    ],
}

SOURCE_PATTERNS = {
    "GET": re.compile(r"\$_GET\b"),
    "POST": re.compile(r"\$_POST\b"),
    "REQUEST": re.compile(r"\$_REQUEST\b"),
    "FILES": re.compile(r"\$_FILES\b"),
    "COOKIE": re.compile(r"\$_COOKIE\b"),
    "SERVER": re.compile(r"\$_SERVER\b"),
    "raw_body": re.compile(r"php://input"),
}

VERSION_PATTERNS = [
    re.compile(r"^\s*\*\s*Version:\s*([^\r\n]+)", re.I | re.M),
    re.compile(r"""define\s*\(\s*['"][A-Za-z0-9_]*VERSION[A-Za-z0-9_]*['"]\s*,\s*['"]([^'"]+)""", re.I),
]


def should_skip(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True

    return any(part.lower() in EXCLUDED_DIRS for part in rel.parts[:-1])


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def context_line(lines, line_no):
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()[:500]
    return ""


def add_matches(output, category, patterns, rel, text, lines):
    for pattern in patterns:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            output.append({
                "category": category,
                "file": rel,
                "line": line,
                "match": match.group(0)[:200],
                "context": context_line(lines, line),
            })


def detect_version(files):
    candidates = sorted(files, key=lambda p: (len(p.parts), len(str(p))))

    for path in candidates:
        text = read_text(path)
        if "Plugin Name:" not in text and "Version:" not in text:
            continue

        for pattern in VERSION_PATTERNS:
            match = pattern.search(text)
            if match:
                return {
                    "version": match.group(1).strip(),
                    "source_file": str(path),
                }

    return {
        "version": None,
        "source_file": None,
    }


def map_plugin(plugin_root: Path):
    php_files = []

    for path in plugin_root.rglob("*.php"):
        if not path.is_file():
            continue

        if should_skip(path, plugin_root):
            continue

        php_files.append(path)

    php_files.sort()

    entrypoints = []
    sinks = []
    controls = []
    sources = []

    for path in php_files:
        text = read_text(path)
        lines = text.splitlines()
        rel = str(path.relative_to(plugin_root))

        for ep_type, pattern in ENTRYPOINT_PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1

                item = {
                    "type": ep_type,
                    "file": rel,
                    "line": line,
                    "match": match.group(0)[:200],
                    "context": context_line(lines, line),
                }

                if match.lastindex:
                    item["name"] = match.group(1)

                if ep_type in {"ajax_unauth", "admin_post_unauth"}:
                    item["minimum_access"] = "unauthenticated"
                elif ep_type in {"ajax_auth", "admin_post_auth"}:
                    item["minimum_access"] = "authenticated"
                elif ep_type == "rest_route":
                    item["minimum_access"] = "unknown_until_permission_callback_analysis"

                entrypoints.append(item)

        for category, patterns in SINK_PATTERNS.items():
            add_matches(sinks, category, patterns, rel, text, lines)

        for category, patterns in CONTROL_PATTERNS.items():
            add_matches(controls, category, patterns, rel, text, lines)

        for category, pattern in SOURCE_PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1

                sources.append({
                    "category": category,
                    "file": rel,
                    "line": line,
                    "match": match.group(0),
                    "context": context_line(lines, line),
                })

    version = detect_version(php_files)

    return {
        "plugin": {
            "name": plugin_root.name,
            "path": str(plugin_root.resolve()),
            "version": version["version"],
            "version_source": version["source_file"],
        },

        "summary": {
            "php_files": len(php_files),
            "entrypoints": len(entrypoints),
            "sinks": len(sinks),
            "controls": len(controls),
            "sources": len(sources),
        },

        "php_files": [
            str(path.relative_to(plugin_root))
            for path in php_files
        ],

        "entrypoints": entrypoints,
        "sinks": sinks,
        "controls": controls,
        "sources": sources,
    }


def write_json(path: Path, data):
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Read-only WordPress plugin security surface mapper"
    )

    parser.add_argument(
        "plugin",
        help="Path to WordPress plugin directory"
    )

    parser.add_argument(
        "--output",
        help="Output directory. Defaults to /opt/codex-security/wpsec-output/<plugin>"
    )

    args = parser.parse_args()

    plugin_root = Path(args.plugin).resolve()

    if not plugin_root.exists():
        print(f"[-] Plugin path does not exist: {plugin_root}", file=sys.stderr)
        sys.exit(1)

    if not plugin_root.is_dir():
        print(f"[-] Plugin path is not a directory: {plugin_root}", file=sys.stderr)
        sys.exit(1)

    output_dir = (
        Path(args.output).resolve()
        if args.output
        else Path("/opt/codex-security/wpsec-output") / plugin_root.name
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    result = map_plugin(plugin_root)

    write_json(output_dir / "surface-map.json", result)
    write_json(output_dir / "entrypoints.json", result["entrypoints"])
    write_json(output_dir / "sinks.json", result["sinks"])
    write_json(output_dir / "controls.json", result["controls"])
    write_json(output_dir / "sources.json", result["sources"])

    print()
    print("WordPress Security Surface Map")
    print("=" * 40)
    print(f"Plugin      : {result['plugin']['name']}")
    print(f"Version     : {result['plugin']['version'] or 'unknown'}")
    print(f"PHP files   : {result['summary']['php_files']}")
    print(f"Entrypoints : {result['summary']['entrypoints']}")
    print(f"Sinks       : {result['summary']['sinks']}")
    print(f"Controls    : {result['summary']['controls']}")
    print(f"Sources     : {result['summary']['sources']}")
    print()
    print(f"Output      : {output_dir}")
    print()

    ep_counts = Counter(x["type"] for x in result["entrypoints"])
    sink_counts = Counter(x["category"] for x in result["sinks"])

    if ep_counts:
        print("Entrypoints:")
        for key, value in ep_counts.most_common():
            print(f"  {key:<25} {value}")

    if sink_counts:
        print()
        print("Sensitive sinks:")
        for key, value in sink_counts.most_common():
            print(f"  {key:<25} {value}")


if __name__ == "__main__":
    main()
