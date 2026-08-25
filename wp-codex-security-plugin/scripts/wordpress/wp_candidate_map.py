#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path
from collections import Counter, defaultdict


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


# ============================================================
# WORDPRESS SOURCES
# ============================================================

SOURCE_PATTERNS = {
    "GET": re.compile(r"\$_GET\b"),
    "POST": re.compile(r"\$_POST\b"),
    "REQUEST": re.compile(r"\$_REQUEST\b"),
    "FILES": re.compile(r"\$_FILES\b"),
    "COOKIE": re.compile(r"\$_COOKIE\b"),
    "SERVER": re.compile(r"\$_SERVER\b"),
    "raw_body": re.compile(r"php://input"),

    "rest_get_param": re.compile(
        r"->\s*get_param\s*\("
    ),
    "rest_get_params": re.compile(
        r"->\s*get_params\s*\("
    ),
    "rest_json": re.compile(
        r"->\s*get_json_params\s*\("
    ),
    "rest_files": re.compile(
        r"->\s*get_file_params\s*\("
    ),

    "filter_input": re.compile(
        r"\bfilter_input\s*\("
    ),
}


# ============================================================
# SECURITY CONTROLS
# ============================================================

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

    "sql_prepare": [
        re.compile(r"\$wpdb\s*->\s*prepare\s*\("),
    ],

    "path_validation": [
        re.compile(r"\brealpath\s*\("),
        re.compile(r"\bwp_normalize_path\s*\("),
        re.compile(r"\bbasename\s*\("),
    ],

    "upload_validation": [
        re.compile(r"\bwp_check_filetype\s*\("),
        re.compile(r"\bwp_check_filetype_and_ext\s*\("),
    ],

    "escaping": [
        re.compile(r"\besc_html\s*\("),
        re.compile(r"\besc_attr\s*\("),
        re.compile(r"\besc_url\s*\("),
        re.compile(r"\bwp_kses\s*\("),
        re.compile(r"\bwp_kses_post\s*\("),
    ],
}


# ============================================================
# HIGH-IMPACT SINKS
# ============================================================

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
        re.compile(r"\bwp_create_user\s*\("),
        re.compile(r"->\s*set_role\s*\("),
        re.compile(r"->\s*add_role\s*\("),
        re.compile(r"->\s*add_cap\s*\("),
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
        re.compile(r"\bmove_uploaded_file\s*\("),
        re.compile(r"\bwp_handle_upload\s*\("),
        re.compile(r"\bfopen\s*\("),
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


FAMILY_MAP = {
    "option_write": "arbitrary_options_update",
    "user_privilege": "privilege_escalation",
    "sql": "sql_injection",
    "file_write_upload": "arbitrary_file_write_or_upload",
    "file_read": "arbitrary_file_read",
    "file_delete": "arbitrary_file_deletion",
    "include": "lfi_or_rfi",
    "command_execution": "command_execution_or_rce",
    "deserialization": "unsafe_deserialization",
}


# ============================================================
# HELPERS
# ============================================================

def should_skip(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True

    return any(
        part.lower() in EXCLUDED_DIRS
        for part in rel.parts[:-1]
    )


def read_text(path: Path) -> str:
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except Exception:
        return ""


def line_number(text, offset):
    return text.count("\n", 0, offset) + 1


def find_matching_brace(text, open_pos):
    depth = 0
    quote = None
    escape = False

    i = open_pos

    while i < len(text):
        ch = text[i]

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None

            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1

        elif ch == "}":
            depth -= 1

            if depth == 0:
                return i

        i += 1

    return None


# ============================================================
# FUNCTION / METHOD INDEX
# ============================================================

FUNCTION_RE = re.compile(
    r"""
    (?:
        public\s+|
        protected\s+|
        private\s+|
        static\s+|
        final\s+|
        abstract\s+
    )*
    function
    \s+
    &?
    \s*
    ([A-Za-z_][A-Za-z0-9_]*)
    \s*
    \(
    """,
    re.X | re.I
)


CLASS_RE = re.compile(
    r"""
    \bclass
    \s+
    ([A-Za-z_][A-Za-z0-9_]*)
    [^{]*
    \{
    """,
    re.X | re.I
)


def build_class_ranges(text):
    ranges = []

    for match in CLASS_RE.finditer(text):
        class_name = match.group(1)

        open_pos = text.find(
            "{",
            match.start(),
            match.end()
        )

        if open_pos == -1:
            continue

        close_pos = find_matching_brace(
            text,
            open_pos
        )

        if close_pos is None:
            continue

        ranges.append({
            "name": class_name,
            "start": match.start(),
            "end": close_pos,
        })

    return ranges


def find_class_for_offset(class_ranges, offset):
    matches = [
        x for x in class_ranges
        if x["start"] <= offset <= x["end"]
    ]

    if not matches:
        return None

    matches.sort(
        key=lambda x: x["end"] - x["start"]
    )

    return matches[0]["name"]


def index_functions(plugin_root):
    index = defaultdict(list)

    php_files = sorted(
        p for p in plugin_root.rglob("*.php")
        if p.is_file()
        and not should_skip(p, plugin_root)
    )

    for path in php_files:
        text = read_text(path)

        if not text:
            continue

        class_ranges = build_class_ranges(text)

        for match in FUNCTION_RE.finditer(text):
            name = match.group(1)

            brace = text.find(
                "{",
                match.end()
            )

            if brace == -1:
                continue

            # Avoid jumping far into unrelated code
            if brace - match.end() > 1000:
                continue

            close = find_matching_brace(
                text,
                brace
            )

            if close is None:
                continue

            class_name = find_class_for_offset(
                class_ranges,
                match.start()
            )

            body = text[
                match.start():
                close + 1
            ]

            index[name.lower()].append({
                "name": name,
                "class": class_name,
                "file": str(
                    path.relative_to(plugin_root)
                ),
                "line": line_number(
                    text,
                    match.start()
                ),
                "body": body,
            })

    return index


# ============================================================
# WORDPRESS ENTRYPOINT REGISTRATION
# ============================================================

ADD_ACTION_RE = re.compile(
    r"""
    add_action
    \s*\(
    \s*
    ['"]
    (
        wp_ajax_nopriv_[^'"]+
        |
        wp_ajax_[^'"]+
        |
        admin_post_nopriv_[^'"]+
        |
        admin_post_[^'"]+
    )
    ['"]
    \s*,
    \s*
    (
        ['"][A-Za-z_][A-Za-z0-9_]*['"]
        |
        \[
            \s*\$this\s*,
            \s*['"][A-Za-z_][A-Za-z0-9_]*['"]
            \s*
        \]
        |
        array
        \s*\(
            \s*\$this\s*,
            \s*['"][A-Za-z_][A-Za-z0-9_]*['"]
            \s*
        \)
        |
        \[
            \s*['"][A-Za-z_][A-Za-z0-9_\\]*['"]
            \s*,
            \s*['"][A-Za-z_][A-Za-z0-9_]*['"]
            \s*
        \]
    )
    """,
    re.X | re.I
)


def parse_callback(expr):
    # Plain function callback
    m = re.fullmatch(
        r"""['"]([A-Za-z_][A-Za-z0-9_]*)['"]""",
        expr.strip()
    )

    if m:
        return {
            "type": "function",
            "function": m.group(1),
            "class": None,
        }

    # [$this, 'method']
    m = re.search(
        r"""\$this\s*,\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]""",
        expr
    )

    if m:
        return {
            "type": "instance_method",
            "function": m.group(1),
            "class": None,
        }

    # ['Class', 'method']
    strings = re.findall(
        r"""['"]([^'"]+)['"]""",
        expr
    )

    if len(strings) >= 2:
        return {
            "type": "static_method",
            "class": strings[-2],
            "function": strings[-1],
        }

    return None


def access_from_hook(hook):
    if hook.startswith("wp_ajax_nopriv_"):
        return "unauthenticated"

    if hook.startswith("admin_post_nopriv_"):
        return "unauthenticated"

    if hook.startswith("wp_ajax_"):
        return "authenticated"

    if hook.startswith("admin_post_"):
        return "authenticated"

    return "unknown"


def collect_action_entrypoints(plugin_root):
    result = []

    php_files = sorted(
        p for p in plugin_root.rglob("*.php")
        if p.is_file()
        and not should_skip(p, plugin_root)
    )

    for path in php_files:
        text = read_text(path)

        for match in ADD_ACTION_RE.finditer(text):
            hook = match.group(1)
            callback_expr = match.group(2)

            callback = parse_callback(
                callback_expr
            )

            if not callback:
                continue

            result.append({
                "type": (
                    "ajax"
                    if hook.startswith("wp_ajax_")
                    else "admin_post"
                ),
                "hook": hook,
                "minimum_access":
                    access_from_hook(hook),
                "callback": callback,
                "registration": {
                    "file": str(
                        path.relative_to(plugin_root)
                    ),
                    "line": line_number(
                        text,
                        match.start()
                    ),
                    "code": match.group(0)[:1000],
                }
            })

    return result


# ============================================================
# BASIC REST ROUTE CALLBACK EXTRACTION
# ============================================================

REST_START_RE = re.compile(
    r"\bregister_rest_route\s*\(",
    re.I
)


def extract_balanced_call(text, start):
    open_paren = text.find("(", start)

    if open_paren == -1:
        return None

    depth = 0
    quote = None
    escape = False

    for i in range(open_paren, len(text)):
        ch = text[i]

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue

        if ch in ("'", '"'):
            quote = ch
            continue

        if ch == "(":
            depth += 1

        elif ch == ")":
            depth -= 1

            if depth == 0:
                return text[start:i + 1]

    return None


def parse_rest_callback(call_text):
    # 'callback' => 'function_name'
    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        ['"]
        ([A-Za-z_][A-Za-z0-9_]*)
        ['"]
        """,
        call_text,
        re.X | re.I
    )

    if m:
        return {
            "type": "function",
            "function": m.group(1),
            "class": None,
        }

    # 'callback' => [$this, 'method']
    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        \[
            \s*\$this\s*,
            \s*['"]
            ([A-Za-z_][A-Za-z0-9_]*)
            ['"]
        """,
        call_text,
        re.X | re.I
    )

    if m:
        return {
            "type": "instance_method",
            "function": m.group(1),
            "class": None,
        }

    # 'callback' => ['Class', 'method']
    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        \[
            \s*['"]
            ([A-Za-z_][A-Za-z0-9_\\]*)
            ['"]
            \s*,
            \s*['"]
            ([A-Za-z_][A-Za-z0-9_]*)
            ['"]
        """,
        call_text,
        re.X | re.I
    )

    if m:
        return {
            "type": "static_method",
            "class": m.group(1),
            "function": m.group(2),
        }

    return None


def rest_access(call_text):
    if re.search(
        r"""
        ['"]permission_callback['"]
        \s*=>
        \s*
        ['"]__return_true['"]
        """,
        call_text,
        re.X | re.I
    ):
        return "unauthenticated"

    if "permission_callback" not in call_text:
        return "unknown_permission_callback"

    return "permission_callback_requires_analysis"


def collect_rest_entrypoints(plugin_root):
    result = []

    php_files = sorted(
        p for p in plugin_root.rglob("*.php")
        if p.is_file()
        and not should_skip(p, plugin_root)
    )

    for path in php_files:
        text = read_text(path)

        for match in REST_START_RE.finditer(text):
            call = extract_balanced_call(
                text,
                match.start()
            )

            if not call:
                continue

            callback = parse_rest_callback(
                call
            )

            if not callback:
                continue

            result.append({
                "type": "rest",
                "hook": "register_rest_route",
                "minimum_access":
                    rest_access(call),
                "callback": callback,
                "registration": {
                    "file": str(
                        path.relative_to(plugin_root)
                    ),
                    "line": line_number(
                        text,
                        match.start()
                    ),
                    "code": call[:3000],
                }
            })

    return result


# ============================================================
# CALLBACK RESOLUTION
# ============================================================

def resolve_callback(entrypoint, function_index):
    callback = entrypoint["callback"]

    name = callback["function"].lower()

    definitions = function_index.get(
        name,
        []
    )

    if callback.get("class"):
        wanted = callback["class"].split("\\")[-1].lower()

        filtered = [
            x for x in definitions
            if x.get("class")
            and x["class"].lower() == wanted
        ]

        if filtered:
            definitions = filtered

    return definitions


# ============================================================
# CALLBACK SECURITY ANALYSIS
# ============================================================

def detect_patterns(body, patterns):
    found = []

    for category, regexes in patterns.items():
        for regex in regexes:
            if regex.search(body):
                found.append(category)
                break

    return sorted(set(found))


def detect_sources(body):
    result = []

    for name, regex in SOURCE_PATTERNS.items():
        if regex.search(body):
            result.append(name)

    return sorted(set(result))


def score_candidate(entrypoint, sources, controls, sink):
    score = 0

    access = entrypoint["minimum_access"]

    if access == "unauthenticated":
        score += 100

    elif access == "authenticated":
        score += 60

    elif access == "unknown_permission_callback":
        score += 80

    elif access == "permission_callback_requires_analysis":
        score += 50

    if sources:
        score += 40

    if sink == "command_execution":
        score += 100

    elif sink == "user_privilege":
        score += 90

    elif sink == "file_write_upload":
        score += 80

    elif sink in {
        "file_read",
        "file_delete",
        "include"
    }:
        score += 75

    elif sink == "option_write":
        score += 70

    elif sink == "sql":
        score += 70

    elif sink == "deserialization":
        score += 60

    if "capability" not in controls:
        score += 40

    if (
        entrypoint["type"] == "ajax"
        and "nonce" in controls
        and "capability" not in controls
    ):
        # nonce != authorization
        score += 10

    if (
        sink == "sql"
        and "sql_prepare" in controls
    ):
        score -= 35

    return score


# ============================================================
# CANDIDATE GENERATION
# ============================================================

def generate_candidates(entrypoints, function_index):
    candidates = []
    unresolved = []

    candidate_id = 1

    for ep in entrypoints:
        definitions = resolve_callback(
            ep,
            function_index
        )

        if not definitions:
            unresolved.append(ep)
            continue

        for definition in definitions:
            body = definition["body"]

            sources = detect_sources(body)

            controls = detect_patterns(
                body,
                CONTROL_PATTERNS
            )

            sinks = detect_patterns(
                body,
                SINK_PATTERNS
            )

            if not sinks:
                continue

            for sink in sinks:
                score = score_candidate(
                    ep,
                    sources,
                    controls,
                    sink
                )

                candidates.append({
                    "id": f"WP-CAND-{candidate_id:04d}",

                    "family":
                        FAMILY_MAP.get(
                            sink,
                            sink
                        ),

                    "score": score,

                    "entrypoint": {
                        "type": ep["type"],
                        "hook": ep["hook"],
                        "minimum_access":
                            ep["minimum_access"],
                        "registration":
                            ep["registration"],
                    },

                    "callback": {
                        "name":
                            definition["name"],
                        "class":
                            definition["class"],
                        "file":
                            definition["file"],
                        "line":
                            definition["line"],
                    },

                    "sources": sources,
                    "controls": controls,

                    "sink_category": sink,

                    "static_observation": {
                        "has_input_source":
                            bool(sources),

                        "has_capability_check":
                            "capability"
                            in controls,

                        "has_nonce_check":
                            "nonce"
                            in controls,

                        "requires_deeper_dataflow":
                            True,
                    },

                    "code_slice":
                        definition["body"][:15000],
                })

                candidate_id += 1

    candidates.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return candidates, unresolved


# ============================================================
# OUTPUT
# ============================================================

def write_json(path, data):
    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "WordPress entrypoint-to-callback "
            "security candidate mapper"
        )
    )

    parser.add_argument(
        "plugin",
        help="WordPress plugin directory"
    )

    parser.add_argument(
        "--output",
        help="Output directory"
    )

    args = parser.parse_args()

    plugin_root = Path(
        args.plugin
    ).resolve()

    if not plugin_root.is_dir():
        print(
            f"[-] Invalid plugin path: {plugin_root}",
            file=sys.stderr
        )
        sys.exit(1)

    output_dir = (
        Path(args.output).resolve()
        if args.output
        else
        Path("/opt/codex-security/wpsec-output")
        / plugin_root.name
        / "v2"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    print("[*] Indexing PHP functions...")
    function_index = index_functions(
        plugin_root
    )

    print("[*] Resolving AJAX/admin-post entrypoints...")
    action_eps = collect_action_entrypoints(
        plugin_root
    )

    print("[*] Resolving REST entrypoints...")
    rest_eps = collect_rest_entrypoints(
        plugin_root
    )

    entrypoints = (
        action_eps
        +
        rest_eps
    )

    print("[*] Generating candidates...")
    candidates, unresolved = generate_candidates(
        entrypoints,
        function_index
    )

    write_json(
        output_dir / "entrypoints-resolved.json",
        entrypoints
    )

    write_json(
        output_dir / "candidates.json",
        candidates
    )

    write_json(
        output_dir / "unresolved-entrypoints.json",
        unresolved
    )

    summary = {
        "plugin": plugin_root.name,

        "indexed_function_names":
            len(function_index),

        "resolved_or_parseable_entrypoints":
            len(entrypoints),

        "action_entrypoints":
            len(action_eps),

        "rest_entrypoints":
            len(rest_eps),

        "candidates":
            len(candidates),

        "unresolved_callbacks":
            len(unresolved),

        "candidate_families":
            dict(
                Counter(
                    x["family"]
                    for x in candidates
                )
            ),

        "access_levels":
            dict(
                Counter(
                    x["entrypoint"]
                    ["minimum_access"]
                    for x in candidates
                )
            ),
    }

    write_json(
        output_dir / "summary.json",
        summary
    )

    print()
    print("WordPress Candidate Mapper V2")
    print("=" * 45)
    print(
        f"Plugin                : "
        f"{plugin_root.name}"
    )
    print(
        f"Indexed functions     : "
        f"{len(function_index)}"
    )
    print(
        f"Entrypoints parsed    : "
        f"{len(entrypoints)}"
    )
    print(
        f"  AJAX/Admin-post     : "
        f"{len(action_eps)}"
    )
    print(
        f"  REST                : "
        f"{len(rest_eps)}"
    )
    print(
        f"Candidates            : "
        f"{len(candidates)}"
    )
    print(
        f"Unresolved callbacks  : "
        f"{len(unresolved)}"
    )

    print()
    print("Candidate families:")

    for family, count in Counter(
        x["family"]
        for x in candidates
    ).most_common():

        print(
            f"  {family:<35} {count}"
        )

    print()
    print("Top candidates:")

    for item in candidates[:15]:
        cb = item["callback"]

        print(
            f'  {item["id"]} '
            f'score={item["score"]:3} '
            f'{item["family"]:<32} '
            f'{item["entrypoint"]["minimum_access"]:<38} '
            f'{cb["file"]}:{cb["line"]}'
        )

    print()
    print(f"Output: {output_dir}")


if __name__ == "__main__":
    main()
