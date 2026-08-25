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

    "cryptographic_signature": [
        re.compile(r"\bhash_hmac\s*\("),
        re.compile(r"\bhash_equals\s*\("),
    ],

    "webhook_signature_header": [
        re.compile(
            r"get_header\s*\(\s*['\"][^'\"]*signature[^'\"]*['\"]",
            re.I
        ),
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
    """
    Parse common WordPress REST callback representations.

    Supported:
      'callback' => 'function_name'

      'callback' => [$this, 'method']
      'callback' => array($this, 'method')

      'callback' => ['ClassName', 'method']
      'callback' => array('ClassName', 'method')

      'callback' => [ClassName::class, 'method']
      'callback' => array(ClassName::class, 'method')

      'callback' => [self::class, 'method']
      'callback' => array(self::class, 'method')

      'callback' => [static::class, 'method']
      'callback' => array(static::class, 'method')
    """

    # --------------------------------------------------------
    # Plain function callback
    #
    # 'callback' => 'function_name'
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Instance method
    #
    # [$this, 'method']
    # array($this, 'method')
    # --------------------------------------------------------

    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        (?:
            \[
            |
            array\s*\(
        )
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

    # --------------------------------------------------------
    # String class callback
    #
    # ['ClassName', 'method']
    # array('ClassName', 'method')
    # --------------------------------------------------------

    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        (?:
            \[
            |
            array\s*\(
        )
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

    # --------------------------------------------------------
    # ::class callback
    #
    # [ClassName::class, 'method']
    # array(ClassName::class, 'method')
    #
    # Also supports self::class / static::class / parent::class
    # --------------------------------------------------------

    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        (?:
            \[
            |
            array\s*\(
        )
        \s*
        (
            (?:
                [A-Za-z_][A-Za-z0-9_\\]*
                |
                self
                |
                static
                |
                parent
            )
            ::class
        )
        \s*,
        \s*['"]
        ([A-Za-z_][A-Za-z0-9_]*)
        ['"]
        """,
        call_text,
        re.X | re.I
    )

    if m:
        cls = re.sub(
            r"::class$",
            "",
            m.group(1),
            flags=re.I
        )

        return {
            "type": "static_method",
            "class": cls,
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



def definition_controls(definition):
    return detect_patterns(
        definition.get("body", ""),
        CONTROL_PATTERNS
    )


def sql_sink_is_locally_prepared(definition):
    """
    Conservative SQL protection heuristic.

    A function containing both a $wpdb SQL execution sink and
    $wpdb->prepare() is treated as locally SQL-protected for
    prioritization purposes.

    This does NOT prove every query in the function is safe.
    """
    body = definition.get("body", "")

    has_prepare = bool(
        re.search(
            r"\$wpdb\s*->\s*prepare\s*\(",
            body,
            re.I
        )
    )

    has_sql_sink = bool(
        re.search(
            r"\$wpdb\s*->\s*"
            r"(?:query|get_results|get_row|get_var|get_col)"
            r"\s*\(",
            body,
            re.I
        )
    )

    return has_prepare and has_sql_sink


def graph_has_signature_gate(nodes):
    """
    Detect a reachable HMAC/signature verification helper.

    This is prioritization metadata only. It must not by itself
    suppress a candidate because the gate may be called after
    attacker-controlled operations or may be logically bypassable.
    """
    for node in nodes:
        body = node.get("body", "")

        has_hmac = bool(
            re.search(r"\bhash_hmac\s*\(", body)
        )

        has_constant_time_compare = bool(
            re.search(r"\bhash_equals\s*\(", body)
        )

        has_signature_input = bool(
            re.search(
                r"get_header\s*\(\s*['\"][^'\"]*signature",
                body,
                re.I
            )
        )

        if (
            has_hmac
            and has_constant_time_compare
            and has_signature_input
        ):
            return True

    return False



def entrypoint_signature_gate_order(definition):
    """
    Lightweight ordering heuristic.

    Determine whether a signature-validation call appears before
    obvious attacker-controlled processing in the entrypoint.

    Returns:
      gate_before_processing
      gate_after_processing
      gate_present_order_unknown
      no_gate
    """

    body = definition.get("body", "")

    gate_patterns = [
        r"\bhas_valid_signature\s*\(",
        r"\bverify_signature\s*\(",
        r"\bvalidate_signature\s*\(",
        r"\bcheck_signature\s*\(",
        r"\bverify_webhook\s*\(",
        r"\bvalidate_webhook\s*\(",
    ]

    gate_positions = []

    for pattern in gate_patterns:
        m = re.search(pattern, body, re.I)
        if m:
            gate_positions.append(m.start())

    if not gate_positions:
        return "no_gate"

    gate_pos = min(gate_positions)

    processing_patterns = [
        r"get_json_params\s*\(",
        r"get_body_params\s*\(",
        r"get_param\s*\(",
        r"\$_POST\b",
        r"\$_GET\b",
        r"\$_REQUEST\b",
        r"\$_FILES\b",
    ]

    processing_positions = []

    for pattern in processing_patterns:
        m = re.search(pattern, body, re.I)
        if m:
            processing_positions.append(m.start())

    if not processing_positions:
        return "gate_present_order_unknown"

    processing_pos = min(processing_positions)

    if gate_pos < processing_pos:
        return "gate_before_processing"

    return "gate_after_processing"


def classify_candidate_protection(
    sink,
    sink_functions,
    reachable_nodes
):
    result = {
        "signature_gate_present": False,
        "signature_gate_order": "no_gate",
        "sink_local_sql_prepare": False,
        "protection_level": "unknown",
    }

    result["signature_gate_present"] = (
        graph_has_signature_gate(reachable_nodes)
    )

    # Determine whether the entrypoint validates the signature
    # before attacker-controlled request processing.
    if reachable_nodes:
        root = reachable_nodes[0]
        result["signature_gate_order"] = (
            entrypoint_signature_gate_order(root)
        )

    if sink == "sql":
        result["sink_local_sql_prepare"] = any(
            sql_sink_is_locally_prepared(x)
            for x in sink_functions
        )

    gate_before = (
        result["signature_gate_order"]
        == "gate_before_processing"
    )

    gate_unknown = (
        result["signature_gate_order"]
        == "gate_present_order_unknown"
    )

    if (
        gate_before
        and result["sink_local_sql_prepare"]
    ):
        result["protection_level"] = "strong_indicators"

    elif (
        gate_before
        or gate_unknown
        or result["sink_local_sql_prepare"]
    ):
        result["protection_level"] = "partial_indicators"

    return result


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
# LIGHTWEIGHT WORDPRESS/PHP CALL GRAPH
# ============================================================

# Intentionally conservative.
#
# We do not attempt to parse PHP completely here. The goal is to
# cheaply discover common helper calls reachable from a WordPress
# entrypoint before model-based semantic validation.

THIS_METHOD_CALL_RE = re.compile(
    r"""
    \$this
    \s*->\s*
    ([A-Za-z_][A-Za-z0-9_]*)
    \s*\(
    """,
    re.X
)

STATIC_METHOD_CALL_RE = re.compile(
    r"""
    (?<![\w$\\])
    (
        [A-Za-z_][A-Za-z0-9_\\]*
        |
        self
        |
        static
        |
        parent
    )
    \s*::\s*
    ([A-Za-z_][A-Za-z0-9_]*)
    \s*\(
    """,
    re.X
)

PLAIN_FUNCTION_CALL_RE = re.compile(
    r"""
    (?<!->)
    (?<!::)
    (?<![\w$\\])
    ([A-Za-z_][A-Za-z0-9_]*)
    \s*\(
    """,
    re.X
)


PHP_LANGUAGE_KEYWORDS = {
    "if",
    "else",
    "elseif",
    "while",
    "for",
    "foreach",
    "switch",
    "match",
    "catch",
    "isset",
    "empty",
    "array",
    "list",
    "echo",
    "print",
    "include",
    "include_once",
    "require",
    "require_once",
    "return",
    "throw",
    "new",
    "clone",
    "unset",
    "exit",
    "die",
    "eval",
}


def function_identity(definition):
    return (
        definition.get("file"),
        definition.get("line"),
        definition.get("class"),
        definition.get("name"),
    )


def definitions_for_name(function_index, name):
    return function_index.get(
        name.lower(),
        []
    )


def filter_definitions_by_class(definitions, class_name):
    if not class_name:
        return definitions

    wanted = class_name.split("\\")[-1].lower()

    filtered = [
        d for d in definitions
        if d.get("class")
        and d["class"].split("\\")[-1].lower() == wanted
    ]

    return filtered


def extract_callees(definition):
    """
    Return conservative call references found inside one function body.

    Supported:
      $this->method()
      ClassName::method()
      self::method()
      static::method()
      parent::method()
      plain_function()
    """

    body = definition.get("body", "")
    current_class = definition.get("class")

    result = []
    seen = set()

    # --------------------------------------------------------
    # $this->method()
    # --------------------------------------------------------

    for m in THIS_METHOD_CALL_RE.finditer(body):
        method = m.group(1)

        key = (
            "instance_method",
            current_class,
            method.lower(),
        )

        if key in seen:
            continue

        seen.add(key)

        result.append({
            "type": "instance_method",
            "class": current_class,
            "function": method,
        })

    # --------------------------------------------------------
    # ClassName::method()
    # --------------------------------------------------------

    for m in STATIC_METHOD_CALL_RE.finditer(body):
        cls = m.group(1)
        method = m.group(2)

        resolved_class = cls

        if cls.lower() in {"self", "static"}:
            resolved_class = current_class

        key = (
            "static_method",
            resolved_class,
            method.lower(),
        )

        if key in seen:
            continue

        seen.add(key)

        result.append({
            "type": "static_method",
            "class": resolved_class,
            "function": method,
        })

    # --------------------------------------------------------
    # plain_function()
    #
    # Resolution later only succeeds when the function actually
    # exists in the plugin function index. This avoids following
    # arbitrary PHP/WordPress built-ins.
    # --------------------------------------------------------

    for m in PLAIN_FUNCTION_CALL_RE.finditer(body):
        name = m.group(1)

        if name.lower() in PHP_LANGUAGE_KEYWORDS:
            continue

        key = (
            "function",
            None,
            name.lower(),
        )

        if key in seen:
            continue

        seen.add(key)

        result.append({
            "type": "function",
            "class": None,
            "function": name,
        })

    return result


def resolve_callee(callee, caller, function_index):
    name = callee["function"]

    definitions = definitions_for_name(
        function_index,
        name
    )

    if not definitions:
        return []

    call_type = callee.get("type")

    if call_type in {
        "instance_method",
        "static_method",
    }:
        cls = callee.get("class")

        # For $this/self/static calls, stay in the caller class
        # whenever possible.
        if not cls:
            cls = caller.get("class")

        filtered = filter_definitions_by_class(
            definitions,
            cls
        )

        if filtered:
            return filtered

        # Do not widen a class-qualified call to every function
        # with the same name. That creates false graph edges.
        if cls:
            return []

    # Plain function call.
    #
    # Prefer true global functions. If the index contains only
    # class methods with the same name, do not guess.
    globals_only = [
        d for d in definitions
        if not d.get("class")
    ]

    if call_type == "function":
        return globals_only

    return definitions


def build_reachable_graph(
    root_definition,
    function_index,
    max_depth=3
):
    """
    Traverse plugin-local helper calls from one entrypoint callback.

    Returns:
      nodes      - unique reachable function definitions
      call_paths - human/model-readable paths
    """

    root_id = function_identity(root_definition)

    nodes = {
        root_id: root_definition
    }

    call_paths = []

    # queue:
    # (definition, depth, path, identities_in_current_path)

    queue = [(
        root_definition,
        0,
        [root_definition["name"]],
        {root_id},
    )]

    while queue:
        current, depth, path, path_seen = queue.pop(0)

        if depth >= max_depth:
            continue

        callees = extract_callees(current)

        for callee in callees:
            resolved = resolve_callee(
                callee,
                current,
                function_index
            )

            for target in resolved:
                target_id = function_identity(target)

                # Cycle protection for this path.
                if target_id in path_seen:
                    continue

                target_label = target["name"]

                if target.get("class"):
                    target_label = (
                        f'{target["class"]}::'
                        f'{target["name"]}'
                    )

                new_path = path + [target_label]

                call_paths.append({
                    "depth": depth + 1,
                    "path": new_path,
                    "from": {
                        "file": current.get("file"),
                        "line": current.get("line"),
                        "class": current.get("class"),
                        "function": current.get("name"),
                    },
                    "to": {
                        "file": target.get("file"),
                        "line": target.get("line"),
                        "class": target.get("class"),
                        "function": target.get("name"),
                    },
                })

                nodes[target_id] = target

                queue.append((
                    target,
                    depth + 1,
                    new_path,
                    path_seen | {target_id},
                ))

    return list(nodes.values()), call_paths


def analyze_reachable_functions(definitions):
    """
    Aggregate security signals from a bounded reachable subgraph.
    """

    sources = set()
    controls = set()
    sinks = set()

    per_function = []

    for definition in definitions:
        body = definition.get("body", "")

        local_sources = detect_sources(body)

        local_controls = detect_patterns(
            body,
            CONTROL_PATTERNS
        )

        local_sinks = detect_patterns(
            body,
            SINK_PATTERNS
        )

        sources.update(local_sources)
        controls.update(local_controls)
        sinks.update(local_sinks)

        per_function.append({
            "name": definition.get("name"),
            "class": definition.get("class"),
            "file": definition.get("file"),
            "line": definition.get("line"),
            "sources": local_sources,
            "controls": local_controls,
            "sinks": local_sinks,
        })

    return {
        "sources": sorted(sources),
        "controls": sorted(controls),
        "sinks": sorted(sinks),
        "functions": per_function,
    }



def adjust_score_for_protection(score, sink, protection):
    """
    Adjust prioritization score using deterministic protection
    indicators.

    Candidates are retained. Protection only changes priority.

    Signature protection receives full credit only when the
    signature gate is observed before request processing.
    """
    adjusted = score
    reasons = []

    gate_order = protection.get(
        "signature_gate_order",
        "no_gate"
    )

    if gate_order == "gate_before_processing":
        adjusted -= 35
        reasons.append("signature_gate_before_processing")

    elif gate_order == "gate_present_order_unknown":
        # Conservative partial credit when ordering cannot be
        # established statically.
        adjusted -= 10
        reasons.append("signature_gate_order_unknown")

    elif gate_order == "gate_after_processing":
        reasons.append("signature_gate_after_processing_no_credit")

    if (
        sink == "sql"
        and protection.get("sink_local_sql_prepare")
    ):
        adjusted -= 70
        reasons.append("sink_local_sql_prepare")

    return max(adjusted, 0), reasons


def candidate_priority(score):
    if score >= 180:
        return "critical_review"

    if score >= 140:
        return "high"

    if score >= 100:
        return "medium"

    if score >= 60:
        return "low"

    return "deprioritized"


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

            reachable, call_paths = build_reachable_graph(
                definition,
                function_index,
                max_depth=3
            )

            analysis = analyze_reachable_functions(
                reachable
            )

            sources = analysis["sources"]
            controls = analysis["controls"]
            sinks = analysis["sinks"]

            if not sinks:
                continue

            for sink in sinks:
                raw_score = score_candidate(
                    ep,
                    sources,
                    controls,
                    sink
                )

                # Keep full reachable definitions containing
                # this sink for local protection analysis.
                sink_definitions = [
                    x
                    for x in reachable
                    if sink in detect_patterns(
                        x.get("body", ""),
                        SINK_PATTERNS
                    )
                ]

                protection = classify_candidate_protection(
                    sink,
                    sink_definitions,
                    reachable
                )

                score, protection_reasons = (
                    adjust_score_for_protection(
                        raw_score,
                        sink,
                        protection
                    )
                )

                priority = candidate_priority(score)

                # Identify exactly which reachable functions
                # contain this sink category.
                sink_functions = [
                    {
                        "name": x["name"],
                        "class": x["class"],
                        "file": x["file"],
                        "line": x["line"],
                    }
                    for x in analysis["functions"]
                    if sink in x["sinks"]
                ]

                control_functions = [
                    {
                        "name": x["name"],
                        "class": x["class"],
                        "file": x["file"],
                        "line": x["line"],
                        "controls": x["controls"],
                    }
                    for x in analysis["functions"]
                    if x["controls"]
                ]

                source_functions = [
                    {
                        "name": x["name"],
                        "class": x["class"],
                        "file": x["file"],
                        "line": x["line"],
                        "sources": x["sources"],
                    }
                    for x in analysis["functions"]
                    if x["sources"]
                ]

                candidates.append({
                    "id": f"WP-CAND-{candidate_id:04d}",

                    "family":
                        FAMILY_MAP.get(
                            sink,
                            sink
                        ),

                    "score": score,
                    "raw_score": raw_score,
                    "priority": priority,

                    "protection": {
                        **protection,
                        "score_adjustment":
                            score - raw_score,
                        "reasons":
                            protection_reasons,
                    },

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

                    "reachable_summary": {
                        "max_depth": 3,
                        "function_count":
                            len(reachable),
                        "call_edge_count":
                            len(call_paths),
                    },

                    "sink_functions":
                        sink_functions,

                    "control_functions":
                        control_functions,

                    "source_functions":
                        source_functions,

                    "call_paths":
                        call_paths,

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

                    "callback_ref": (
                        f'{definition["file"]}:'
                        f'{definition["line"]}:'
                        f'{definition["name"]}'
                    ),
                })

                candidate_id += 1

    candidates.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return candidates, unresolved



# ============================================================
# GENERIC REVIEW-UNIT CLUSTERING
# ============================================================

def build_review_units(candidates):
    """
    Cluster candidates that share the same externally reachable
    entrypoint and resolved callback.

    Important:
    - No candidate is discarded.
    - Multiple vulnerability families may live inside one unit.
    - Codex can review the source/call graph once and evaluate
      several sink families together.
    """

    groups = {}

    for candidate in candidates:
        ep = candidate.get("entrypoint", {})
        cb = candidate.get("callback", {})

        key = (
            ep.get("type"),
            ep.get("hook"),
            ep.get("minimum_access"),
            cb.get("file"),
            cb.get("line"),
            cb.get("class"),
            cb.get("name"),
        )

        if key not in groups:
            groups[key] = {
                "entrypoint": ep,
                "callback": cb,

                "candidate_ids": [],
                "families": set(),
                "sink_categories": set(),

                "sources": set(),
                "controls": set(),

                "max_raw_score": 0,
                "max_score": 0,

                "priorities": set(),

                "sink_functions": {},
                "source_functions": {},
                "control_functions": {},

                "call_paths": {},
                "protections": [],
            }

        unit = groups[key]

        unit["candidate_ids"].append(
            candidate.get("id")
        )

        if candidate.get("family"):
            unit["families"].add(
                candidate["family"]
            )

        if candidate.get("sink_category"):
            unit["sink_categories"].add(
                candidate["sink_category"]
            )

        unit["sources"].update(
            candidate.get("sources", [])
        )

        unit["controls"].update(
            candidate.get("controls", [])
        )

        unit["max_raw_score"] = max(
            unit["max_raw_score"],
            candidate.get("raw_score", 0)
        )

        unit["max_score"] = max(
            unit["max_score"],
            candidate.get("score", 0)
        )

        if candidate.get("priority"):
            unit["priorities"].add(
                candidate["priority"]
            )

        protection = candidate.get(
            "protection"
        )

        if protection:
            unit["protections"].append({
                "candidate_id":
                    candidate.get("id"),

                "family":
                    candidate.get("family"),

                **protection,
            })

        for f in candidate.get(
            "sink_functions", []
        ):
            fkey = (
                f.get("file"),
                f.get("line"),
                f.get("class"),
                f.get("name"),
            )

            unit["sink_functions"][fkey] = f

        for f in candidate.get(
            "source_functions", []
        ):
            fkey = (
                f.get("file"),
                f.get("line"),
                f.get("class"),
                f.get("name"),
            )

            unit["source_functions"][fkey] = f

        for f in candidate.get(
            "control_functions", []
        ):
            fkey = (
                f.get("file"),
                f.get("line"),
                f.get("class"),
                f.get("name"),
            )

            unit["control_functions"][fkey] = f

        for edge in candidate.get(
            "call_paths", []
        ):
            path = tuple(
                edge.get("path", [])
            )

            if path:
                unit["call_paths"][path] = edge

    priority_rank = {
        "critical_review": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "deprioritized": 1,
    }

    result = []

    for index, unit in enumerate(
        groups.values(),
        start=1
    ):
        priorities = sorted(
            unit["priorities"],
            key=lambda x:
                priority_rank.get(x, 0),
            reverse=True
        )

        result.append({
            "id":
                f"WP-UNIT-{index:04d}",

            "entrypoint":
                unit["entrypoint"],

            "callback":
                unit["callback"],

            "candidate_ids":
                unit["candidate_ids"],

            "candidate_count":
                len(unit["candidate_ids"]),

            "families":
                sorted(unit["families"]),

            "sink_categories":
                sorted(
                    unit["sink_categories"]
                ),

            "sources":
                sorted(unit["sources"]),

            "controls":
                sorted(unit["controls"]),

            "max_raw_score":
                unit["max_raw_score"],

            "max_score":
                unit["max_score"],

            "priority":
                priorities[0]
                if priorities
                else "unknown",

            "sink_functions":
                list(
                    unit[
                        "sink_functions"
                    ].values()
                ),

            "source_functions":
                list(
                    unit[
                        "source_functions"
                    ].values()
                ),

            "control_functions":
                list(
                    unit[
                        "control_functions"
                    ].values()
                ),

            "call_paths":
                list(
                    unit[
                        "call_paths"
                    ].values()
                ),

            "protections":
                unit["protections"],
        })

    result.sort(
        key=lambda x: (
            x["max_score"],
            x["candidate_count"],
        ),
        reverse=True
    )

    return result



def build_review_index(review_units):
    """
    Produce a compact model-facing index.

    Full candidates/review-units remain available locally for
    drill-down, but Codex should load this compact index first.
    """

    compact = []

    for unit in review_units:
        ep = unit.get("entrypoint", {})
        cb = unit.get("callback", {})
        reg = ep.get("registration", {})

        compact.append({
            "id": unit.get("id"),

            "priority": unit.get("priority"),
            "score": unit.get("max_score"),
            "raw_score": unit.get("max_raw_score"),

            "candidate_count":
                unit.get("candidate_count"),

            "candidate_ids":
                unit.get("candidate_ids", []),

            "families":
                unit.get("families", []),

            "sink_categories":
                unit.get("sink_categories", []),

            "sources":
                unit.get("sources", []),

            "controls":
                unit.get("controls", []),

            "entrypoint": {
                "type":
                    ep.get("type"),

                "hook":
                    ep.get("hook"),

                "minimum_access":
                    ep.get("minimum_access"),

                "file":
                    reg.get("file"),

                "line":
                    reg.get("line"),
            },

            "callback": {
                "class":
                    cb.get("class"),

                "name":
                    cb.get("name"),

                "file":
                    cb.get("file"),

                "line":
                    cb.get("line"),
            },

            "sink_locations": [
                {
                    "file": x.get("file"),
                    "line": x.get("line"),
                    "class": x.get("class"),
                    "name": x.get("name"),
                }
                for x in unit.get(
                    "sink_functions", []
                )
            ],
        })

    return compact


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

    callbacks = {}

    for items in function_index.values():
        for definition in items:
            ref = (
                f'{definition["file"]}:'
                f'{definition["line"]}:'
                f'{definition["name"]}'
            )

            if ref not in callbacks:
                callbacks[ref] = {
                    "ref": ref,
                    "name": definition["name"],
                    "class": definition["class"],
                    "file": definition["file"],
                    "line": definition["line"],
                    "code": definition["body"][:15000],
                }

    used_callback_refs = {
        x["callback_ref"]
        for x in candidates
        if x.get("callback_ref")
    }

    callbacks = {
        ref: item
        for ref, item in callbacks.items()
        if ref in used_callback_refs
    }

    write_json(
        output_dir / "candidates.json",
        candidates
    )

    review_units = build_review_units(
        candidates
    )

    write_json(
        output_dir / "review-units.json",
        review_units
    )

    review_index = build_review_index(
        review_units
    )

    write_json(
        output_dir / "review-index.json",
        review_index
    )

    write_json(
        output_dir / "callbacks.json",
        callbacks
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
    print("WordPress Candidate Mapper V4")
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
