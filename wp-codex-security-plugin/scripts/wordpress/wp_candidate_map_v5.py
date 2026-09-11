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
        re.compile(r"\bwp_upload_bits\s*\("),
        re.compile(r"\bfopen\s*\("),
        re.compile(r"\bcopy\s*\("),
        re.compile(r"\brename\s*\("),
        re.compile(r"\bmkdir\s*\("),
        re.compile(r"\btouch\s*\("),
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
        re.compile(r"\bwp_delete_file\s*\("),
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
        re.compile(r"\bpcntl_exec\s*\("),
    ],

    # Direct PHP dynamic-code sinks. These are kept separate so the
    # semantic reviewer can distinguish PHP code execution from OS commands.
    "code_injection": [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bcreate_function\s*\("),
    ],

    "deserialization": [
        re.compile(r"\bunserialize\s*\("),
        re.compile(r"\bmaybe_unserialize\s*\("),
    ],

    # Dynamic invocation is not automatically RCE, but it is a high-value
    # authorization/dataflow boundary and must remain visible to review.
    "dynamic_invocation": [
        re.compile(r"\bcall_user_func\s*\("),
        re.compile(r"\bcall_user_func_array\s*\("),
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
    "code_injection": "code_injection",
    "deserialization": "unsafe_deserialization",
    "dynamic_invocation": "dynamic_invocation",
}



# ============================================================
# V5 GENERIC SECURITY GRAPH MODEL
# ============================================================

ENTRYPOINT_KINDS = {
    "http_public",
    "http_authenticated",
    "rest",
    "ajax",
    "admin_post",
    "hook",
    "shortcode",
    "render_callback",
    "cli",
    "cron",
    "unknown",
}


SOURCE_KINDS = {
    "query",
    "post",
    "request",
    "cookie",
    "header",
    "file_upload",
    "rest_parameter",
    "rest_body",
    "route_parameter",
    "raw_body",
    "user_identity",
    "database_value",
    "external_response",
    "unknown",
}


CONTROL_KINDS = {
    # Access / authorization
    "authentication",
    "capability",
    "role",
    "ownership",
    "object_secret",
    "tenant_boundary",

    # Request integrity
    "nonce",
    "csrf_token",
    "signature",
    "hmac",

    # Input restriction
    "type_validation",
    "numeric_conversion",
    "allowlist",
    "canonicalization",

    # Sink-specific
    "sql_parameterization",
    "path_containment",
    "file_type_validation",
    "output_encoding",
    "deserialization_restriction",

    "unknown",
}


EFFECT_KINDS = {
    # Code/system
    "code_execution",
    "dynamic_include",
    "deserialization",

    # Database/configuration
    "database_read",
    "database_write",
    "configuration_read",
    "configuration_write",

    # Filesystem
    "file_read",
    "file_write",
    "file_delete",
    "file_upload",

    # Identity/authorization
    "user_create",
    "user_update",
    "role_change",
    "capability_change",
    "session_change",

    # Object/business logic
    "object_lookup",
    "object_read",
    "object_update",
    "object_delete",
    "secret_read",
    "sensitive_metadata_read",
    "payment_state_change",

    # Exposure/output
    "redirect",
    "http_response",
    "json_response",
    "download",
    "header_output",
    "html_output",

    # Network
    "external_request",

    "unknown",
}


FLOW_CONFIDENCE = {
    "confirmed",
    "probable",
    "reachability_only",
    "unknown",
}


GAP_KINDS = {
    "dynamic_hook",
    "dynamic_callback",
    "dynamic_dispatch",
    "dynamic_include",
    "variable_function",
    "magic_method",
    "inheritance_ambiguity",
    "factory_resolution",
    "unknown_framework_semantic",
    "unsupported_syntax",
    "unresolved_dataflow",
}


def make_security_node(
    node_type,
    kind,
    file=None,
    line=None,
    function=None,
    class_name=None,
    evidence=None,
    metadata=None,
):
    return {
        "node_type": node_type,
        "kind": kind,
        "file": file,
        "line": line,
        "function": function,
        "class": class_name,
        "evidence": evidence,
        "metadata": metadata or {},
    }


def make_security_edge(
    source,
    target,
    edge_type,
    confidence="unknown",
    metadata=None,
):
    return {
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "confidence": confidence,
        "metadata": metadata or {},
    }


def make_gap_unit(
    gap_id,
    kind,
    file,
    line,
    reason,
    local_context=None,
    required_resolution=None,
):
    return {
        "id": gap_id,
        "kind": kind,
        "file": file,
        "line": line,
        "reason": reason,
        "local_context": local_context,
        "required_resolution":
            required_resolution or [],
        "status": "unresolved",
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


def index_rest_anonymous_callbacks(
    function_index,
    rest_entrypoints,
):
    """
    Add only anonymous REST callbacks to the shared function index.
    This keeps unrelated anonymous closures out of the global index.
    """
    if not isinstance(function_index, dict):
        return function_index

    for reg in rest_entrypoints or []:
        callback = reg.get("callback") or {}

        if callback.get("type") != "anonymous":
            continue

        name = callback.get("name")
        body = callback.get("body")

        if not name or not isinstance(body, str) or not body.strip():
            continue

        key = name.lower()

        item = {
            "name": name,
            "class": None,
            "file": callback.get("registration_file"),
            "line": callback.get("registration_line"),
            "body": body,
        }

        existing = function_index.setdefault(key, [])

        if not any(
            x.get("name") == item["name"]
            and x.get("file") == item["file"]
            and x.get("line") == item["line"]
            for x in existing
        ):
            existing.append(item)

    return function_index


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



def extract_rest_anonymous_callback(call_text):
    """
    Extract the body of an anonymous PHP closure used as a REST
    callback.

    This is intentionally generic: it does not assume anything
    about the plugin, route name, service class, or callback
    implementation.
    """
    m = re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        function\b
        [^{]*
        \{
        """,
        call_text,
        re.X | re.I
    )

    if not m:
        return None

    brace = call_text.find("{", m.start())

    if brace == -1:
        return None

    close = find_matching_brace(
        call_text,
        brace
    )

    if close is None:
        return None

    return call_text[m.start():close + 1]


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

    Also preserves unresolved/anonymous callbacks instead of
    dropping the REST route from the security graph.
    """

    # --------------------------------------------------------
    # Plain function callback
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

    # --------------------------------------------------------
    # Anonymous / closure callback
    #
    # Example:
    # 'callback' => function () use (...) { ... }
    # --------------------------------------------------------

    if re.search(
        r"""
        ['"]callback['"]
        \s*=>
        \s*
        function\b
        """,
        call_text,
        re.X | re.I
    ):
        anonymous_body = extract_rest_anonymous_callback(
            call_text
        )

        return {
            "type": "anonymous",
            "function": None,
            "class": None,
            "body": anonymous_body,
        }

    # --------------------------------------------------------
    # Dynamic / unresolved callback
    #
    # Preserve the REST route so later V5/V6/V6.1 analysis
    # can reason about the unresolved callback rather than
    # treating the route as nonexistent.
    # --------------------------------------------------------

    if re.search(
        r"""['"]callback['"]\s*=>""",
        call_text,
        re.X | re.I
    ):
        return {
            "type": "dynamic",
            "function": None,
            "class": None,
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

            callback = parse_rest_callback(call)

            # Do not discard REST registrations merely because
            # callback resolution is incomplete. Dynamic and
            # anonymous callbacks remain security-relevant
            # entrypoints and must flow into later analysis.
            if callback is None:
                callback = {
                    "type": "unresolved",
                    "function": None,
                    "class": None,
                }

            # Preserve registration context on anonymous callbacks
            # so the resolver can construct a synthetic definition
            # without inventing a plugin-specific function name.
            if callback.get("type") == "anonymous":
                callback["registration_file"] = str(
                    path.relative_to(plugin_root)
                )
                callback["registration_line"] = line_number(
                    text,
                    match.start()
                )
                callback["name"] = (
                    "__rest_anonymous_callback_"
                    f"{callback['registration_line'] or 'unknown'}"
                )
                callback["name"] = (
                    "__rest_anonymous_callback_"
                    f"{callback["registration_line"] or "unknown"}"
                )

            result.append({
                "type": "rest",
                "hook": "register_rest_route",
                "minimum_access": rest_access(call),
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

            if callback is None:
                callback = {
                    "type": "unresolved",
                    "function": None,
                    "class": None,
                }

            if callback.get("type") == "anonymous":
                callback["registration_file"] = str(
                    path.relative_to(plugin_root)
                )
                callback["registration_line"] = line_number(
                    text,
                    match.start()
                )
                callback["name"] = (
                    "__rest_anonymous_callback_"
                    f"{callback['registration_line'] or 'unknown'}"
                )

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
# V5 GENERIC WORDPRESS REGISTRATION DISCOVERY
# ============================================================

# Hooks that are commonly reachable during frontend/public
# request processing. These are semantic hints, not an
# exhaustive vulnerability signature list.
PUBLIC_REQUEST_HOOK_HINTS = {
    "template_redirect",
    "parse_request",
    "wp",
    "wp_loaded",
    "init",
    "send_headers",
    "pre_get_posts",
    "request",
    "rest_api_init",
}


# Hooks that are clearly administrative/internal unless another
# registration mechanism exposes them.
ADMIN_HOOK_PREFIXES = (
    "admin_",
    "manage_",
    "load-",
)


# Registration APIs we want to inventory generically.
GENERIC_REGISTRATION_RE = re.compile(
    r"""
    \b
    (
        add_action
        |
        add_filter
        |
        add_shortcode
    )
    \s*\(
    """,
    re.X | re.I
)


def split_php_call_arguments(call_text):
    """
    Lightweight PHP call-argument splitter.

    Handles nested (), [], {}, strings, and escapes well enough
    for common WordPress registration calls.

    Returns raw argument strings without evaluating PHP.
    """

    open_pos = call_text.find("(")

    if open_pos == -1:
        return []

    # remove final closing ')' when present
    inner = call_text[open_pos + 1:]

    if inner.rstrip().endswith(")"):
        inner = inner.rstrip()
        inner = inner[:-1]

    args = []
    start = 0

    paren = 0
    bracket = 0
    brace = 0
    quote = None
    escape = False

    for i, ch in enumerate(inner):
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
            paren += 1
            continue

        if ch == ")":
            if paren:
                paren -= 1
            continue

        if ch == "[":
            bracket += 1
            continue

        if ch == "]":
            if bracket:
                bracket -= 1
            continue

        if ch == "{":
            brace += 1
            continue

        if ch == "}":
            if brace:
                brace -= 1
            continue

        if (
            ch == ","
            and paren == 0
            and bracket == 0
            and brace == 0
        ):
            args.append(
                inner[start:i].strip()
            )
            start = i + 1

    tail = inner[start:].strip()

    if tail:
        args.append(tail)

    return args


def parse_php_literal_string(expr):
    expr = expr.strip()

    m = re.fullmatch(
        r"""['"]([^'"]+)['"]""",
        expr,
        re.S
    )

    if m:
        return m.group(1)

    return None


def parse_generic_callback_expr(expr):
    """
    Parse common WordPress callback expressions.

    Returns callback descriptor or None when dynamic/unresolved.
    """

    expr = expr.strip()

    # Anonymous closure: function (...) { ... }
    if re.match(r"^function\b", expr, re.I):
        brace = expr.find("{")

        if brace != -1:
            close = find_matching_brace(expr, brace)

            if close is not None:
                return {
                    "type": "anonymous",
                    "function": None,
                    "class": None,
                    "body": expr[brace + 1:close],
                }

    # 'function_name'
    m = re.fullmatch(
        r"""['"]([A-Za-z_][A-Za-z0-9_]*)['"]""",
        expr
    )

    if m:
        return {
            "type": "function",
            "function": m.group(1),
            "class": None,
        }

    # [$this, 'method'] / array($this, 'method')
    m = re.fullmatch(
        r"""
        (?:
            \[
            |
            array\s*\(
        )
        \s*\$this\s*,
        \s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]
        \s*
        (?:\]|\))
        """,
        expr,
        re.X | re.I
    )

    if m:
        return {
            "type": "instance_method",
            "function": m.group(1),
            "class": None,
        }

    # ['Class', 'method']
    m = re.fullmatch(
        r"""
        (?:
            \[
            |
            array\s*\(
        )
        \s*['"]([A-Za-z_][A-Za-z0-9_\\]*)['"]
        \s*,\s*
        ['"]([A-Za-z_][A-Za-z0-9_]*)['"]
        \s*
        (?:\]|\))
        """,
        expr,
        re.X | re.I
    )

    if m:
        return {
            "type": "static_method",
            "class": m.group(1),
            "function": m.group(2),
        }

    # [ClassName::class, 'method']
    m = re.fullmatch(
        r"""
        (?:
            \[
            |
            array\s*\(
        )
        \s*
        (
            [A-Za-z_][A-Za-z0-9_\\]*
            |
            self
            |
            static
            |
            parent
        )
        ::class
        \s*,\s*
        ['"]([A-Za-z_][A-Za-z0-9_]*)['"]
        \s*
        (?:\]|\))
        """,
        expr,
        re.X | re.I
    )

    if m:
        return {
            "type": "static_method",
            "class": m.group(1),
            "function": m.group(2),
        }

    return None


def classify_generic_hook_surface(
    registration_api,
    hook_name
):
    """
    Classify request relevance without assuming vulnerability.

    known_public:
        directly associated with public/request dispatch

    conditional:
        generic lifecycle hook that requires callback analysis

    internal:
        likely admin/internal/event hook

    unknown:
        unresolved semantics
    """

    if registration_api == "add_shortcode":
        return "known_public"

    if not hook_name:
        return "unknown"

    lower = hook_name.lower()

    if lower.startswith("wp_ajax_nopriv_"):
        return "known_public"

    if lower.startswith("admin_post_nopriv_"):
        return "known_public"

    # WooCommerce and other frameworks often build public dispatcher
    # hooks using prefixes. Do not assign vulnerability semantics here;
    # only mark as public-dispatch-like for later validation.
    if (
        lower.startswith("woocommerce_api_")
        or lower.startswith("wc_ajax_")
    ):
        return "known_public"

    if lower in PUBLIC_REQUEST_HOOK_HINTS:
        return "conditional"

    if lower.startswith(ADMIN_HOOK_PREFIXES):
        return "internal"

    return "unknown"


def collect_generic_registrations(plugin_root):
    """
    Inventory generic WordPress callback registrations.

    This does not create vulnerabilities. It provides:
      - resolved registrations
      - dynamic/unresolved registrations
      - request-surface classification
    """

    registrations = []
    gaps = []

    gap_id = 1

    php_files = sorted(
        p for p in plugin_root.rglob("*.php")
        if p.is_file()
        and not should_skip(p, plugin_root)
    )

    for path in php_files:
        text = read_text(path)

        for match in GENERIC_REGISTRATION_RE.finditer(text):
            call = extract_balanced_call(
                text,
                match.start()
            )

            if not call:
                gaps.append(
                    make_gap_unit(
                        f"WP-GAP-{gap_id:04d}",
                        "unsupported_syntax",
                        str(path.relative_to(plugin_root)),
                        line_number(text, match.start()),
                        "Could not extract balanced WordPress registration call.",
                        local_context=text[
                            max(0, match.start() - 200):
                            min(len(text), match.start() + 800)
                        ],
                        required_resolution=[
                            "resolve_registration_call"
                        ],
                    )
                )
                gap_id += 1
                continue

            api_match = re.match(
                r"\s*([A-Za-z_][A-Za-z0-9_]*)",
                call
            )

            if not api_match:
                continue

            api = api_match.group(1)

            args = split_php_call_arguments(call)

            if len(args) < 2:
                gaps.append(
                    make_gap_unit(
                        f"WP-GAP-{gap_id:04d}",
                        "unsupported_syntax",
                        str(path.relative_to(plugin_root)),
                        line_number(text, match.start()),
                        "Registration call did not expose hook and callback arguments.",
                        local_context=call[:1500],
                        required_resolution=[
                            "resolve_registration_arguments"
                        ],
                    )
                )
                gap_id += 1
                continue

            hook_expr = args[0]
            callback_expr = args[1]

            hook_name = parse_php_literal_string(
                hook_expr
            )

            callback = parse_generic_callback_expr(
                callback_expr
            )

            surface = classify_generic_hook_surface(
                api,
                hook_name
            )

            registration = {
                "registration_api": api,
                "hook": hook_name,
                "hook_expression": hook_expr[:500],
                "callback": callback,
                "callback_expression":
                    callback_expr[:800],
                "surface_class": surface,
                "registration": {
                    "file": str(
                        path.relative_to(plugin_root)
                    ),
                    "line": line_number(
                        text,
                        match.start()
                    ),
                    "code": call[:2000],
                },
            }

            registrations.append(
                registration
            )

            if hook_name is None:
                gaps.append(
                    make_gap_unit(
                        f"WP-GAP-{gap_id:04d}",
                        "dynamic_hook",
                        str(path.relative_to(plugin_root)),
                        line_number(text, match.start()),
                        "WordPress registration hook name is dynamic.",
                        local_context=call[:1500],
                        required_resolution=[
                            "backward_slice_hook_expression",
                            "classify_request_reachability",
                        ],
                    )
                )
                gap_id += 1

            if callback is None:
                gaps.append(
                    make_gap_unit(
                        f"WP-GAP-{gap_id:04d}",
                        "dynamic_callback",
                        str(path.relative_to(plugin_root)),
                        line_number(text, match.start()),
                        "WordPress registration callback could not be resolved statically.",
                        local_context=call[:1500],
                        required_resolution=[
                            "backward_slice_callback_expression",
                            "resolve_callback_target",
                        ],
                    )
                )
                gap_id += 1

    return registrations, gaps


# ============================================================
# V5 NORMALIZATION
# ============================================================

SOURCE_TO_V5 = {
    "GET": "query",
    "POST": "post",
    "REQUEST": "request",
    "FILES": "file_upload",
    "COOKIE": "cookie",
    "SERVER": "header",
    "raw_body": "raw_body",
    "rest_get_param": "rest_parameter",
    "rest_get_params": "rest_parameter",
    "rest_json": "rest_body",
    "rest_files": "file_upload",
    "filter_input": "request",
}


CONTROL_TO_V5 = {
    "capability": "capability",
    "nonce": "nonce",
    "sql_prepare": "sql_parameterization",
    "path_validation": "path_containment",
    "cryptographic_signature": "signature",
    "webhook_signature_header": "signature",
    "upload_validation": "file_type_validation",
    "escaping": "output_encoding",
}


SINK_TO_EFFECTS = {
    "option_write": [
        "configuration_write",
    ],

    "user_privilege": [
        "user_update",
        "role_change",
        "capability_change",
    ],

    "sql": [
        "database_read",
        "database_write",
    ],

    "file_write_upload": [
        "file_write",
        "file_upload",
    ],

    "file_read": [
        "file_read",
    ],

    "file_delete": [
        "file_delete",
    ],

    "include": [
        "dynamic_include",
    ],

    "command_execution": [
        "code_execution",
    ],

    "code_injection": [
        "code_execution",
    ],

    "dynamic_invocation": [
        "code_execution",
    ],

    "deserialization": [
        "deserialization",
    ],
}


def normalize_sources_v5(sources):
    return sorted({
        SOURCE_TO_V5.get(
            source,
            "unknown"
        )
        for source in sources
    })


def normalize_controls_v5(controls):
    return sorted({
        CONTROL_TO_V5.get(
            control,
            "unknown"
        )
        for control in controls
    })


def normalize_effects_v5(sinks):
    result = set()

    for sink in sinks:
        effects = SINK_TO_EFFECTS.get(
            sink,
            ["unknown"]
        )

        result.update(effects)

    return sorted(result)


def normalize_entrypoint_v5(entrypoint):
    ep_type = entrypoint.get(
        "type",
        "unknown"
    )

    access = entrypoint.get(
        "minimum_access",
        "unknown"
    )

    if ep_type == "rest":
        kind = "rest"

    elif ep_type == "ajax":
        kind = "ajax"

    elif ep_type == "admin_post":
        kind = "admin_post"

    else:
        kind = "hook"

    if access == "unauthenticated":
        exposure = "public"

    elif access == "authenticated":
        exposure = "authenticated"

    else:
        exposure = "unknown"

    return {
        "kind": kind,
        "exposure": exposure,
        "hook": entrypoint.get("hook"),
        "minimum_access": access,
        "registration":
            entrypoint.get("registration"),
    }




# ============================================================
# V5.3 BOUNDED DYNAMIC REGISTRATION RESOLUTION
# ============================================================

def local_source_window(
    text,
    line,
    before_lines=120,
    after_lines=10,
):
    """
    Return a bounded source slice around a registration.

    This is intentionally local. It must never trigger
    repository-wide discovery.
    """

    lines = text.splitlines()

    start = max(
        0,
        line - before_lines - 1
    )

    end = min(
        len(lines),
        line + after_lines
    )

    return "\n".join(
        lines[start:end]
    )


def extract_string_literals(expr):
    return re.findall(
        r"""['"]([^'"]*)['"]""",
        expr,
        re.S
    )


def find_local_variable_string_values(
    text,
    line,
    variable,
    max_lines=120,
):
    """
    Resolve a local variable to a bounded set of string values.

    Supported examples:

      $action = 'save';

      foreach (['save', 'delete'] as $action)

      foreach (
          array('save', 'delete')
          as $action
      )

      foreach (static::ACTIONS as $action)

    Class constants are resolved only when defined in the
    same PHP file.
    """

    var = re.escape(
        variable.lstrip("$")
    )

    window = local_source_window(
        text,
        line,
        before_lines=max_lines
    )

    values = set()

    # --------------------------------------------------------
    # Simple local assignment:
    #
    # $action = 'save';
    # --------------------------------------------------------

    assignment_re = re.compile(
        rf"""
        \${var}
        \s*=\s*
        ['"]([^'"]+)['"]
        \s*;
        """,
        re.X | re.I
    )

    for m in assignment_re.finditer(window):
        values.add(
            m.group(1)
        )

    # --------------------------------------------------------
    # Literal foreach array:
    #
    # foreach (['a', 'b'] as $action)
    # foreach (array('a', 'b') as $action)
    # --------------------------------------------------------

    literal_foreach_patterns = [
        re.compile(
            rf"""
            foreach\s*\(
            \s*\[
            (.*?)
            \]
            \s+as\s+
            \${var}
            \s*
            \)
            """,
            re.X | re.I | re.S
        ),

        re.compile(
            rf"""
            foreach\s*\(
            \s*array\s*\(
            (.*?)
            \)
            \s+as\s+
            \${var}
            \s*
            \)
            """,
            re.X | re.I | re.S
        ),
    ]

    for regex in literal_foreach_patterns:
        for m in regex.finditer(window):
            for value in extract_string_literals(
                m.group(1)
            ):
                values.add(value)

    # --------------------------------------------------------
    # Class constant foreach:
    #
    # foreach (static::ACTIONS as $action)
    # foreach (self::ACTIONS as $action)
    # --------------------------------------------------------

    const_foreach = re.compile(
        rf"""
        foreach\s*\(
        \s*
        (?:self|static|parent)
        ::
        ([A-Z_][A-Z0-9_]*)
        \s+as\s+
        \${var}
        \s*
        \)
        """,
        re.X | re.I
    )

    for m in const_foreach.finditer(window):
        const_name = m.group(1)

        # Short array const.
        const_array = re.search(
            rf"""
            \bconst\s+
            {re.escape(const_name)}
            \s*=\s*
            \[
            (.*?)
            \]
            \s*;
            """,
            text,
            re.X | re.I | re.S
        )

        if const_array:
            for value in extract_string_literals(
                const_array.group(1)
            ):
                values.add(value)

        # Legacy array() const.
        const_array = re.search(
            rf"""
            \bconst\s+
            {re.escape(const_name)}
            \s*=\s*
            array\s*\(
            (.*?)
            \)
            \s*;
            """,
            text,
            re.X | re.I | re.S
        )

        if const_array:
            for value in extract_string_literals(
                const_array.group(1)
            ):
                values.add(value)

    return sorted(values)


def resolve_scalar_class_constant(
    text,
    const_name
):
    """
    Resolve a same-file scalar class constant.
    """

    m = re.search(
        rf"""
        \bconst\s+
        {re.escape(const_name)}
        \s*=\s*
        ['"]([^'"]*)['"]
        \s*;
        """,
        text,
        re.X | re.I
    )

    if not m:
        return []

    return [
        m.group(1)
    ]


def split_php_concat(expr):
    """
    Split a PHP string concatenation at top-level dots.

    Example:
        'prefix_' . static::PREFIX . '_' . $action
    """

    parts = []

    start = 0
    quote = None
    escape = False

    paren = 0
    bracket = 0
    brace = 0

    for i, ch in enumerate(expr):
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
            paren += 1
            continue

        if ch == ")":
            paren = max(0, paren - 1)
            continue

        if ch == "[":
            bracket += 1
            continue

        if ch == "]":
            bracket = max(0, bracket - 1)
            continue

        if ch == "{":
            brace += 1
            continue

        if ch == "}":
            brace = max(0, brace - 1)
            continue

        if (
            ch == "."
            and paren == 0
            and bracket == 0
            and brace == 0
        ):
            parts.append(
                expr[start:i].strip()
            )
            start = i + 1

    parts.append(
        expr[start:].strip()
    )

    return [
        x for x in parts
        if x
    ]


def resolve_string_term_local(
    term,
    text,
    line,
):
    """
    Resolve one term of a PHP concatenation to possible strings.
    """

    term = term.strip()

    literal = parse_php_literal_string(
        term
    )

    if literal is not None:
        return [literal]

    # $variable
    m = re.fullmatch(
        r"\$([A-Za-z_][A-Za-z0-9_]*)",
        term
    )

    if m:
        return find_local_variable_string_values(
            text,
            line,
            m.group(1)
        )

    # self::PREFIX / static::PREFIX / parent::PREFIX
    m = re.fullmatch(
        r"""
        (?:self|static|parent)
        ::
        ([A-Z_][A-Z0-9_]*)
        """,
        term,
        re.X | re.I
    )

    if m:
        return resolve_scalar_class_constant(
            text,
            m.group(1)
        )

    return []


def resolve_dynamic_hook_expression_local(
    expr,
    text,
    line,
    max_combinations=64,
):
    """
    Resolve simple dynamic WordPress hook expressions using a
    bounded local backward slice.

    No repository-wide symbol search is performed.
    """

    literal = parse_php_literal_string(
        expr
    )

    if literal is not None:
        return [literal]

    parts = split_php_concat(
        expr
    )

    if not parts:
        return []

    possibilities = [""]

    for part in parts:
        values = resolve_string_term_local(
            part,
            text,
            line
        )

        if not values:
            return []

        next_values = []

        for prefix in possibilities:
            for value in values:
                next_values.append(
                    prefix + value
                )

                if (
                    len(next_values)
                    >= max_combinations
                ):
                    break

            if (
                len(next_values)
                >= max_combinations
            ):
                break

        possibilities = next_values

    return sorted(
        set(possibilities)
    )


def resolve_dynamic_callback_expression_local(
    expr,
    text,
    line,
    max_candidates=64,
):
    """
    Resolve common dynamic callback expressions locally.

    Supported examples:

      [$this, $action]
      array($this, $action)

      $callback = [$this, 'save'];
      add_action(..., $callback)
    """

    direct = parse_generic_callback_expr(
        expr
    )

    if direct:
        return [direct]

    expr = expr.strip()

    # --------------------------------------------------------
    # [$this, $method_variable]
    # --------------------------------------------------------

    m = re.fullmatch(
        r"""
        (?:
            \[
            |
            array\s*\(
        )
        \s*\$this\s*,
        \s*
        \$([A-Za-z_][A-Za-z0-9_]*)
        \s*
        (?:\]|\))
        """,
        expr,
        re.X | re.I
    )

    if m:
        methods = (
            find_local_variable_string_values(
                text,
                line,
                m.group(1)
            )
        )

        return [
            {
                "type": "instance_method",
                "class": None,
                "function": method,
            }
            for method in methods[
                :max_candidates
            ]
        ]

    # --------------------------------------------------------
    # Callback variable:
    #
    # $callback = [$this, 'save'];
    # add_action('...', $callback);
    # --------------------------------------------------------

    m = re.fullmatch(
        r"\$([A-Za-z_][A-Za-z0-9_]*)",
        expr
    )

    if m:
        var = re.escape(
            m.group(1)
        )

        window = local_source_window(
            text,
            line,
            before_lines=120
        )

        assignment_re = re.compile(
            rf"""
            \${var}
            \s*=\s*
            (
                \[[^;]+?\]
                |
                array\s*\([^;]+?\)
                |
                ['"][^'"]+['"]
            )
            \s*;
            """,
            re.X | re.I | re.S
        )

        matches = list(
            assignment_re.finditer(window)
        )

        if matches:
            rhs = matches[-1].group(1)

            parsed = (
                parse_generic_callback_expr(
                    rhs
                )
            )

            if parsed:
                return [parsed]

    return []


def resolve_dynamic_registrations_v5(
    plugin_root,
    registrations,
):
    """
    Expand registrations whose hook or callback can be resolved
    by bounded local analysis.

    Returns:
      resolved_registrations
      resolver_stats

    Original registrations are never deleted solely because
    resolution fails.
    """

    result = []

    stats = {
        "input_registrations":
            len(registrations),

        "hook_expansions": 0,
        "callback_expansions": 0,

        "fully_resolved": 0,
        "still_dynamic_hook": 0,
        "still_dynamic_callback": 0,
    }

    for reg in registrations:
        file_name = (
            reg.get("registration", {})
            .get("file")
        )

        line = (
            reg.get("registration", {})
            .get("line")
        )

        if not file_name or not line:
            result.append(reg)
            continue

        path = plugin_root / file_name

        text = read_text(path)

        # ----------------------------------------------------
        # Resolve hook candidates.
        # ----------------------------------------------------

        if reg.get("hook"):
            hook_values = [
                reg["hook"]
            ]
        else:
            hook_values = (
                resolve_dynamic_hook_expression_local(
                    reg.get(
                        "hook_expression",
                        ""
                    ),
                    text,
                    line
                )
            )

            if hook_values:
                stats[
                    "hook_expansions"
                ] += len(hook_values)
            else:
                stats[
                    "still_dynamic_hook"
                ] += 1

        if not hook_values:
            hook_values = [None]

        # ----------------------------------------------------
        # Resolve callback candidates.
        # ----------------------------------------------------

        if reg.get("callback"):
            callbacks = [
                reg["callback"]
            ]
        else:
            callbacks = (
                resolve_dynamic_callback_expression_local(
                    reg.get(
                        "callback_expression",
                        ""
                    ),
                    text,
                    line
                )
            )

            if callbacks:
                stats[
                    "callback_expansions"
                ] += len(callbacks)
            else:
                stats[
                    "still_dynamic_callback"
                ] += 1

        if not callbacks:
            callbacks = [None]

        # ----------------------------------------------------
        # Cartesian expansion is deliberately bounded by
        # each resolver's maximum candidate limit.
        # ----------------------------------------------------

        for hook in hook_values:
            for callback in callbacks:
                clone = dict(reg)

                clone["hook"] = hook
                clone["callback"] = callback

                clone[
                    "surface_class"
                ] = classify_generic_hook_surface(
                    clone.get(
                        "registration_api"
                    ),
                    hook
                )

                clone[
                    "resolution"
                ] = {
                    "hook_resolved":
                        hook is not None,

                    "callback_resolved":
                        callback is not None,

                    "method":
                        "bounded_local_slice",
                }

                if (
                    hook is not None
                    and callback is not None
                ):
                    stats[
                        "fully_resolved"
                    ] += 1

                result.append(clone)

    return result, stats


def build_security_relevant_gap_units_v5(
    plugin_root,
    registrations,
    function_index,
):
    """
    Emit only unresolved gaps that can plausibly affect a
    request/security-relevant surface.

    This is the model-facing gap queue.

    The raw registration inventory remains available locally.
    """

    gap_units = []
    gap_id = 1

    for reg in registrations:
        hook = reg.get("hook")
        callback = reg.get("callback")

        surface = reg.get(
            "surface_class",
            "unknown"
        )

        # Fully resolved registrations are not gaps.
        if hook and callback:
            continue

        security_signal = False

        # A known/conditional public surface is inherently worth
        # resolving when callback semantics are unknown.
        if surface in {
            "known_public",
            "conditional",
        }:
            security_signal = True

        # If callback is known but hook semantics are dynamic,
        # profile the callback. Escalate only when it contains
        # security-relevant behavior.
        if callback and not hook:
            definitions = (
                resolve_generic_registration_callback(
                    reg,
                    function_index
                )
            )

            for definition in definitions:
                profile = (
                    profile_callback_security_v5(
                        definition,
                        function_index,
                        max_depth=3
                    )
                )

                if profile[
                    "security_relevant"
                ]:
                    security_signal = True
                    break

        if not security_signal:
            continue

        registration = reg.get(
            "registration",
            {}
        )

        if not hook:
            kind = "dynamic_hook"
            reason = (
                "Security-relevant WordPress registration "
                "has an unresolved dynamic hook."
            )
            required = [
                "bounded_backward_slice_hook",
                "resolve_dispatch_reachability",
            ]

        else:
            kind = "dynamic_callback"
            reason = (
                "Request-relevant WordPress registration "
                "has an unresolved dynamic callback."
            )
            required = [
                "bounded_backward_slice_callback",
                "resolve_callback_target",
            ]

        gap_units.append(
            make_gap_unit(
                f"WP-V5-GAP-{gap_id:04d}",
                kind,
                registration.get("file"),
                registration.get("line"),
                reason,
                local_context=
                    registration.get("code"),
                required_resolution=
                    required,
            )
        )

        gap_id += 1

    return gap_units



# ============================================================
# V5.4 LIGHTWEIGHT SOURCE-TO-EFFECT FLOW ANALYSIS
# ============================================================

VARIABLE_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)"
)


def extract_assigned_tainted_variables(body):
    """
    Identify variables directly assigned from common request sources.

    Examples:
        $id = $_GET['id'];
        $data = $request->get_json_params();
        $order_id = absint($_GET['order_id']);

    This is intentionally lightweight and conservative.
    """

    result = set()

    patterns = [
        re.compile(
            r"""
            \$([A-Za-z_][A-Za-z0-9_]*)
            \s*=\s*
            [^;]*
            \$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)
            \b
            """,
            re.X | re.I | re.S
        ),

        re.compile(
            r"""
            \$([A-Za-z_][A-Za-z0-9_]*)
            \s*=\s*
            [^;]*
            ->
            \s*
            get_(?:param|params|json_params|body)
            \s*\(
            """,
            re.X | re.I | re.S
        ),

        re.compile(
            r"""
            \$([A-Za-z_][A-Za-z0-9_]*)
            \s*=\s*
            [^;]*
            \$wp
            \s*->\s*
            query_vars
            """,
            re.X | re.I | re.S
        ),
    ]

    for regex in patterns:
        for m in regex.finditer(body):
            result.add(
                m.group(1)
            )

    return result


def extract_function_parameter_names(definition):
    """
    Best-effort parameter extraction from indexed function body metadata.
    """

    body = definition.get("body", "")

    # The indexed body normally begins at or near the function
    # declaration. Restrict search to the first part.
    head = body[:1500]

    m = re.search(
        r"""
        function
        \s+
        [A-Za-z_][A-Za-z0-9_]*
        \s*
        \(
        (.*?)
        \)
        """,
        head,
        re.X | re.I | re.S
    )

    if not m:
        return []

    params = []

    for name in VARIABLE_RE.findall(
        m.group(1)
    ):
        params.append(name)

    return params


def expression_contains_tainted_variable(
    expr,
    tainted
):
    vars_found = set(
        VARIABLE_RE.findall(expr)
    )

    return bool(
        vars_found & tainted
    )


def find_calls_with_tainted_arguments(
    body,
    tainted
):
    """
    Detect common function/method calls whose argument expression
    directly contains a tainted local variable.
    """

    result = []

    # foo(...)
    # $this->foo(...)
    # Class::foo(...)
    call_re = re.compile(
        r"""
        (
            (?:
                \$this\s*->\s*
                |
                [A-Za-z_][A-Za-z0-9_\\]*\s*::\s*
            )?
            [A-Za-z_][A-Za-z0-9_]*
        )
        \s*
        \(
        """,
        re.X
    )

    for m in call_re.finditer(body):
        call = extract_balanced_call(
            body,
            m.start()
        )

        if not call:
            continue

        if expression_contains_tainted_variable(
            call,
            tainted
        ):
            result.append({
                "call": m.group(1),
                "expression": call[:1200],
            })

    return result


def body_has_effect_with_tainted_variable(
    body,
    tainted
):
    """
    Determine whether a security-sensitive effect invocation directly
    contains a tainted variable.

    This establishes a strong local flow signal, not full PHP taint
    proof.
    """

    effect_regexes = []

    for regexes in SINK_PATTERNS.values():
        effect_regexes.extend(regexes)

    for regexes in OUTPUT_EFFECT_PATTERNS.values():
        effect_regexes.extend(regexes)

    # Object lookups are also security-relevant effects.
    effect_regexes.extend(
        OBJECT_LOOKUP_PATTERNS
    )

    for regex in effect_regexes:
        for m in regex.finditer(body):
            call = extract_balanced_call(
                body,
                m.start()
            )

            if not call:
                # output statements like echo may not be function calls
                start = m.start()
                excerpt = body[
                    start:
                    min(len(body), start + 1200)
                ]

                if expression_contains_tainted_variable(
                    excerpt,
                    tainted
                ):
                    return True

                continue

            if expression_contains_tainted_variable(
                call,
                tainted
            ):
                return True

    return False


def classify_local_flow_v5(definition):
    """
    Classify direct source-to-effect relation inside one function.
    """

    body = definition.get("body", "")

    tainted = extract_assigned_tainted_variables(
        body
    )

    if not tainted:
        return {
            "confidence": "unknown",
            "tainted_variables": [],
            "direct_effect_flow": False,
            "tainted_calls": [],
        }

    direct = (
        body_has_effect_with_tainted_variable(
            body,
            tainted
        )
    )

    calls = find_calls_with_tainted_arguments(
        body,
        tainted
    )

    if direct:
        confidence = "confirmed"

    elif calls:
        confidence = "probable"

    else:
        confidence = "reachability_only"

    return {
        "confidence": confidence,
        "tainted_variables":
            sorted(tainted),

        "direct_effect_flow":
            direct,

        "tainted_calls":
            calls,
    }


def aggregate_flow_confidence_v5(
    reachable_nodes
):
    """
    Aggregate local flow signals across the bounded reachable graph.

    Important:
    reachability_only is retained rather than suppressed.
    """

    rank = {
        "unknown": 0,
        "reachability_only": 1,
        "probable": 2,
        "confirmed": 3,
    }

    best = "unknown"
    evidence = []

    for node in reachable_nodes:
        flow = classify_local_flow_v5(
            node
        )

        if (
            rank[flow["confidence"]]
            > rank[best]
        ):
            best = flow["confidence"]

        if flow["confidence"] != "unknown":
            evidence.append({
                "file": node.get("file"),
                "line": node.get("line"),
                "class": node.get("class"),
                "function": node.get("name"),
                **flow,
            })

    return {
        "confidence": best,
        "evidence": evidence,
    }



# ============================================================
# V5.5 INTERPROCEDURAL TAINT PROPAGATION
# ============================================================

def split_call_arguments_v5(call_text):
    """
    Reuse the generic balanced argument splitter for ordinary
    function/method calls.
    """

    return split_php_call_arguments(
        call_text
    )


def extract_call_target_v5(
    call_text
):
    """
    Parse the callable prefix of a PHP call.

    Supported:
      foo(...)
      $this->foo(...)
      ClassName::foo(...)
      self::foo(...)
      static::foo(...)
      parent::foo(...)
    """

    m = re.match(
        r"""
        \s*
        (?:
            \$this\s*->\s*
            ([A-Za-z_][A-Za-z0-9_]*)
            |
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
            |
            ([A-Za-z_][A-Za-z0-9_]*)
        )
        \s*\(
        """,
        call_text,
        re.X
    )

    if not m:
        return None

    if m.group(1):
        return {
            "type": "instance_method",
            "class": None,
            "function": m.group(1),
        }

    if m.group(2):
        return {
            "type": "static_method",
            "class": m.group(2),
            "function": m.group(3),
        }

    return {
        "type": "function",
        "class": None,
        "function": m.group(4),
    }


def resolve_call_target_v5(
    target,
    caller_definition,
    function_index,
):
    """
    Resolve a parsed call target conservatively against the
    plugin-local function index.
    """

    if not target:
        return []

    name = target.get("function")

    if not name:
        return []

    definitions = function_index.get(
        name.lower(),
        []
    )

    if not definitions:
        return []

    call_type = target.get(
        "type"
    )

    caller_class = (
        caller_definition.get("class")
    )

    if call_type == "instance_method":
        if caller_class:
            filtered = [
                d for d in definitions
                if d.get("class")
                and d["class"].split("\\")[-1].lower()
                    == caller_class.split("\\")[-1].lower()
            ]

            if filtered:
                return filtered

        return []

    if call_type == "static_method":
        cls = target.get("class")

        if (
            cls
            and cls.lower()
            in {"self", "static"}
        ):
            cls = caller_class

        if (
            cls
            and cls.lower() == "parent"
        ):
            # Parent resolution requires inheritance semantics.
            # Leave unresolved here rather than guessing.
            return []

        if cls:
            wanted = (
                cls.split("\\")[-1].lower()
            )

            filtered = [
                d for d in definitions
                if d.get("class")
                and d["class"].split("\\")[-1].lower()
                    == wanted
            ]

            if filtered:
                return filtered

            return []

    # Plain functions resolve only to global functions.
    if call_type == "function":
        return [
            d for d in definitions
            if not d.get("class")
        ]

    return []


def derive_tainted_parameters_v5(
    caller_definition,
    callee_definition,
    call_text,
    caller_tainted,
):
    """
    Map tainted caller arguments to callee parameters by position.

    Example:

      $id = $_GET['id'];
      load_order($id);

      function load_order($order_id) {}

    => order_id becomes tainted.
    """

    args = split_call_arguments_v5(
        call_text
    )

    params = (
        extract_function_parameter_names(
            callee_definition
        )
    )

    if not args or not params:
        return set()

    tainted_params = set()

    for index, arg in enumerate(args):
        if index >= len(params):
            break

        if expression_contains_tainted_variable(
            arg,
            caller_tainted
        ):
            tainted_params.add(
                params[index]
            )

    return tainted_params


def propagate_local_assignments_v5(
    body,
    tainted,
    max_rounds=8,
):
    """
    Propagate simple local assignments.

    Examples:

        $a = $input;
        $b = absint($a);
        $c = sanitize_text_field($b);

    Sanitization is intentionally NOT treated as taint removal here.
    A sanitizer may restrict syntax without establishing authorization.
    """

    result = set(tainted)

    assignment_re = re.compile(
        r"""
        \$([A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        ([^;]+)
        ;
        """,
        re.X | re.S
    )

    for _ in range(max_rounds):
        changed = False

        for m in assignment_re.finditer(body):
            target = m.group(1)
            expr = m.group(2)

            if (
                target not in result
                and expression_contains_tainted_variable(
                    expr,
                    result
                )
            ):
                result.add(target)
                changed = True

        if not changed:
            break

    return result


def extract_resolvable_calls_v5(
    definition
):
    """
    Collect balanced plugin-call expressions from one function.

    Built-ins may appear in the result but are ignored later when
    they cannot resolve against the plugin-local function index.
    """

    body = definition.get(
        "body",
        ""
    )

    result = []
    seen = set()

    call_start_re = re.compile(
        r"""
        (?<![\w])
        (
            \$this\s*->\s*
            [A-Za-z_][A-Za-z0-9_]*
            |
            (?:
                [A-Za-z_][A-Za-z0-9_\\]*
                |
                self
                |
                static
                |
                parent
            )
            \s*::\s*
            [A-Za-z_][A-Za-z0-9_]*
            |
            [A-Za-z_][A-Za-z0-9_]*
        )
        \s*\(
        """,
        re.X
    )

    for m in call_start_re.finditer(body):
        call = extract_balanced_call(
            body,
            m.start()
        )

        if not call:
            continue

        key = (
            m.start(),
            call[:300]
        )

        if key in seen:
            continue

        seen.add(key)

        target = extract_call_target_v5(
            call
        )

        if not target:
            continue

        result.append({
            "offset": m.start(),
            "call": call,
            "target": target,
        })

    return result


def node_has_tainted_effect_v5(
    definition,
    tainted,
):
    """
    Check whether taint reaches a locally visible security effect.
    """

    if not tainted:
        return False

    body = definition.get(
        "body",
        ""
    )

    expanded = (
        propagate_local_assignments_v5(
            body,
            tainted
        )
    )

    return (
        body_has_effect_with_tainted_variable(
            body,
            expanded
        )
    )


def interprocedural_taint_v5(
    root_definition,
    function_index,
    max_depth=3,
    max_states=256,
):
    """
    Bounded argument-to-parameter taint propagation.

    This is deliberately NOT a full PHP abstract interpreter.

    It follows:
      request source
      -> local variable
      -> local assignments
      -> function/method argument
      -> callee parameter
      -> sensitive effect

    Returns explicit flow evidence suitable for model review.
    """

    root_body = root_definition.get(
        "body",
        ""
    )

    initial = (
        extract_assigned_tainted_variables(
            root_body
        )
    )

    initial = (
        propagate_local_assignments_v5(
            root_body,
            initial
        )
    )

    if not initial:
        return {
            "confidence": "unknown",
            "confirmed_paths": [],
            "propagated_states": 0,
        }

    queue = [{
        "definition":
            root_definition,

        "tainted":
            initial,

        "depth":
            0,

        "path": [{
            "file":
                root_definition.get("file"),
            "line":
                root_definition.get("line"),
            "class":
                root_definition.get("class"),
            "function":
                root_definition.get("name"),
            "tainted":
                sorted(initial),
        }],
    }]

    visited = set()
    confirmed = []

    states = 0

    while queue and states < max_states:
        state = queue.pop(0)

        definition = state[
            "definition"
        ]

        tainted = (
            propagate_local_assignments_v5(
                definition.get("body", ""),
                state["tainted"]
            )
        )

        identity = (
            function_identity(definition),
            tuple(sorted(tainted)),
            state["depth"],
        )

        if identity in visited:
            continue

        visited.add(identity)
        states += 1

        if node_has_tainted_effect_v5(
            definition,
            tainted
        ):
            confirmed.append({
                "path": state["path"],
                "sink": {
                    "file":
                        definition.get("file"),
                    "line":
                        definition.get("line"),
                    "class":
                        definition.get("class"),
                    "function":
                        definition.get("name"),
                },
            })

        if state["depth"] >= max_depth:
            continue

        for call_info in (
            extract_resolvable_calls_v5(
                definition
            )
        ):
            call_text = (
                call_info["call"]
            )

            # If no tainted variable appears in the arguments,
            # this call cannot propagate our current taint.
            args = split_call_arguments_v5(
                call_text
            )

            if not any(
                expression_contains_tainted_variable(
                    arg,
                    tainted
                )
                for arg in args
            ):
                continue

            targets = resolve_call_target_v5(
                call_info["target"],
                definition,
                function_index
            )

            for callee in targets:
                callee_tainted = (
                    derive_tainted_parameters_v5(
                        definition,
                        callee,
                        call_text,
                        tainted
                    )
                )

                if not callee_tainted:
                    continue

                callee_tainted = (
                    propagate_local_assignments_v5(
                        callee.get("body", ""),
                        callee_tainted
                    )
                )

                label = callee.get(
                    "name"
                )

                if callee.get("class"):
                    label = (
                        f'{callee["class"]}::'
                        f'{callee["name"]}'
                    )

                queue.append({
                    "definition":
                        callee,

                    "tainted":
                        callee_tainted,

                    "depth":
                        state["depth"] + 1,

                    "path":
                        state["path"] + [{
                            "file":
                                callee.get("file"),
                            "line":
                                callee.get("line"),
                            "class":
                                callee.get("class"),
                            "function":
                                callee.get("name"),
                            "label":
                                label,
                            "tainted":
                                sorted(
                                    callee_tainted
                                ),
                        }],
                })

    if confirmed:
        confidence = "confirmed"

    elif states > 1:
        confidence = "probable"

    else:
        confidence = (
            classify_local_flow_v5(
                root_definition
            )["confidence"]
        )

    return {
        "confidence":
            confidence,

        "confirmed_paths":
            confirmed,

        "propagated_states":
            states,
    }



# ============================================================
# V5.6 DOWNSTREAM SOURCE SEEDING
# ============================================================

def discover_source_seeds_v5(
    root_definition,
    function_index,
    max_depth=3,
):
    """
    Discover request-controlled source variables anywhere in the
    bounded reachable call graph.

    This handles callbacks that delegate request parsing to a helper.

    Example:

        callback()
            -> controller()
                -> $id = $_GET['id']
                -> sensitive_effect($id)

    The root callback itself does not need to contain a source.
    """

    reachable, call_paths = build_reachable_graph(
        root_definition,
        function_index,
        max_depth=max_depth
    )

    seeds = []

    for node in reachable:
        body = node.get("body", "")

        tainted = (
            extract_assigned_tainted_variables(
                body
            )
        )

        tainted = (
            propagate_local_assignments_v5(
                body,
                tainted
            )
        )

        if not tainted:
            continue

        seeds.append({
            "definition": node,
            "tainted": tainted,
            "source": {
                "file": node.get("file"),
                "line": node.get("line"),
                "class": node.get("class"),
                "function": node.get("name"),
                "variables": sorted(tainted),
            },
        })

    return {
        "seeds": seeds,
        "reachable": reachable,
        "call_paths": call_paths,
    }


def propagate_from_seed_v5(
    seed_definition,
    seed_tainted,
    function_index,
    max_depth=3,
    max_states=256,
):
    """
    Run the existing bounded taint propagation starting from an
    explicitly supplied source seed.
    """

    initial = (
        propagate_local_assignments_v5(
            seed_definition.get("body", ""),
            set(seed_tainted)
        )
    )

    queue = [{
        "definition": seed_definition,
        "tainted": initial,
        "depth": 0,
        "path": [{
            "file": seed_definition.get("file"),
            "line": seed_definition.get("line"),
            "class": seed_definition.get("class"),
            "function": seed_definition.get("name"),
            "tainted": sorted(initial),
        }],
    }]

    visited = set()
    confirmed = []
    states = 0

    while queue and states < max_states:
        state = queue.pop(0)

        definition = state["definition"]

        tainted = (
            propagate_local_assignments_v5(
                definition.get("body", ""),
                state["tainted"]
            )
        )

        identity = (
            function_identity(definition),
            tuple(sorted(tainted)),
            state["depth"],
        )

        if identity in visited:
            continue

        visited.add(identity)
        states += 1

        if node_has_tainted_effect_v5(
            definition,
            tainted
        ):
            confirmed.append({
                "path": state["path"],
                "sink": {
                    "file": definition.get("file"),
                    "line": definition.get("line"),
                    "class": definition.get("class"),
                    "function": definition.get("name"),
                },
            })

        if state["depth"] >= max_depth:
            continue

        for call_info in (
            extract_resolvable_calls_v5(
                definition
            )
        ):
            call_text = call_info["call"]

            args = split_call_arguments_v5(
                call_text
            )

            if not any(
                expression_contains_tainted_variable(
                    arg,
                    tainted
                )
                for arg in args
            ):
                continue

            targets = resolve_call_target_v5(
                call_info["target"],
                definition,
                function_index
            )

            for callee in targets:
                callee_tainted = (
                    derive_tainted_parameters_v5(
                        definition,
                        callee,
                        call_text,
                        tainted
                    )
                )

                if not callee_tainted:
                    continue

                callee_tainted = (
                    propagate_local_assignments_v5(
                        callee.get("body", ""),
                        callee_tainted
                    )
                )

                queue.append({
                    "definition": callee,
                    "tainted": callee_tainted,
                    "depth": state["depth"] + 1,
                    "path": state["path"] + [{
                        "file": callee.get("file"),
                        "line": callee.get("line"),
                        "class": callee.get("class"),
                        "function": callee.get("name"),
                        "tainted": sorted(
                            callee_tainted
                        ),
                    }],
                })

    return {
        "confirmed_paths": confirmed,
        "propagated_states": states,
    }


def security_flow_v5(
    root_definition,
    function_index,
    max_depth=3,
):
    """
    Unified V5 flow analysis.

    Phase 1:
        Try ordinary root-source interprocedural taint.

    Phase 2:
        Discover request sources introduced by reachable helpers.

    No candidate is suppressed merely because flow remains unknown.
    """

    direct = interprocedural_taint_v5(
        root_definition,
        function_index,
        max_depth=max_depth
    )

    if direct["confidence"] == "confirmed":
        return {
            **direct,
            "source_origin": "root_or_propagated",
        }

    discovery = discover_source_seeds_v5(
        root_definition,
        function_index,
        max_depth=max_depth
    )

    confirmed_paths = []
    total_states = 0

    for seed in discovery["seeds"]:
        result = propagate_from_seed_v5(
            seed["definition"],
            seed["tainted"],
            function_index,
            max_depth=max_depth
        )

        total_states += result[
            "propagated_states"
        ]

        for path in result[
            "confirmed_paths"
        ]:
            confirmed_paths.append({
                **path,
                "source_seed":
                    seed["source"],
            })

    if confirmed_paths:
        confidence = "confirmed"

    elif discovery["seeds"]:
        confidence = "probable"

    elif direct["confidence"] != "unknown":
        confidence = direct["confidence"]

    else:
        confidence = "unknown"

    return {
        "confidence":
            confidence,

        "confirmed_paths":
            confirmed_paths
            or direct.get(
                "confirmed_paths",
                []
            ),

        "propagated_states":
            total_states
            + direct.get(
                "propagated_states",
                0
            ),

        "source_seed_count":
            len(discovery["seeds"]),

        "source_origin":
            (
                "downstream_helper"
                if discovery["seeds"]
                else "none"
            ),
    }


# ============================================================
# V5.2 GENERIC CALLBACK SECURITY PROFILING
# ============================================================

OBJECT_LOOKUP_PATTERNS = [
    re.compile(r"\bwc_get_order\s*\(", re.I),
    re.compile(r"\bget_post\s*\(", re.I),
    re.compile(r"\bget_user_by\s*\(", re.I),
    re.compile(r"\bget_user_meta\s*\(", re.I),
    re.compile(r"\bget_post_meta\s*\(", re.I),
]


OUTPUT_EFFECT_PATTERNS = {
    "redirect": [
        re.compile(r"\bwp_redirect\s*\(", re.I),
        re.compile(r"\bwp_safe_redirect\s*\(", re.I),
    ],

    "json_response": [
        re.compile(r"\bwp_send_json(?:_success|_error)?\s*\(", re.I),
        re.compile(r"\bWP_REST_Response\s*\(", re.I),
    ],

    "http_response": [
        re.compile(r"\becho\b", re.I),
        re.compile(r"\bprint\s*\(", re.I),
    ],

    "download": [
        re.compile(r"\breadfile\s*\(", re.I),
    ],
}


REQUEST_SOURCE_PATTERNS_V5 = [
    re.compile(r"\$_GET\b"),
    re.compile(r"\$_POST\b"),
    re.compile(r"\$_REQUEST\b"),
    re.compile(r"\$_FILES\b"),
    re.compile(r"\$_COOKIE\b"),
    re.compile(r"\$_SERVER\b"),

    re.compile(r"->\s*get_param\s*\("),
    re.compile(r"->\s*get_params\s*\("),
    re.compile(r"->\s*get_json_params\s*\("),
    re.compile(r"->\s*get_body\s*\("),

    re.compile(r"\$wp\s*->\s*query_vars\b"),
]


AUTHORIZATION_PATTERNS_V5 = {
    "authentication": [
        re.compile(r"\bis_user_logged_in\s*\("),
        re.compile(r"\bwp_get_current_user\s*\("),
    ],

    "capability": [
        re.compile(r"\bcurrent_user_can\s*\("),
        re.compile(r"\buser_can\s*\("),
    ],

    "nonce": [
        re.compile(r"\bcheck_ajax_referer\s*\("),
        re.compile(r"\bcheck_admin_referer\s*\("),
        re.compile(r"\bwp_verify_nonce\s*\("),
    ],

    "ownership_hint": [
        re.compile(r"\bget_current_user_id\s*\("),
        re.compile(r"->\s*get_user_id\s*\("),
        re.compile(r"->\s*get_customer_id\s*\("),
        re.compile(r"->\s*get_customer_user\s*\("),
    ],
}


def detect_request_source_v5(body):
    return any(
        regex.search(body)
        for regex in REQUEST_SOURCE_PATTERNS_V5
    )


def detect_object_lookup_v5(body):
    return any(
        regex.search(body)
        for regex in OBJECT_LOOKUP_PATTERNS
    )


def detect_output_effects_v5(body):
    effects = []

    for kind, regexes in OUTPUT_EFFECT_PATTERNS.items():
        if any(regex.search(body) for regex in regexes):
            effects.append(kind)

    return sorted(set(effects))


def detect_authorization_hints_v5(body):
    result = []

    for kind, regexes in AUTHORIZATION_PATTERNS_V5.items():
        if any(regex.search(body) for regex in regexes):
            result.append(kind)

    return sorted(set(result))


def profile_callback_security_v5(
    definition,
    function_index,
    max_depth=3
):
    """
    Produce a generic security-relevance profile.

    This is NOT vulnerability validation.
    It only determines whether the callback deserves semantic review.
    """

    reachable, call_paths = build_reachable_graph(
        definition,
        function_index,
        max_depth=max_depth
    )

    sources = set()
    controls = set()
    effects = set()

    has_request_source = False
    has_object_lookup = False

    relevant_functions = []

    for node in reachable:
        body = node.get("body", "")

        local_sources = detect_sources(body)

        local_controls = detect_patterns(
            body,
            CONTROL_PATTERNS
        )

        local_sinks = detect_patterns(
            body,
            SINK_PATTERNS
        )

        local_outputs = detect_output_effects_v5(
            body
        )

        request_source = (
            detect_request_source_v5(body)
        )

        object_lookup = (
            detect_object_lookup_v5(body)
        )

        auth_hints = (
            detect_authorization_hints_v5(body)
        )

        sources.update(
            normalize_sources_v5(local_sources)
        )

        controls.update(
            normalize_controls_v5(local_controls)
        )

        controls.update(auth_hints)

        effects.update(
            normalize_effects_v5(local_sinks)
        )

        effects.update(local_outputs)

        if object_lookup:
            effects.add("object_lookup")

        has_request_source |= request_source
        has_object_lookup |= object_lookup

        if (
            local_sources
            or local_controls
            or local_sinks
            or local_outputs
            or request_source
            or object_lookup
            or auth_hints
        ):
            relevant_functions.append({
                "file": node.get("file"),
                "line": node.get("line"),
                "class": node.get("class"),
                "name": node.get("name"),
                "request_source": request_source,
                "object_lookup": object_lookup,
                "sources":
                    normalize_sources_v5(local_sources),
                "controls":
                    sorted(set(
                        normalize_controls_v5(
                            local_controls
                        )
                        + auth_hints
                    )),
                "effects":
                    sorted(set(
                        normalize_effects_v5(
                            local_sinks
                        )
                        + local_outputs
                        + (
                            ["object_lookup"]
                            if object_lookup
                            else []
                        )
                    )),
            })

    # Generic promotion conditions.
    #
    # Important:
    # We do not require a classic dangerous sink.
    #
    # Public request + object lookup + output is interesting.
    # Request input + sensitive mutation is interesting.
    # Sensitive effect reachable from public/conditional callback is
    # interesting even when taint is not yet proven.
    sensitive_effects = effects & {
        "code_execution",
        "dynamic_include",
        "deserialization",

        "database_write",
        "configuration_write",

        "file_read",
        "file_write",
        "file_delete",
        "file_upload",

        "user_create",
        "user_update",
        "role_change",
        "capability_change",
        "session_change",

        "object_lookup",
        "object_read",
        "object_update",
        "object_delete",
        "secret_read",
        "sensitive_metadata_read",
        "payment_state_change",

        "redirect",
        "json_response",
        "download",
        "header_output",
    }

    security_relevant = bool(
        sensitive_effects
        and (
            has_request_source
            or has_object_lookup
            or effects & {
                "redirect",
                "json_response",
                "download",
                "header_output",
            }
        )
    )

    return {
        "security_relevant":
            security_relevant,

        "has_request_source":
            has_request_source,

        "has_object_lookup":
            has_object_lookup,

        "sources":
            sorted(sources),

        "controls":
            sorted(controls),

        "effects":
            sorted(effects),

        "reachable_function_count":
            len(reachable),

        "call_edge_count":
            len(call_paths),

        "relevant_functions":
            relevant_functions,

        "call_paths":
            call_paths,
    }


def resolve_generic_registration_callback(
    registration,
    function_index
):
    callback = registration.get("callback")

    if not callback:
        return []

    # Anonymous callbacks are valid request-surface definitions.
    # Reuse the same synthetic-definition representation used by
    # resolve_callback() so generic V5 review-unit generation can
    # inspect the closure body without inventing a named function.
    if callback.get("type") == "anonymous":
        body = callback.get("body")

        if not isinstance(body, str) or not body.strip():
            return []

        registration_meta = registration.get(
            "registration",
            {}
        )

        registration_file = (
            callback.get("registration_file")
            or registration_meta.get("file")
        )

        registration_line = (
            callback.get("registration_line")
            or registration_meta.get("line")
        )

        return [{
            "name": (
                "__rest_anonymous_callback_"
                f"{registration_line or 'unknown'}"
            ),
            "class": None,
            "file": registration_file,
            "line": registration_line,
            "body": body,
        }]

    name = callback.get("function")

    if not name:
        return []

    definitions = function_index.get(
        name.lower(),
        []
    )

    cls = callback.get("class")

    if cls:
        wanted = cls.split("\\")[-1].lower()

        filtered = [
            x for x in definitions
            if x.get("class")
            and x["class"].split("\\")[-1].lower()
                == wanted
        ]

        if filtered:
            return filtered

    return definitions


def build_rest_review_units_v5(
    rest_entrypoints,
    function_index,
):
    """
    Build V5 review units directly from register_rest_route()
    entrypoints.

    REST routes are collected separately from generic hook
    registrations, so they must be explicitly promoted into the
    V5 review queue.
    """
    units = []
    unit_id = 1

    for reg in rest_entrypoints:
        definitions = resolve_generic_registration_callback(
            reg,
            function_index
        )

        if not definitions:
            continue

        for definition in definitions:
            profile = profile_callback_security_v5(
                definition,
                function_index,
                max_depth=3
            )

            if not profile["security_relevant"]:
                continue

            minimum_access = reg.get(
                "minimum_access"
            )

            units.append({
                "id":
                    f"WP-V5-REST-{unit_id:04d}",

                "surface_class": (
                    "known_public"
                    if minimum_access
                    == "unauthenticated"
                    else "unknown"
                ),

                "registration_api":
                    "register_rest_route",

                "hook":
                    "register_rest_route",

                "registration":
                    reg.get(
                        "registration",
                        {}
                    ),

                "minimum_access":
                    minimum_access,

                "callback": {
                    "file":
                        definition.get("file"),
                    "line":
                        definition.get("line"),
                    "class":
                        definition.get("class"),
                    "name":
                        definition.get("name"),
                },

                "sources":
                    profile["sources"],

                "controls":
                    profile["controls"],

                "effects":
                    profile["effects"],

                "signals": {
                    "request_source":
                        profile["has_request_source"],
                    "object_lookup":
                        profile["has_object_lookup"],
                },

                "graph_summary": {
                    "reachable_functions":
                        profile[
                            "reachable_function_count"
                        ],
                    "call_edges":
                        profile[
                            "call_edge_count"
                        ],
                },

                "relevant_functions":
                    profile["relevant_functions"],

                "call_paths":
                    profile["call_paths"],

                "flow_confidence":
                    "reachability_only",
            })

            unit_id += 1

    return units



def build_generic_review_units_v5(
    registrations,
    function_index
):
    """
    Promote only security-relevant request surfaces.

    Unknown/dynamic registrations remain GAP_UNITs elsewhere.
    """

    units = []
    unit_id = 1

    for reg in registrations:
        if reg.get("surface_class") not in {
            "known_public",
            "conditional",
            "unknown",
        }:
            continue

        definitions = (
            resolve_generic_registration_callback(
                reg,
                function_index
            )
        )

        if not definitions:
            continue

        for definition in definitions:
            profile = profile_callback_security_v5(
                definition,
                function_index,
                max_depth=3
            )

            if not profile["security_relevant"]:
                continue

            units.append({
                "id":
                    f"WP-V5-UNIT-{unit_id:04d}",

                "surface_class":
                    reg.get("surface_class"),

                "registration_api":
                    reg.get("registration_api"),

                "hook":
                    reg.get("hook"),

                "registration":
                    reg.get("registration"),

                "callback": {
                    "file":
                        definition.get("file"),

                    "line":
                        definition.get("line"),

                    "class":
                        definition.get("class"),

                    "name":
                        definition.get("name"),
                },

                "sources":
                    profile["sources"],

                "controls":
                    profile["controls"],

                "effects":
                    profile["effects"],

                "signals": {
                    "request_source":
                        profile[
                            "has_request_source"
                        ],

                    "object_lookup":
                        profile[
                            "has_object_lookup"
                        ],
                },

                "graph_summary": {
                    "reachable_functions":
                        profile[
                            "reachable_function_count"
                        ],

                    "call_edges":
                        profile[
                            "call_edge_count"
                        ],
                },

                "relevant_functions":
                    profile[
                        "relevant_functions"
                    ],

                "call_paths":
                    profile["call_paths"],

                # Until V5 dataflow is implemented, this remains
                # conservative.
                "flow_confidence":
                    "reachability_only",
            })

            unit_id += 1

    return units


# ============================================================
# CALLBACK RESOLUTION
# ============================================================

def resolve_callback(entrypoint, function_index):
    callback = entrypoint["callback"]

    callback_type = callback.get("type")

    # --------------------------------------------------------
    # Anonymous REST closure
    #
    # Treat the closure as a local synthetic definition so the
    # existing V5 source/control/sink and bounded call-graph
    # analysis can inspect its body.
    #
    # This is generic and does not depend on route names,
    # plugin names, service classes, or framework conventions.
    # --------------------------------------------------------

    if callback_type == "anonymous":
        body = callback.get("body")

        if not isinstance(body, str) or not body.strip():
            return []

        registration_file = callback.get(
            "registration_file"
        )

        registration_line = callback.get(
            "registration_line"
        )

        synthetic_name = (
            "__rest_anonymous_callback_"
            f"{registration_line or 'unknown'}"
        )

        return [{
            "name": synthetic_name,
            "class": None,
            "file": registration_file,
            "line": registration_line,
            "body": body,
        }]

    # --------------------------------------------------------
    # Dynamic / unresolved callback
    #
    # Do not invent a target. The REST registration remains
    # visible to the unresolved-entrypoint coverage path.
    # --------------------------------------------------------

    callback_function = callback.get("function")

    if not isinstance(callback_function, str):
        return []

    if not callback_function.strip():
        return []

    name = callback_function.lower()

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
# V5 SECURITY GRAPH OUTPUT
# ============================================================

FLOW_RANK_V5 = {
    "unknown": 0,
    "reachability_only": 1,
    "probable": 2,
    "confirmed": 3,
}


def resolve_unit_definition_v5(
    unit,
    function_index,
):
    cb = unit.get("callback", {})

    name = cb.get("name")

    if not name:
        return []

    definitions = function_index.get(
        name.lower(),
        []
    )

    exact = [
        d for d in definitions
        if d.get("file") == cb.get("file")
        and d.get("line") == cb.get("line")
    ]

    return exact or definitions


def enrich_review_units_with_flow_v5(
    units,
    function_index,
):
    """
    Attach the strongest deterministic flow result to each unit.

    Unknown is retained and never interpreted as safe.
    """

    result = []

    for unit in units:
        clone = dict(unit)

        best = {
            "confidence": "unknown",
            "confirmed_paths": [],
            "propagated_states": 0,
            "source_seed_count": 0,
            "source_origin": "none",
        }

        for definition in (
            resolve_unit_definition_v5(
                unit,
                function_index
            )
        ):
            flow = security_flow_v5(
                definition,
                function_index,
                max_depth=3
            )

            if (
                FLOW_RANK_V5.get(
                    flow.get(
                        "confidence",
                        "unknown"
                    ),
                    0
                )
                >
                FLOW_RANK_V5.get(
                    best.get(
                        "confidence",
                        "unknown"
                    ),
                    0
                )
            ):
                best = flow

        clone["flow"] = best

        result.append(clone)

    return result


HIGH_IMPACT_V5_EFFECTS = {
    "code_execution",
    "dynamic_include",
    "deserialization",
    "configuration_write",
    "database_write",
    "file_write",
    "file_upload",
    "file_delete",
    "role_change",
    "capability_change",
    "session_change",
    "object_update",
    "object_delete",
    "secret_read",
}


def v5_access_is_low_privilege(unit):
    access = str(unit.get("minimum_access") or "").lower()
    surface = str(unit.get("surface_class") or "").lower()
    hook = str(unit.get("hook") or "").lower()

    return access in {
        "unauthenticated",
        "public",
        "unknown_permission_callback",
        "permission_callback_requires_analysis",
    } or "nopriv" in hook or surface == "known_public"


def v5_review_priority(unit):
    """
    Model-work priority, not vulnerability severity.

    A priority label never suppresses a unit. High-impact effects receive
    a conservative deep-review floor on public/low-privilege surfaces and
    whenever deterministic flow is unknown.
    """

    flow = (
        unit.get("flow", {})
        .get("confidence", "unknown")
    )

    surface = unit.get(
        "surface_class"
    )

    signals = unit.get(
        "signals",
        {}
    )

    effects = set(
        unit.get("effects", [])
    )

    score = 0

    if surface == "known_public":
        score += 50
    elif surface == "conditional":
        score += 30

    if flow == "confirmed":
        score += 60
    elif flow == "probable":
        score += 35
    elif flow == "reachability_only":
        score += 15
    else:
        # Unknown is not safe.
        score += 20

    if signals.get("request_source"):
        score += 20

    if signals.get("object_lookup"):
        score += 25

    high_effects = HIGH_IMPACT_V5_EFFECTS | {
        "payment_state_change",
    }

    exposure_effects = {
        "redirect",
        "json_response",
        "download",
        "header_output",
    }

    if effects & high_effects:
        score += 35

    if effects & exposure_effects:
        score += 20

    if score >= 120:
        label = "deep"
    elif score >= 80:
        label = "normal"
    else:
        label = "bounded"

    high_impact = bool(effects & HIGH_IMPACT_V5_EFFECTS)
    low_privilege = v5_access_is_low_privilege(unit)
    flow_unknown = flow == "unknown"

    # Recall-first safety floor. A dangerous sink on an exposed/unknown path
    # must get semantic review even when heuristics cannot prove the flow.
    if high_impact and (low_privilege or flow_unknown):
        label = "deep"

    return {
        "score": score,
        "review_effort": label,
        "coverage_floor": (
            "deep"
            if high_impact and (low_privilege or flow_unknown)
            else "none"
        ),
        "must_review": True,
    }


def build_review_index_v5(
    units,
):
    """
    Compact model-facing queue.

    Do not embed complete call graphs or full code bodies.
    """

    result = []

    for unit in units:
        priority = v5_review_priority(
            unit
        )

        flow = unit.get(
            "flow",
            {}
        )

        result.append({
            "id":
                unit.get("id"),

            "priority_score":
                priority["score"],

            "review_effort":
                priority["review_effort"],
            "coverage_floor":
                priority.get("coverage_floor", "none"),
            "must_review": True,

            "surface_class":
                unit.get("surface_class"),

            "registration_api":
                unit.get("registration_api"),

            "hook":
                unit.get("hook"),

            "registration":
                {
                    "file":
                        unit.get(
                            "registration",
                            {}
                        ).get("file"),

                    "line":
                        unit.get(
                            "registration",
                            {}
                        ).get("line"),
                },

            "callback":
                unit.get("callback"),

            "sources":
                unit.get("sources", []),

            "controls":
                unit.get("controls", []),

            "effects":
                unit.get("effects", []),

            "signals":
                unit.get("signals", {}),

            "flow": {
                "confidence":
                    flow.get(
                        "confidence",
                        "unknown"
                    ),

                "source_seed_count":
                    flow.get(
                        "source_seed_count",
                        0
                    ),

                "confirmed_path_count":
                    len(
                        flow.get(
                            "confirmed_paths",
                            []
                        )
                    ),
            },

            "relevant_locations": [
                {
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "class": f.get("class"),
                    "function": f.get("name"),
                    "effects":
                        f.get("effects", []),
                    "controls":
                        f.get("controls", []),
                }
                for f in unit.get(
                    "relevant_functions",
                    []
                )
            ],
        })

    result.sort(
        key=lambda x:
            x["priority_score"],
        reverse=True
    )

    return result


def build_security_graph_v5(
    registrations,
    units,
    gaps,
):
    """
    Full local drill-down artifact.

    This artifact should not be loaded wholesale into initial
    model context.
    """

    return {
        "schema_version": "5.0",

        "registrations":
            registrations,

        "review_units":
            units,

        "gap_units":
            gaps,

        "counts": {
            "registrations":
                len(registrations),

            "review_units":
                len(units),

            "gap_units":
                len(gaps),
        },
    }


# ============================================================

# ================================================================
# V6 SECURITY STATE GRAPH
# ================================================================

V6_IDENTITY_PATTERNS = {
    "user_create": [
        "wp_create_user",
        "wp_insert_user",
    ],
    "user_update": [
        "wp_update_user",
    ],
    "user_delete": [
        "wp_delete_user",
    ],
    "role_transition": [
        "set_role",
        "add_role",
        "remove_role",
        "add_cap",
        "remove_cap",
    ],
    "user_meta_transition": [
        "update_user_meta",
        "add_user_meta",
        "delete_user_meta",
    ],
    "password_transition": [
        "wp_set_password",
        "reset_password",
        "check_password_reset_key",
        "get_password_reset_key",
    ],
    "authentication_transition": [
        "wp_set_auth_cookie",
        "wp_clear_auth_cookie",
        "wp_signon",
        "wp_authenticate",
    ],
}

V6_CONFIGURATION_PATTERNS = {
    "configuration_write": [
        "update_option",
        "add_option",
        "delete_option",
        "update_site_option",
        "add_site_option",
        "delete_site_option",
    ],
}

V6_TOKEN_PATTERNS = {
    "token_create_or_read": [
        "wp_create_nonce",
        "wp_nonce_url",
        "wp_nonce_field",
        "get_password_reset_key",
    ],
    "token_verify": [
        "wp_verify_nonce",
        "check_ajax_referer",
        "check_admin_referer",
        "check_password_reset_key",
    ],
}

V6_AUTHORIZATION_PATTERNS = {
    "capability_check": [
        "current_user_can",
        "user_can",
        "map_meta_cap",
    ],
    "identity_check": [
        "get_current_user_id",
        "wp_get_current_user",
        "is_user_logged_in",
    ],
}

V6_OBJECT_PATTERNS = {
    "user_lookup": [
        "get_user_by",
        "get_userdata",
        "get_user_meta",
    ],
    "post_lookup": [
        "get_post",
        "get_post_meta",
    ],
}

# Custom-role scope classification.
#
# Only Subscriber/Contributor-equivalent capability profiles are
# eligible for the requested low-privilege scope.
#
# Author is intentionally NOT a low-privilege baseline.
V6_LOW_PRIVILEGE_ROLE_CAPABILITIES = {
    "subscriber": {
        "read",
    },
    "contributor": {
        "read",
        "edit_posts",
    },
}

# Capabilities that clearly place a custom role above the requested
# low-privilege scope.
V6_ELEVATED_ROLE_CAPABILITIES = {
    "manage_options",
    "activate_plugins",
    "install_plugins",
    "update_plugins",
    "delete_plugins",
    "edit_plugins",
    "edit_themes",
    "switch_themes",
    "edit_users",
    "create_users",
    "delete_users",
    "promote_users",
    "manage_categories",
    "publish_posts",
    "publish_pages",
    "edit_pages",
    "delete_pages",
    "delete_published_posts",
    "delete_published_pages",
    "unfiltered_html",
}

V6_SECURITY_META_HINTS = [
    "role",
    "capabil",
    "permission",
    "privilege",
    "admin",
    "password",
    "passwd",
    "email",
    "verify",
    "verified",
    "approve",
    "approved",
    "activate",
    "active",
    "status",
    "owner",
    "ownership",
    "auth",
    "token",
    "secret",
    "registration",
]


def _v6_extract_static_role_capabilities(text):
    """
    Extract capabilities only when an add_role() declaration contains
    a statically visible capability array.

    Dynamic capability expressions are deliberately classified as
    unknown rather than guessed.
    """
    if not text:
        return [], False

    if not re.search(
        r"\badd_role\s*\(",
        text,
        flags=re.IGNORECASE,
    ):
        return [], False

    capabilities = set()

    # Support common WordPress forms:
    #
    # add_role('role', array(
    #     'read' => true,
    #     'edit_posts' => true,
    # ));
    #
    # and:
    #
    # add_role('role', [
    #     'read' => true,
    # ]);
    role_call_re = re.compile(
        r"""
        \badd_role\s*\(
        \s*['"][A-Za-z0-9_-]+['"]
        \s*,
        \s*
        (?P<array>
            array\s*\((?P<array_body>.*?)
            \)
            |
            \[(?P<bracket_body>.*?)
            \]
        )
        """,
        flags=re.IGNORECASE | re.DOTALL | re.VERBOSE,
    )

    matched_static = False

    for match in role_call_re.finditer(text):
        matched_static = True

        body = (
            match.group("array_body")
            if match.group("array_body") is not None
            else match.group("bracket_body")
        )

        for cap_match in re.finditer(
            r"""['"]([A-Za-z0-9_-]+)['"]\s*=>\s*(?:true|1)\b""",
            body,
            flags=re.IGNORECASE,
        ):
            capabilities.add(
                cap_match.group(1).lower()
            )

    if not matched_static:
        return [], True

    if not capabilities:
        return [], True

    return sorted(capabilities), False


def _v6_classify_custom_role_capabilities(text):
    """
    Classify a statically visible custom role against the requested
    low-privilege scope.

    Author is intentionally never treated as a low-privilege baseline.

    Returns:
        profile:
            none
            subscriber_like
            contributor_like
            higher_privilege
            unknown

        low_privilege_scope:
            True  = in requested low-privilege scope
            False = clearly above requested scope
            None  = unresolved / do not promote
    """
    capabilities, unknown = (
        _v6_extract_static_role_capabilities(text)
    )

    if not capabilities and not unknown:
        return {
            "profile": "none",
            "capabilities": [],
            "low_privilege_scope": None,
            "reason": None,
        }

    if unknown:
        return {
            "profile": "unknown",
            "capabilities": [],
            "low_privilege_scope": None,
            "reason": "custom_role_capabilities_unresolved",
        }

    caps = set(capabilities)

    elevated = sorted(
        caps & V6_ELEVATED_ROLE_CAPABILITIES
    )

    # Elevated capability always wins. This prevents a role such as
    # read + edit_posts + manage_options from being treated as
    # Contributor-like.
    if elevated:
        return {
            "profile": "higher_privilege",
            "capabilities": capabilities,
            "low_privilege_scope": False,
            "reason": "custom_role_contains_elevated_capability",
            "elevated_capabilities": elevated,
        }

    subscriber = V6_LOW_PRIVILEGE_ROLE_CAPABILITIES[
        "subscriber"
    ]
    contributor = V6_LOW_PRIVILEGE_ROLE_CAPABILITIES[
        "contributor"
    ]

    if (
        "edit_posts" in caps
        and caps.issubset(contributor)
    ):
        return {
            "profile": "contributor_like",
            "capabilities": capabilities,
            "low_privilege_scope": True,
            "reason": "custom_role_is_contributor_like",
        }

    if caps.issubset(subscriber):
        return {
            "profile": "subscriber_like",
            "capabilities": capabilities,
            "low_privilege_scope": True,
            "reason": "custom_role_is_subscriber_like",
        }

    # Unknown custom capabilities are not assumed to be low privilege.
    return {
        "profile": "unknown",
        "capabilities": capabilities,
        "low_privilege_scope": None,
        "reason": (
            "custom_role_capability_profile_not_equivalent_to_"
            "low_privilege_baseline"
        ),
    }


def _v6_text(obj):
    if obj is None:
        return ""
    return str(obj)


def _v6_contains_any(text, patterns):
    text = text.lower()

    return any(
        pattern.lower() in text
        for pattern in patterns
    )


def _v6_scan_patterns(text, groups):
    found = []

    low = text.lower()

    for category, patterns in groups.items():
        matches = []

        for pattern in patterns:
            if pattern.lower() in low:
                matches.append(pattern)

        if matches:
            found.append({
                "category": category,
                "matches": sorted(set(matches)),
            })

    return found


def _v6_security_meta_hints(text):
    low = text.lower()

    return sorted({
        hint
        for hint in V6_SECURITY_META_HINTS
        if hint in low
    })


def build_security_state_graph_v6(
    plugin_root,
    function_index,
    registrations,
    review_units,
    model_gaps,
):
    """
    Build model-facing security-state transition units.

    V6 does not declare vulnerabilities. It identifies transitions where
    authorization, ownership, identity, configuration, token lifecycle, or
    cross-request state semantics require model reasoning.
    """

    units = []
    seen = set()

    if isinstance(function_index, dict):
        function_items = function_index.items()
    else:
        function_items = []

    registration_by_callback = {}

    for reg in registrations or []:
        cb = reg.get("callback") or {}
        name = (
            cb.get("function")
            or cb.get("name")
        )

        if name:
            registration_by_callback.setdefault(
                name,
                []
            ).append(reg)

    # REST registrations may use anonymous callbacks and therefore
    # are not present in the generic registration resolver. Preserve
    # their provenance for V6 request-reachability analysis.
    for reg in review_units or []:
        if reg.get("registration_api") != "register_rest_route":
            continue

        cb = reg.get("callback") or {}
        name = cb.get("name")

        if not name:
            continue

        registration_by_callback.setdefault(
            name,
            []
        ).append({
            "type": "rest",
            "hook": "register_rest_route",
            "minimum_access":
                reg.get("minimum_access"),
            "callback": {
                "name": name,
                "class": cb.get("class"),
                "function": name,
            },
            "registration":
                reg.get("registration", {}),
        })

    counter = 0

    for function_name, function_obj in function_items:
        text = _v6_text(function_obj)

        identity = _v6_scan_patterns(
            text,
            V6_IDENTITY_PATTERNS,
        )

        config = _v6_scan_patterns(
            text,
            V6_CONFIGURATION_PATTERNS,
        )

        tokens = _v6_scan_patterns(
            text,
            V6_TOKEN_PATTERNS,
        )

        authorization = _v6_scan_patterns(
            text,
            V6_AUTHORIZATION_PATTERNS,
        )

        objects = _v6_scan_patterns(
            text,
            V6_OBJECT_PATTERNS,
        )

        security_hints = _v6_security_meta_hints(
            text
        )

        transition_present = bool(
            identity or config
        )

        if not transition_present:
            continue

        registrations_for_function = (
            registration_by_callback.get(
                function_name,
                []
            )
        )

        request_reachable = bool(
            registrations_for_function
        )

        has_capability_check = any(
            x["category"] == "capability_check"
            for x in authorization
        )

        has_identity_check = any(
            x["category"] == "identity_check"
            for x in authorization
        )

        has_token_verification = any(
            x["category"] == "token_verify"
            for x in tokens
        )

        role_transition = any(
            x["category"] == "role_transition"
            for x in identity
        )

        custom_role_profile = (
            _v6_classify_custom_role_capabilities(text)
            if role_transition
            else {
                "profile": "none",
                "capabilities": [],
                "low_privilege_scope": None,
                "reason": None,
            }
        )

        password_transition = any(
            x["category"] == "password_transition"
            for x in identity
        )

        auth_transition = any(
            x["category"] == "authentication_transition"
            for x in identity
        )

        user_mutation = any(
            x["category"] in {
                "user_create",
                "user_update",
                "user_delete",
                "user_meta_transition",
            }
            for x in identity
        )

        configuration_write = bool(config)

        security_sensitive = bool(
            role_transition
            or password_transition
            or auth_transition
            or user_mutation
            or (
                configuration_write
                and security_hints
            )
        )

        if not security_sensitive:
            continue

        key = (
            function_name,
            tuple(
                x["category"]
                for x in identity
            ),
            tuple(
                x["category"]
                for x in config
            ),
        )

        if key in seen:
            continue

        seen.add(key)
        counter += 1

        risk_reasons = []

        if role_transition:
            risk_reasons.append(
                "role_or_capability_transition"
            )

            if custom_role_profile["profile"] == "higher_privilege":
                risk_reasons.append(
                    "custom_role_higher_privilege_than_low_scope"
                )

            elif custom_role_profile["profile"] == "unknown":
                risk_reasons.append(
                    "custom_role_privilege_requires_analysis"
                )

        if password_transition:
            risk_reasons.append(
                "password_or_reset_transition"
            )

        if auth_transition:
            risk_reasons.append(
                "authentication_state_transition"
            )

        if user_mutation:
            risk_reasons.append(
                "user_security_state_mutation"
            )

        if configuration_write and security_hints:
            risk_reasons.append(
                "security_relevant_configuration_transition"
            )

        if request_reachable and not has_capability_check:
            risk_reasons.append(
                "request_reachable_without_obvious_capability_check"
            )

        if (
            user_mutation
            and not has_identity_check
        ):
            risk_reasons.append(
                "ownership_or_target_identity_requires_analysis"
            )

        required_reasoning = [
            "determine minimum attacker privilege",
            "determine whether attacker controls target object identity",
            "verify capability and ownership enforcement",
            "determine security meaning of mutated state",
            "trace downstream consumers of changed state",
        ]

        if password_transition:
            required_reasoning.extend([
                "verify password-reset token lifecycle",
                "verify victim ownership proof",
            ])

        if role_transition:
            required_reasoning.extend([
                "determine reachable resulting role/capabilities",
                "check subscriber-to-admin or equivalent privilege chain",
                "compare custom role capabilities against subscriber and contributor baselines",
                "do not treat author as low privilege scope",
            ])

            if custom_role_profile["profile"] == "unknown":
                required_reasoning.append(
                    "resolve dynamic or unknown custom role capabilities before scope classification"
                )

        if configuration_write:
            required_reasoning.extend([
                "trace configuration value to behavior changes",
                "check whether configuration exposes new privileged surface",
            ])

        units.append({
            "id": (
                f"WP-V6-STATE-{counter:04d}"
            ),
            "kind": "security_state_transition",
            "function": function_name,
            "request_reachable": request_reachable,
            "registrations": registrations_for_function,
            "identity_transitions": identity,
            "custom_role_profile": custom_role_profile,
            "configuration_transitions": config,
            "token_operations": tokens,
            "authorization_controls": authorization,
            "object_operations": objects,
            "security_meta_hints": security_hints,
            "risk_reasons": risk_reasons,
            "required_reasoning": sorted(
                set(required_reasoning)
            ),
            "status": "requires_semantic_review",
        })

    return units


def build_v6_review_index(state_units):
    """
    Compact queue consumed by Codex.
    """

    queue = []

    for unit in state_units:
        score = 50

        reasons = set(
            unit.get("risk_reasons", [])
        )

        if "role_or_capability_transition" in reasons:
            score += 70

        if "password_or_reset_transition" in reasons:
            score += 70

        if "authentication_state_transition" in reasons:
            score += 60

        if "user_security_state_mutation" in reasons:
            score += 40

        if (
            "security_relevant_configuration_transition"
            in reasons
        ):
            score += 40

        if (
            "request_reachable_without_obvious_capability_check"
            in reasons
        ):
            score += 50

        if (
            "ownership_or_target_identity_requires_analysis"
            in reasons
        ):
            score += 40

        if unit.get("request_reachable"):
            score += 25

        if score >= 180:
            effort = "deep"
        elif score >= 120:
            effort = "normal"
        else:
            effort = "light"

        queue.append({
            "id": unit["id"],
            "kind": unit["kind"],
            "function": unit["function"],
            "priority_score": score,
            "review_effort": effort,
            "request_reachable": unit[
                "request_reachable"
            ],
            "risk_reasons": unit[
                "risk_reasons"
            ],
            "required_reasoning": unit[
                "required_reasoning"
            ],
            "security_meta_hints": unit[
                "security_meta_hints"
            ],
        })

    queue.sort(
        key=lambda x: (
            -x["priority_score"],
            x["id"],
        )
    )

    return queue



# ============================================================
# V6.1 COVERAGE SAFETY NET
#
# Candidate/review-unit discovery is an optimization boundary,
# never a security coverage boundary.
#
# This pass adds:
#   1. reverse call reachability
#   2. cross-state dependencies
#   3. orphan security-sensitive review
# ============================================================

V61_SECURITY_NAME_HINTS = {
    "admin",
    "administrator",
    "role",
    "cap",
    "capability",
    "permission",
    "privilege",
    "access",
    "owner",
    "ownership",
    "approve",
    "approval",
    "verify",
    "verified",
    "activate",
    "activation",
    "auth",
    "authenticate",
    "login",
    "password",
    "passwd",
    "reset",
    "token",
    "secret",
    "level",
    "group",
    "membership",
    "account",
    "user",
    "register",
    "registration",
}

V61_STATE_WRITE_HINTS = {
    "update_option",
    "add_option",
    "delete_option",
    "update_site_option",
    "update_user_meta",
    "add_user_meta",
    "delete_user_meta",
    "update_post_meta",
    "add_post_meta",
    "delete_post_meta",
    "wp_update_user",
    "wp_insert_user",
    "wp_create_user",
    "wp_set_password",
    "set_role",
    "add_role",
    "remove_role",
    "add_cap",
    "remove_cap",
}

V61_STATE_READ_HINTS = {
    "get_option",
    "get_site_option",
    "get_user_meta",
    "get_post_meta",
    "get_user_by",
    "get_userdata",
    "wp_get_current_user",
    "current_user_can",
    "user_can",
    "is_user_logged_in",
}

V61_SECURITY_CONSUMER_HINTS = {
    "wp_set_auth_cookie",
    "wp_signon",
    "wp_authenticate",
    "wp_set_password",
    "reset_password",
    "wp_update_user",
    "wp_insert_user",
    "wp_create_user",
    "set_role",
    "add_role",
    "add_cap",
}


def _v61_text(obj):
    if obj is None:
        return ""

    if isinstance(obj, str):
        return obj.lower()

    try:
        import json
        return json.dumps(
            obj,
            ensure_ascii=False,
            default=str,
        ).lower()
    except Exception:
        return str(obj).lower()


def _v61_security_name_score(name):
    text = _v61_text(name)

    score = 0
    hits = []

    for hint in V61_SECURITY_NAME_HINTS:
        if hint in text:
            score += 1
            hits.append(hint)

    return score, sorted(set(hits))


def build_reverse_call_index_v61(function_index):
    """
    Lightweight reverse caller index.

    This intentionally uses the mapper's already indexed function
    representations rather than performing repository-wide model
    discovery.

    Output:
        callee-name -> bounded caller descriptors
    """

    reverse = {}

    if not isinstance(function_index, dict):
        return reverse

    known_names = set(
        str(x)
        for x in function_index.keys()
    )

    for caller_name, records in function_index.items():
        if not isinstance(records, list):
            records = [records]

        for record in records:
            text = _v61_text(record)

            if not text:
                continue

            for callee in known_names:
                if callee == caller_name:
                    continue

                # Cheap deterministic edge discovery. Semantic
                # validation remains Codex's responsibility.
                if (
                    f"{callee.lower()}(" in text
                    or f"::{callee.lower()}(" in text
                    or f"->{callee.lower()}(" in text
                ):
                    reverse.setdefault(
                        callee,
                        []
                    ).append({
                        "caller": caller_name,
                        "callee": callee,
                        "evidence_kind":
                            "indexed_call_reference",
                    })

    return reverse


def reverse_reachability_v61(
    start_function,
    reverse_index,
    max_depth=4,
    max_nodes=80,
):
    """
    Bounded reverse traversal.

    We deliberately cap traversal so custom security abstractions
    can be connected back toward exposure without recreating a
    repository-wide semantic audit.
    """

    queue = [
        (start_function, 0, [])
    ]

    seen = {start_function}
    paths = []

    while queue and len(seen) <= max_nodes:
        current, depth, path = queue.pop(0)

        if depth >= max_depth:
            continue

        for edge in reverse_index.get(
            current,
            []
        ):
            caller = edge.get("caller")

            if not caller:
                continue

            new_path = path + [{
                "caller": caller,
                "callee": current,
            }]

            paths.append(new_path)

            if caller not in seen:
                seen.add(caller)
                queue.append(
                    (
                        caller,
                        depth + 1,
                        new_path,
                    )
                )

    return {
        "start_function": start_function,
        "max_depth": max_depth,
        "visited_functions": sorted(seen),
        "paths": paths,
    }


def discover_state_accesses_v61(function_index):
    """
    Discover generic state producers/readers/consumers.

    This is intentionally broader than WordPress roles alone so
    plugin-specific state abstractions can reach semantic review.
    """

    writes = []
    reads = []
    consumers = []

    if not isinstance(function_index, dict):
        return {
            "writes": writes,
            "reads": reads,
            "consumers": consumers,
        }

    for function_name, records in function_index.items():
        if not isinstance(records, list):
            records = [records]

        text = _v61_text(records)

        name_score, name_hints = (
            _v61_security_name_score(
                function_name
            )
        )

        write_hits = sorted(
            x
            for x in V61_STATE_WRITE_HINTS
            if x.lower() in text
        )

        read_hits = sorted(
            x
            for x in V61_STATE_READ_HINTS
            if x.lower() in text
        )

        consumer_hits = sorted(
            x
            for x in V61_SECURITY_CONSUMER_HINTS
            if x.lower() in text
        )

        if write_hits:
            writes.append({
                "function": function_name,
                "operations": write_hits,
                "security_name_hints":
                    name_hints,
                "security_name_score":
                    name_score,
            })

        if read_hits:
            reads.append({
                "function": function_name,
                "operations": read_hits,
                "security_name_hints":
                    name_hints,
                "security_name_score":
                    name_score,
            })

        if consumer_hits:
            consumers.append({
                "function": function_name,
                "operations": consumer_hits,
                "security_name_hints":
                    name_hints,
                "security_name_score":
                    name_score,
            })

    return {
        "writes": writes,
        "reads": reads,
        "consumers": consumers,
    }



# ============================================================
# V6.1.2 CONCRETE STATE-KEY EXTRACTION
# ============================================================

V612_STATE_KEY_PATTERNS = {
    "option": [
        r"""(?:get_option|update_option|add_option|delete_option)\s*\(\s*['"]([^'"]+)['"]""",
        r"""(?:get_site_option|update_site_option|add_site_option|delete_site_option)\s*\(\s*['"]([^'"]+)['"]""",
    ],

    "user_meta": [
        r"""(?:get_user_meta|update_user_meta|add_user_meta|delete_user_meta)\s*\([^,]+,\s*['"]([^'"]+)['"]""",
    ],

    "post_meta": [
        r"""(?:get_post_meta|update_post_meta|add_post_meta|delete_post_meta)\s*\([^,]+,\s*['"]([^'"]+)['"]""",
    ],
}


def extract_state_keys_v612(text):
    import re

    result = []

    raw = str(text)

    for storage, patterns in (
        V612_STATE_KEY_PATTERNS.items()
    ):
        for pattern in patterns:
            for m in re.finditer(
                pattern,
                raw,
                re.I
            ):
                result.append({
                    "storage": storage,
                    "key": m.group(1),
                })

    unique = {}

    for item in result:
        k = (
            item["storage"],
            item["key"],
        )

        unique[k] = item

    return list(unique.values())


def discover_concrete_state_accesses_v612(
    function_index
):
    writes = []
    reads = []

    if not isinstance(function_index, dict):
        return {
            "writes": [],
            "reads": [],
        }

    for function_name, records in (
        function_index.items()
    ):
        if not isinstance(records, list):
            records = [records]

        raw = str(records)

        keys = extract_state_keys_v612(
            raw
        )

        if not keys:
            continue

        low = raw.lower()

        has_write = any(
            x in low
            for x in (
                "update_option",
                "add_option",
                "delete_option",
                "update_site_option",
                "add_site_option",
                "delete_site_option",
                "update_user_meta",
                "add_user_meta",
                "delete_user_meta",
                "update_post_meta",
                "add_post_meta",
                "delete_post_meta",
            )
        )

        has_read = any(
            x in low
            for x in (
                "get_option",
                "get_site_option",
                "get_user_meta",
                "get_post_meta",
            )
        )

        if has_write:
            writes.append({
                "function": function_name,
                "keys": keys,
            })

        if has_read:
            reads.append({
                "function": function_name,
                "keys": keys,
            })

    return {
        "writes": writes,
        "reads": reads,
    }


V613_SECURITY_STATE_KEY_HINTS = {
    "admin",
    "administrator",
    "role",
    "default_role",
    "capability",
    "capabilities",
    "permission",
    "privilege",
    "access",
    "auth",
    "login",
    "password",
    "passwd",
    "reset",
    "token",
    "secret",
    "nonce",
    "verify",
    "verified",
    "verification",
    "approve",
    "approved",
    "approval",
    "activate",
    "activation",
    "owner",
    "ownership",
    "registration",
    "register",
    "membership",
    "account",
}

V613_EXACT_SECURITY_KEYS = {
    "default_role",
    "users_can_register",
    "active_plugins",
    "active_sitewide_plugins",
    "administrator",
    "wp_user_roles",
}


def state_key_security_score_v613(
    storage,
    key,
):
    """
    Return a deterministic security-interest score for a concrete
    persisted state key.

    This is prioritization only, never proof of vulnerability.
    """

    low = str(key).lower()

    score = 0
    reasons = []

    if low in V613_EXACT_SECURITY_KEYS:
        score += 100
        reasons.append(
            "known_security_sensitive_key"
        )

    for hint in V613_SECURITY_STATE_KEY_HINTS:
        if hint in low:
            score += 25
            reasons.append(
                f"security_key_hint:{hint}"
            )

    if storage == "user_meta":
        # User-meta state is more likely than generic options to
        # encode account approval/role/identity state.
        score += 10

    return (
        score,
        sorted(set(reasons)),
    )


def function_security_signal_v613(
    function_name,
    function_index,
):
    """
    Determine whether a producer/consumer itself has strong
    authorization/identity/privilege semantics.
    """

    records = (
        function_index.get(
            function_name,
            []
        )
        if isinstance(
            function_index,
            dict
        )
        else []
    )

    body = _v61_text(records)

    name_score, name_hints = (
        _v61_security_name_score(
            function_name
        )
    )

    api_hits = sorted({
        x
        for x in (
            "current_user_can",
            "user_can",
            "map_meta_cap",
            "wp_set_password",
            "reset_password",
            "check_password_reset_key",
            "get_password_reset_key",
            "wp_set_auth_cookie",
            "wp_signon",
            "wp_authenticate",
            "set_role",
            "add_role",
            "remove_role",
            "add_cap",
            "remove_cap",
            "wp_update_user",
            "wp_insert_user",
            "wp_create_user",
            "update_user_meta",
            "add_user_meta",
            "delete_user_meta",
        )
        if x in body
    })

    strong = bool(
        api_hits
        or name_score >= 2
    )

    return {
        "strong": strong,
        "name_hints": name_hints,
        "api_hits": api_hits,
    }


def build_concrete_cross_state_v612(
    function_index
):
    """
    V6.1.3 model-facing cross-state graph.

    Requirements:
      - same concrete storage + key; AND
      - security-relevant state key OR strong security semantics
        in producer/consumer.

    Dependencies are grouped by producer + concrete state key so
    common options do not create O(writer * reader) model units.
    """

    accesses = (
        discover_concrete_state_accesses_v612(
            function_index
        )
    )

    writers = accesses["writes"]
    readers = accesses["reads"]

    # Build reader index:
    #
    # (storage, key) -> set(functions)
    reader_index = {}

    for reader in readers:
        for item in reader.get(
            "keys",
            []
        ):
            state = (
                item["storage"],
                item["key"],
            )

            reader_index.setdefault(
                state,
                set()
            ).add(
                reader["function"]
            )

    result = []
    counter = 0
    seen = set()

    for writer in writers:
        producer = writer["function"]

        producer_signal = (
            function_security_signal_v613(
                producer,
                function_index,
            )
        )

        for item in writer.get(
            "keys",
            []
        ):
            storage = item["storage"]
            key = item["key"]

            state = (
                storage,
                key,
            )

            consumers = sorted(
                reader_index.get(
                    state,
                    set()
                )
            )

            if not consumers:
                continue

            key_score, key_reasons = (
                state_key_security_score_v613(
                    storage,
                    key,
                )
            )

            consumer_details = []

            any_strong_consumer = False

            for consumer in consumers:
                signal = (
                    function_security_signal_v613(
                        consumer,
                        function_index,
                    )
                )

                if signal["strong"]:
                    any_strong_consumer = True

                consumer_details.append({
                    "function":
                        consumer,

                    "security_signal":
                        signal,
                })

            # V6.1.4:
            #
            # Exact-key equality proves a data dependency, but does
            # not prove the state is security relevant.
            #
            # Generic operational state such as timezone, cache,
            # appearance, price formatting, or database prefixes
            # must not enter the primary model queue merely because
            # one of many consumers happens to contain a security
            # API.
            #
            # Primary promotion requires:
            #
            #   1. an explicitly security-relevant concrete key; OR
            #   2. user/post metadata where both sides exhibit
            #      strong security semantics.
            #
            # All other concrete dependencies remain available in
            # fallback evidence.

            explicit_security_key = (
                key_score > 0
            )

            strong_object_state = (
                storage in {
                    "user_meta",
                    "post_meta",
                }
                and producer_signal["strong"]
                and any_strong_consumer
            )

            if not (
                explicit_security_key
                or strong_object_state
            ):
                continue

            identity = (
                producer,
                storage,
                key,
            )

            if identity in seen:
                continue

            seen.add(identity)
            counter += 1

            priority = (
                50
                + min(key_score, 100)
            )

            if producer_signal["strong"]:
                priority += 30

            if any_strong_consumer:
                priority += 30

            if storage == "user_meta":
                priority += 15

            effort = (
                "deep"
                if priority >= 150
                else
                "normal"
                if priority >= 100
                else
                "light"
            )

            result.append({
                "id":
                    f"WP-V613-STATE-{counter:04d}",

                "producer":
                    producer,

                "state": {
                    "storage": storage,
                    "key": key,
                },

                "consumers":
                    consumer_details,

                "consumer_count":
                    len(consumer_details),

                "priority_score":
                    priority,

                "review_effort":
                    effort,

                "confidence":
                    "concrete_state_key",

                "security_key_reasons":
                    key_reasons,

                "producer_security_signal":
                    producer_signal,

                "status":
                    "requires_semantic_validation",

                "required_resolution": [
                    "determine whether attacker can influence the state producer",
                    "determine producer authorization and minimum attacker privilege",
                    "determine whether producer and consumers operate in the same WordPress scope and target object",
                    "determine the security meaning of the concrete persisted state",
                    "determine whether any consumer changes authentication, authorization, privilege, identity, approval, verification, ownership, registration, or another security boundary",
                    "check whether exploitation spans multiple requests",
                    "reject the unit with source-backed evidence when the state is operational rather than security-sensitive",
                ],
            })

    result.sort(
        key=lambda x: (
            -x["priority_score"],
            x["id"],
        )
    )

    return result


def build_cross_state_dependencies_v61(
    state_accesses,
):
    """
    Produce compact producer -> reader/consumer hypotheses.

    These are review hypotheses, not confirmed dataflows.

    Codex must validate the concrete key/field/object and whether
    attacker-controlled state actually influences the consumer.
    """

    writes = state_accesses.get(
        "writes",
        []
    )

    reads = state_accesses.get(
        "reads",
        []
    )

    consumers = state_accesses.get(
        "consumers",
        []
    )

    dependencies = []
    counter = 0

    for writer in writes:
        writer_hints = set(
            writer.get(
                "security_name_hints",
                []
            )
        )

        for reader in reads:
            reader_hints = set(
                reader.get(
                    "security_name_hints",
                    []
                )
            )

            overlap = sorted(
                writer_hints & reader_hints
            )

            if not overlap:
                continue

            counter += 1

            dependencies.append({
                "id":
                    f"WP-V61-STATE-{counter:04d}",
                "producer":
                    writer["function"],
                "consumer":
                    reader["function"],
                "shared_semantic_hints":
                    overlap,
                "producer_operations":
                    writer.get(
                        "operations",
                        []
                    ),
                "consumer_operations":
                    reader.get(
                        "operations",
                        []
                    ),
                "status":
                    "requires_semantic_validation",
                "required_resolution": [
                    "identify the concrete state key, field, object, or custom storage",
                    "prove whether producer and consumer reference the same security state",
                    "determine attacker control over the producer",
                    "determine the downstream authorization, identity, privilege, or authentication consequence",
                    "check cross-request and cross-user behavior",
                ],
            })

        for consumer in consumers:
            consumer_hints = set(
                consumer.get(
                    "security_name_hints",
                    []
                )
            )

            overlap = sorted(
                writer_hints & consumer_hints
            )

            if not overlap:
                continue

            counter += 1

            dependencies.append({
                "id":
                    f"WP-V61-STATE-{counter:04d}",
                "producer":
                    writer["function"],
                "consumer":
                    consumer["function"],
                "shared_semantic_hints":
                    overlap,
                "producer_operations":
                    writer.get(
                        "operations",
                        []
                    ),
                "consumer_operations":
                    consumer.get(
                        "operations",
                        []
                    ),
                "status":
                    "requires_semantic_validation",
                "required_resolution": [
                    "resolve the concrete state dependency",
                    "determine whether the state survives across requests",
                    "determine attacker privilege and target identity",
                    "validate whether the consumer grants security-sensitive behavior",
                    "check capability, ownership, authentication and business authorization independently",
                ],
            })

    return dependencies


def build_orphan_security_queue_v61(
    function_index,
    reverse_index,
    v5_review_index,
    v6_review_index,
):
    """
    Security-sensitive functions not already represented by V5/V6
    become explicit review units instead of silently disappearing.
    """

    represented = _v61_text(
        {
            "v5": v5_review_index,
            "v6": v6_review_index,
        }
    )

    queue = []
    counter = 0

    if not isinstance(function_index, dict):
        return queue

    for function_name, records in function_index.items():
        name_score, name_hints = (
            _v61_security_name_score(
                function_name
            )
        )

        body = _v61_text(records)

        state_write_hits = sorted(
            x
            for x in V61_STATE_WRITE_HINTS
            if x.lower() in body
        )

        state_read_hits = sorted(
            x
            for x in V61_STATE_READ_HINTS
            if x.lower() in body
        )

        # V6.1.3:
        # Security-like naming is only a discovery hint.
        # Require structural evidence before exposing an orphan
        # unit to the model-facing queue.

        has_db_mutation = (
            "$wpdb" in body
            and any(
                x in body
                for x in (
                    "insert",
                    "update",
                    "delete",
                    "replace",
                    "query",
                )
            )
        )

        has_security_transition = bool(
            state_write_hits
        )

        has_identity_read = bool(
            state_read_hits
        )

        has_security_api = any(
            x in body
            for x in (
                "current_user_can",
                "user_can",
                "map_meta_cap",
                "wp_set_password",
                "reset_password",
                "check_password_reset_key",
                "get_password_reset_key",
                "wp_set_auth_cookie",
                "wp_signon",
                "wp_authenticate",
                "set_role",
                "add_role",
                "remove_role",
                "add_cap",
                "remove_cap",
                "update_user_meta",
                "add_user_meta",
                "delete_user_meta",
                "wp_update_user",
                "wp_insert_user",
                "wp_create_user",
            )
        )

        has_target_identity_signal = any(
            x in body
            for x in (
                "user_id",
                "userid",
                "account_id",
                "member_id",
                "owner_id",
                "target_user",
                "target_id",
                "role",
                "capability",
                "permission",
                "password",
                "reset_key",
                "token",
            )
        )

        reverse_probe = (
            reverse_reachability_v61(
                function_name,
                reverse_index,
                max_depth=2,
                max_nodes=30,
            )
        )

        has_reverse_path = bool(
            reverse_probe.get(
                "paths"
            )
        )

        strong_structural_signal = bool(
            has_security_transition
            or has_db_mutation
            or has_security_api
            or (
                has_identity_read
                and has_target_identity_signal
            )
            or (
                name_score >= 2
                and has_reverse_path
                and has_target_identity_signal
            )
        )

        custom_security_signal = (
            name_score > 0
            and strong_structural_signal
        )

        if not custom_security_signal:
            continue

        if function_name.lower() in represented:
            continue

        counter += 1

        reverse = reverse_reachability_v61(
            function_name,
            reverse_index,
        )

        score = (
            70
            + min(name_score * 10, 50)
            + min(
                len(state_write_hits) * 15,
                45,
            )
        )

        if reverse["paths"]:
            score += 20

        effort = (
            "deep"
            if score >= 130
            else
            "normal"
            if score >= 90
            else
            "light"
        )

        queue.append({
            "id":
                f"WP-V61-ORPHAN-{counter:04d}",
            "function":
                function_name,
            "priority_score":
                score,
            "review_effort":
                effort,
            "security_name_hints":
                name_hints,
            "state_write_operations":
                state_write_hits,
            "state_read_operations":
                state_read_hits,
            "reverse_reachability":
                reverse,
            "status":
                "requires_semantic_validation",
            "risk_reasons": [
                "security_sensitive_code_outside_primary_v5_v6_queue",
                "custom_security_abstraction_requires_analysis",
            ],
            "required_resolution": [
                "determine whether the function is request reachable",
                "resolve callers using the bounded reverse graph",
                "determine attacker privilege and controlled parameters",
                "determine whether the state represents authorization, identity, ownership, privilege, authentication, approval, verification, or another security boundary",
                "follow concrete downstream consumers when security impact is plausible",
                "do not report solely from naming or heuristic signals",
            ],
        })

    queue.sort(
        key=lambda x: (
            -x["priority_score"],
            x["id"],
        )
    )

    return queue



def partition_orphan_queue_v614(
    orphan_queue
):
    """
    Split orphan discoveries into initial semantic review and
    fallback coverage hypotheses.

    No unit is discarded.

    Light units remain available for escalation and completeness
    accounting but are not automatically loaded into initial model
    context.
    """

    primary = []
    fallback = []

    for unit in orphan_queue:
        effort = unit.get(
            "review_effort",
            "light"
        )

        if effort in {
            "deep",
            "normal",
        }:
            primary.append(unit)
        else:
            fallback.append(unit)

    return {
        "primary": primary,
        "fallback": fallback,
    }


def build_coverage_safety_net_v61(
    function_index,
    v5_review_index,
    v6_review_index,
):
    reverse_index = (
        build_reverse_call_index_v61(
            function_index
        )
    )

    state_accesses = (
        discover_state_accesses_v61(
            function_index
        )
    )

    # Concrete shared state keys are the preferred
    # model-facing cross-request dependency source.
    concrete_cross_state = (
        build_concrete_cross_state_v612(
            function_index
        )
    )

    # Retain the older semantic-only graph locally as a
    # fallback hypothesis source, but do not treat it as
    # equally strong evidence.
    semantic_cross_state = (
        build_cross_state_dependencies_v61(
            state_accesses
        )
    )

    cross_state = (
        concrete_cross_state
    )

    orphan_queue = (
        build_orphan_security_queue_v61(
            function_index,
            reverse_index,
            v5_review_index,
            v6_review_index,
        )
    )


    orphan_partition = (
        partition_orphan_queue_v614(
            orphan_queue
        )
    )

    return {
        "schema_version": "6.1",
        "reverse_call_index":
            reverse_index,
        "state_accesses":
            state_accesses,
        "cross_state_dependencies":
            cross_state,

        # Model-facing concrete security-state dependencies.
        "cross_state_primary":
            cross_state,

        # Broad semantic hypotheses are retained locally as a
        # coverage fallback. They are not initial model context.
        "semantic_cross_state_hypotheses":
            semantic_cross_state,

        "orphan_review_queue":
            orphan_partition["primary"],

        "orphan_fallback_hypotheses":
            orphan_partition["fallback"],

        "orphan_all":
            orphan_queue,
    }

# ============================================================
# SEMANTIC REVIEW CORRELATOR / MODEL WORK PACKS
#
# This layer reduces repeated model context without suppressing
# any V5/V6/V6.1 review unit. A pack is a batching/context unit,
# NOT a finding and NOT a safety verdict.
# ============================================================

SECURITY_REVIEW_PACK_ORDER = [
    "public_filesystem_execution",
    "public_configuration_mutation",
    "identity_auth_authorization",
    "user_state_mutation",
    "configuration_lifecycle",
    "operational_state",
    "secret_verification",
    "other_security_logic",
]


def _review_pack_text(obj):
    return _v61_text(obj)


def _review_pack_themes(unit):
    """Return conservative semantic themes for batching only."""
    text = _review_pack_text(unit)
    themes = set()

    effects = set(unit.get("effects", [])) if isinstance(unit, dict) else set()
    reasons = set(unit.get("risk_reasons", [])) if isinstance(unit, dict) else set()
    hints = set(unit.get("security_meta_hints", [])) if isinstance(unit, dict) else set()
    hints |= set(unit.get("security_name_hints", [])) if isinstance(unit, dict) else set()

    if effects & {
        "file_read", "file_write", "file_upload", "file_delete",
        "dynamic_include", "code_execution", "secret_read",
    }:
        themes.add("public_filesystem_execution")

    if "configuration_write" in effects or "configuration" in text:
        themes.add("public_configuration_mutation")

    if any(x in reasons for x in {
        "role_or_capability_transition",
        "password_or_reset_transition",
        "authentication_state_transition",
    }) or any(x in text for x in (
        "authorization", "capability", "password", "reset", "auth",
        "current_user_can", "user_can",
    )):
        themes.add("identity_auth_authorization")

    if "user_security_state_mutation" in reasons or any(x in text for x in (
        "usermeta", "user_meta", "user state", "ownership", "target identity",
    )):
        themes.add("user_state_mutation")


    if any(x in hints for x in {"token", "secret", "verify", "verification"}) or any(
        x in text for x in ("token", "secret", "credential", "verification", "verify")
    ):
        themes.add("secret_verification")


    if not themes:
        themes.add("other_security_logic")

    return themes


def _review_pack_effort(units):
    ranks = {"light": 1, "bounded": 1, "normal": 2, "deep": 3}
    best = max((ranks.get(x.get("review_effort"), 1) for x in units), default=1)
    return {1: "light", 2: "normal", 3: "deep"}[best]


def build_semantic_review_packs_v62(v5_review_index, v6_review_index, v61_orphan_review_index, v61_fallback_index):
    """
    Build model-facing work packs while retaining every raw unit.

    Safety invariants:
      - no unit is discarded;
      - no unit is declared safe by grouping;
      - disposition remains member-level;
      - fallback remains separate and can be promoted;
      - a pack's effort is the maximum member effort.
    """
    sources = []
    for source_name, items in (
        ("v5", v5_review_index),
        ("v6", v6_review_index),
        ("v6.1_orphan", v61_orphan_review_index),
        ("v6.1_fallback", v61_fallback_index),
    ):
        for item in items or []:
            clone = dict(item)
            clone["review_source"] = source_name
            clone["review_themes"] = sorted(_review_pack_themes(clone))
            clone["must_disposition"] = True
            sources.append(clone)

    # Deep/high-impact units are isolated unless they share an explicit
    # security theme AND both are already model-facing primary units.
    # This avoids accidentally merging unrelated attack surfaces.
    packs = []
    pack_index = {}

    def add_pack(key, item):
        if key not in pack_index:
            pack_index[key] = len(packs)
            packs.append({
                "pack_id": f"SRP-{len(packs)+1:03d}",
                "theme": key,
                "review_effort": item.get("review_effort", "light"),
                "must_disposition": True,
                "members": [],
                "member_count": 0,
                "purpose": "context batching only; not a finding or safety verdict",
            })
        pack = packs[pack_index[key]]
        pack["members"].append({
            "id": item.get("id"),
            "source": item.get("review_source"),
            "function": item.get("function"),
            "review_effort": item.get("review_effort"),
            "priority_score": item.get("priority_score"),
            "must_disposition": True,
        })
        pack["member_count"] = len(pack["members"])
        pack["review_effort"] = _review_pack_effort([
            {"review_effort": x["review_effort"]} for x in pack["members"]
        ])

    for item in sources:
        themes = item.get("review_themes") or ["other_security_logic"]
        source = item.get("review_source")
        effort = item.get("review_effort", "light")

        # Fallback hypotheses must never silently merge into a primary pack.
        if source == "v6.1_fallback":
            theme = sorted(themes)[0]
            add_pack(f"fallback::{theme}", item)
            continue

        # Deep items are isolated by source+id to preserve maximum recall.
        if effort == "deep":
            add_pack(f"deep::{source}::{item.get('id')}", item)
            continue

        # Normal/light items can share a theme across V5/V6/V6.1. This is
        # the main token-saving mechanism, while member-level disposition
        # prevents grouping from becoming a suppression boundary.
        theme = sorted(themes)[0]
        add_pack(f"primary::{theme}", item)

    for pack in packs:
        pack["members"].sort(key=lambda x: (-(x.get("priority_score") or 0), x.get("id") or ""))

    return {
        "schema_version": "6.2",
        "policy": {
            "no_unit_discard": True,
            "member_level_disposition_required": True,
            "grouping_is_context_batching_only": True,
            "fallback_cannot_merge_into_primary": True,
            "deep_units_isolated": True,
            "unknown_is_not_safe": True,
        },
        "raw_unit_count": len(sources),
        "pack_count": len(packs),
        "packs": packs,
        "all_units": sources,
    }


# ============================================================
# V6.3 ADAPTIVE SECURITY INVESTIGATION
#
# This layer does not attempt to prove vulnerabilities deterministically.
# It creates compact, source-backed investigation cases that allow the
# semantic reviewer to generate and expand attack hypotheses adaptively.
# V5/V6/V6.1 remain the discovery and coverage layers.
# ============================================================

V63_HIGH_IMPACT_EFFECTS = {
    "code_execution",
    "dynamic_include",
    "deserialization",
    "sql_query",
    "database_write",
    "file_read",
    "file_write",
    "file_upload",
    "file_delete",
    "configuration_write",
    "role_change",
    "capability_change",
    "session_change",
    "object_update",
    "object_delete",
    "secret_read",
}

V63_SECURITY_THEMES = {
    "filesystem": {
        "file_read", "file_write", "file_upload", "file_delete",
        "dynamic_include", "code_execution",
    },
    "injection": {"sql_query", "code_execution", "dynamic_include", "deserialization"},
    "configuration": {"configuration_write"},
    "identity": {"role_change", "capability_change", "session_change"},
    "object_authorization": {"object_update", "object_delete"},
    "secrets": {"secret_read"},
}


def _v63_effects(obj):
    if not isinstance(obj, dict):
        return set()
    return set(obj.get("effects", []) or [])


def _v63_text(obj):
    return _review_pack_text(obj) if isinstance(obj, dict) else ""


def _v63_themes(obj):
    """Return conservative semantic themes for adaptive investigation."""
    effects = _v63_effects(obj)
    themes = {
        name for name, members in V63_SECURITY_THEMES.items()
        if effects & members
    }

    text = _v63_text(obj).lower()
    reasons = set(obj.get("risk_reasons", []) or []) if isinstance(obj, dict) else set()

    # Preserve the existing broad identity signal for authentication,
    # roles, capabilities, sessions, and related security concepts.
    if any(x in text for x in (
        "authorization",
        "capability",
        "ownership",
        "permission",
        "auth",
    )):
        themes.add("identity")

    if any(x in text for x in (
        "user",
        "role",
        "account",
        "password",
        "reset",
        "session",
    )):
        themes.add("identity")

    if any(x in reasons for x in (
        "role_or_capability_transition",
        "password_or_reset_transition",
        "authentication_state_transition",
    )):
        themes.add("identity")

    # Generic semantic security signals emitted by V6/V6.1.
    if "request_reachable_without_obvious_capability_check" in reasons:
        themes.add("authorization")

    if "ownership_or_target_identity_requires_analysis" in reasons:
        themes.add("ownership")

    if "user_security_state_mutation" in reasons:
        themes.add("state_transition")

    if "security_relevant_configuration_transition" in reasons:
        themes.add("configuration")

    if any(x in reasons for x in (
        "security_sensitive_code_outside_primary_v5_v6_queue",
        "custom_security_abstraction_requires_analysis",
    )):
        themes.add("security_abstraction")

    if "state_transition" in reasons or "security_sensitive_state_change" in reasons:
        themes.add("configuration")

    # V6.1 cross-state records represent a concrete producer/consumer
    # relationship even when no direct effect is attached.
    if isinstance(obj, dict) and (
        obj.get("producer") or obj.get("consumer")
    ) and (
        obj.get("state") or obj.get("shared_semantic_hints")
    ):
        themes.add("cross_request_state")

    return themes or {"other"}


def _v63_role_signal(obj):
    text = _v63_text(obj).lower()
    if any(x in text for x in ("unauthenticated", "nopriv", "public", "known_public")):
        return "unauthenticated_or_public"
    if "subscriber" in text:
        return "subscriber"
    if "contributor" in text:
        return "contributor"
    if "author" in text:
        return "author"
    return "unknown_or_authenticated"


def _v63_case_key(obj):
    if not isinstance(obj, dict):
        return None
    # Prefer concrete source anchors. IDs from different graph generations
    # are intentionally not used as the sole deduplication key.
    producer = str(obj.get("producer") or "")
    consumer = str(obj.get("consumer") or "")
    function = str(obj.get("function") or producer or "")
    file = str(obj.get("file") or obj.get("source_file") or "")
    line = str(obj.get("line") or obj.get("source_line") or "")
    state = obj.get("state") if isinstance(obj.get("state"), dict) else {}
    hints = tuple(sorted(obj.get("shared_semantic_hints", []) or []))
    # A semantic cross-state relationship has no single concrete source line;
    # retain producer+consumer+hints so distinct consumers are not collapsed.
    if consumer or hints:
        return ("relationship", producer, consumer, hints)
    return ("unit", function, file, line, state.get("storage"), state.get("key"))


def _v63_seed_location(item):
    """Normalize source anchors across V5/V6/V6.1 review schemas.

    V5 stores concrete anchors under callback/relevant_locations, while V6
    review entries normally expose only the function name. V6.1 relationship
    records use producer/consumer/state rather than a single callback anchor.
    Never invent a file or line when the upstream graph does not provide one.
    """
    if not isinstance(item, dict):
        return None, None, None

    function = item.get("function") or item.get("producer")

    callback = item.get("callback")
    if isinstance(callback, dict):
        function = function or callback.get("name")
        if callback.get("file") is not None or callback.get("line") is not None:
            return (
                function,
                callback.get("file"),
                callback.get("line"),
            )

    locations = item.get("relevant_locations")
    if isinstance(locations, list):
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            loc_function = function or loc.get("function") or loc.get("name")
            if loc.get("file") is not None or loc.get("line") is not None:
                return (
                    loc_function,
                    loc.get("file"),
                    loc.get("line"),
                )

    return function, item.get("file"), item.get("line")


def _v63_compact_seed_evidence(source, item):
    """Keep the security evidence needed to start semantic investigation.

    This is deliberately compact: it preserves graph/provenance facts but does
    not embed source code. The semantic reviewer can load code slices only when
    a hypothesis needs them.
    """
    if not isinstance(item, dict):
        return {}

    function, file, line = _v63_seed_location(item)
    evidence = {
        "source": source,
        "id": item.get("id"),
        "function": function,
        "file": file,
        "line": line,
    }

    for key in (
        "priority_score",
        "review_effort",
        "coverage_floor",
        "must_review",
        "surface_class",
        "request_reachable",
        "confidence",
        "status",
    ):
        if key in item:
            evidence[key] = item.get(key)

    # V5 entrypoint / callback / flow evidence.
    for key in ("registration", "entrypoint", "callback", "flow"):
        value = item.get(key)
        if isinstance(value, dict):
            evidence[key] = value

    for key in (
        "registration_api",
        "hook",
        "sources",
        "controls",
        "effects",
        "signals",
        "risk_reasons",
        "required_reasoning",
        "security_meta_hints",
        "security_name_hints",
        "kind",
    ):
        if key in item:
            value = item.get(key)
            if isinstance(value, (list, dict, str, int, float, bool)) or value is None:
                evidence[key] = value

    # V5 has useful source/sink anchors in relevant_locations. Keep only the
    # compact security fields; source code remains a drill-down concern.
    locations = item.get("relevant_locations")
    if isinstance(locations, list):
        compact_locations = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            compact = {}
            for key in ("file", "line", "class", "function", "name", "effects", "controls"):
                if key in loc:
                    compact[key] = loc.get(key)
            if compact:
                compact_locations.append(compact)
        if compact_locations:
            evidence["relevant_locations"] = compact_locations

    # V6.1 concrete state / relationship evidence.
    state = item.get("state")
    if isinstance(state, dict):
        evidence["state"] = {
            key: state.get(key)
            for key in ("storage", "key", "scope", "value_type")
            if key in state
        }

    consumers = item.get("consumers")
    if isinstance(consumers, list):
        compact_consumers = []
        for consumer in consumers:
            if not isinstance(consumer, dict):
                continue
            compact = {"function": consumer.get("function")}
            if "security_signal" in consumer:
                compact["security_signal"] = consumer.get("security_signal")
            compact_consumers.append(compact)
        if compact_consumers:
            evidence["consumers"] = compact_consumers
            evidence["consumer_count"] = item.get("consumer_count", len(compact_consumers))

    for key in (
        "producer_security_signal",
        "security_key_reasons",
        "required_resolution",
    ):
        if key in item:
            evidence[key] = item.get(key)

    return evidence


def _v63_hypothesis_seeds(case):
    themes = set(case.get("themes", []))
    seeds = []
    if "identity" in themes:
        seeds += [
            "Could attacker-controlled identity, ownership, role, capability, token, or account state cross a security boundary?",
            "Could a state transition make a privileged workflow reachable without the expected authorization proof?",
        ]
    if "configuration" in themes:
        seeds += [
            "Could attacker-controlled configuration alter authentication, authorization, registration, verification, routing, or privilege behavior downstream?",
        ]
    if "filesystem" in themes:
        seeds += [
            "Could a path, filename, archive, extension, or derived filesystem target cross a trust boundary and produce read/write/upload/delete or code-execution impact?",
        ]
    if "injection" in themes:
        seeds += [
            "Could an input transformation or custom wrapper preserve attacker control into a parser, query, evaluator, include, or deserializer despite nearby filtering?",
        ]
    if "object_authorization" in themes:
        seeds += [
            "Could an attacker select another user's/object's identifier and pass a local capability check without proving ownership of that target?",
        ]
    if "secrets" in themes:
        seeds += [
            "Could a secret, token, credential, or verification artifact become attacker-readable or reusable across users or requests?",
        ]
    # Always give the model an explicit invitation to invent a hypothesis
    # from evidence rather than forcing it into the predefined taxonomy.
    seeds.append(
        "What security invariant is assumed by this path, and what non-obvious way could that invariant be violated based on the available source evidence?"
    )
    return seeds


def build_adaptive_security_investigation_v63(
    v5_review_index,
    v6_review_index,
    v61_cross_state_index,
    v61_orphan_review_index,
    v61_fallback_index,
):
    """Build adaptive semantic investigation cases without adding a new scan boundary.

    The output is intentionally a plan/evidence index, not a vulnerability verdict.
    Cases are seeded from already discovered security surfaces. The semantic reviewer
    may expand a case when evidence creates a new, source-backed relationship.
    """
    raw = []

    for source_name, items in (
        ("v5", v5_review_index),
        ("v6", v6_review_index),
        ("v6.1_orphan", v61_orphan_review_index),
        ("v6.1_fallback", v61_fallback_index),
    ):
        for item in items or []:
            raw.append((source_name, item))

    for item in v61_cross_state_index or []:
        raw.append(("v6.1_cross_state", item))

    cases = []
    seen = set()

    for source, item in raw:
        effects = _v63_effects(item)
        themes = _v63_themes(item)
        text = _v63_text(item).lower()
        # Any security-relevant V6/V6.1 semantic theme is a valid
        # investigation seed. V6.3 must not suppress a unit merely because
        # the theme was introduced after the original four-theme set.
        security_signal = bool(effects & V63_HIGH_IMPACT_EFFECTS) or bool(
            themes & {
                "identity",
                "configuration",
                "object_authorization",
                "secrets",
                "authorization",
                "ownership",
                "state_transition",
                "security_abstraction",
                "cross_request_state",
            }
        )

        # Cross-state records may have no effects; their concrete producer/
        # consumer relationship is itself the security signal.
        if source == "v6.1_cross_state":
            security_signal = True
            themes.add("configuration")

        if not security_signal:
            continue

        key = _v63_case_key(item)
        if key in seen:
            continue
        seen.add(key)

        seed_function, seed_file, seed_line = _v63_seed_location(item)
        seed_evidence = _v63_compact_seed_evidence(source, item)

        priority = 0
        if effects & V63_HIGH_IMPACT_EFFECTS:
            priority += 50
        if _v63_role_signal(item) in {"unauthenticated_or_public", "subscriber", "contributor"}:
            priority += 35
        if item.get("review_effort") == "deep":
            priority += 30
        if source in {"v6.1_cross_state", "v6.1_orphan", "v6.1_fallback"}:
            priority += 20
        if not effects:
            priority += 10

        # Upstream deep is a floor: V6.3 may promote normal → deep,
        # but must never downgrade an upstream deep review unit.
        upstream_effort = item.get("review_effort")
        review_effort = (
            "deep"
            if upstream_effort == "deep" or priority >= 80
            else "normal"
        )

        case = {
            "id": f"WP-V63-CASE-{len(cases)+1:04d}",
            "seed_source": source,
            "seed_id": item.get("id"),
            "seed_function": seed_function,
            "seed_file": seed_file,
            "seed_line": seed_line,
            "seed_evidence": seed_evidence,
            "themes": sorted(themes),
            "effects": sorted(effects),
            "attacker_signal": _v63_role_signal(item),
            "priority_score": priority,
            "review_effort": review_effort,
            "status": "requires_adaptive_semantic_investigation",
            "hypothesis_seeds": [],
            "expansion_rules": [
                "follow only source-backed callers, callees, state readers/writers, inheritance, and framework edges revealed by the current case",
                "when a new security-relevant relationship is discovered, create a child hypothesis instead of restarting repository-wide discovery",
                "compare attacker-controlled state with the exact target identity/object before accepting an authorization or ownership bypass",
                "follow cross-request state when a producer can influence a persisted value consumed by a security-sensitive path",
                "actively search for counter-evidence before increasing confidence or impact",
                "stop when the hypothesis is disproved, reaches a concrete accepted impact, or has an explicit unresolved proof gap",
            ],
            "proof_requirements": [
                "attacker reachability",
                "attacker control over relevant input or state",
                "missing or bypassed security control",
                "source-backed security effect",
                "concrete impact or explicit proof gap",
            ],
        }
        case["hypothesis_seeds"] = _v63_hypothesis_seeds(case)
        cases.append(case)

    cases.sort(key=lambda x: (-x["priority_score"], x["id"]))

    # Re-number after sorting for deterministic IDs without using source-specific
    # names or assumptions.
    for i, case in enumerate(cases, 1):
        case["id"] = f"WP-V63-CASE-{i:04d}"

    return {
        "schema_version": "6.3",
        "purpose": "adaptive source-backed security hypothesis investigation",
        "policy": {
            "discovery_is_seeded_by_existing_security_surfaces": True,
            "ai_may_generate_novel_hypotheses": True,
            "ai_may_expand_cases_when_new_evidence_appears": True,
            "no_fixed_hypothesis_budget": True,
            "no_repository_wide_freeform_scan": True,
            "counter_evidence_required_before_confirmation": True,
            "impact_requires_source_backed_proof": True,
            "unknown_is_not_safe": True,
            "incomplete_is_not_safe": True,
        },
        "investigation_loop": [
            "seed_from existing V5/V6/V6.1 evidence",
            "form one or more attack hypotheses",
            "test each hypothesis against source evidence",
            "expand only along newly justified security relationships",
            "actively seek counter-evidence",
            "prove concrete impact or record the exact remaining proof gap",
            "do not convert suspicion into a finding without the proof chain",
        ],
        "case_count": len(cases),
        "cases": cases,
    }


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

    function_index = index_rest_anonymous_callbacks(
        function_index,
        rest_eps,
    )

    entrypoints = (
        action_eps
        +
        rest_eps
    )

    print("[*] Building V5 security graph...")

    raw_registrations, raw_registration_gaps = (
        collect_generic_registrations(
            plugin_root
        )
    )

    resolved_registrations, resolver_stats = (
        resolve_dynamic_registrations_v5(
            plugin_root,
            raw_registrations
        )
    )

    generic_v5_review_units = (
        build_generic_review_units_v5(
            resolved_registrations,
            function_index
        )
    )

    rest_v5_review_units = (
        build_rest_review_units_v5(
            rest_eps,
            function_index
        )
    )

    v5_review_units = (
        generic_v5_review_units
        + rest_v5_review_units
    )

    v5_review_units = (
        enrich_review_units_with_flow_v5(
            v5_review_units,
            function_index
        )
    )

    v5_gap_units = (
        build_security_relevant_gap_units_v5(
            plugin_root,
            resolved_registrations,
            function_index
        )
    )

    v5_review_index = (
        build_review_index_v5(
            v5_review_units
        )
    )

    v5_security_graph = (
        build_security_graph_v5(
            resolved_registrations,
            v5_review_units,
            v5_gap_units
        )
    )


    # ------------------------------------------------------------
    # V6 Security State Graph
    # ------------------------------------------------------------

    print("[*] Building V6 security state graph...")

    v6_state_units = (
        build_security_state_graph_v6(
            plugin_root,
            function_index,
            resolved_registrations,
            v5_review_units,
            v5_gap_units,
        )
    )

    v6_review_index = (
        build_v6_review_index(
            v6_state_units
        )
    )


    # ------------------------------------------------------------
    # V6.1 Coverage Safety Net
    # ------------------------------------------------------------

    print("[*] Building V6.1 coverage safety net...")

    v61_coverage = (
        build_coverage_safety_net_v61(
            function_index,
            v5_review_index,
            v6_review_index,
        )
    )

    v61_orphan_review_index = (
        v61_coverage[
            "orphan_review_queue"
        ]
    )

    v61_cross_state_index = (
        v61_coverage[
            "cross_state_dependencies"
        ]
    )

    v61_fallback_index = v61_coverage.get(
        "orphan_fallback_hypotheses",
        [],
    )

    # ------------------------------------------------------------
    # V6.2 Semantic review packs
    # ------------------------------------------------------------

    print("[*] Building V6.2 semantic review packs...")

    semantic_review_plan = build_semantic_review_packs_v62(
        v5_review_index,
        v6_review_index,
        v61_orphan_review_index,
        v61_fallback_index,
    )

    # ------------------------------------------------------------
    # V6.3 Adaptive security investigation
    # ------------------------------------------------------------

    print("[*] Building V6.3 adaptive security investigation...")

    adaptive_investigation = build_adaptive_security_investigation_v63(
        v5_review_index,
        v6_review_index,
        v61_cross_state_index,
        v61_orphan_review_index,
        v61_fallback_index,
    )

    v5_output_dir = (
        Path("/opt/codex-security/wpsec-output")
        / plugin_root.name
        / "v5"
    )

    v5_output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    flow_counts = {}

    for unit in v5_review_units:
        confidence = (
            unit.get("flow", {})
            .get("confidence", "unknown")
        )

        flow_counts[confidence] = (
            flow_counts.get(
                confidence,
                0
            )
            + 1
        )

    effort_counts = {}

    for unit in v5_review_index:
        effort = unit.get(
            "review_effort",
            "unknown"
        )

        effort_counts[effort] = (
            effort_counts.get(
                effort,
                0
            )
            + 1
        )

    v5_summary = {
        "schema_version": "5.0",

        "plugin":
            plugin_root.name,

        "indexed_function_names":
            len(function_index),

        "raw_registrations":
            len(raw_registrations),

        "resolved_registration_variants":
            len(resolved_registrations),

        "raw_registration_gaps":
            len(raw_registration_gaps),

        "review_units":
            len(v5_review_units),

        "model_facing_gaps":
            len(v5_gap_units),

        "flow_confidence":
            flow_counts,

        "review_effort":
            effort_counts,

        "coverage_policy": {
            "all_review_units_must_be_dispositioned": True,
            "high_impact_low_privilege_floor": "deep",
            "unknown_flow_is_not_safe": True,
            "priority_is_not_a_suppression_boundary": True,
        },

        "resolver_stats":
            resolver_stats,
    }

    write_json(
        v5_output_dir / "summary.json",
        v5_summary
    )

    write_json(
        v5_output_dir / "review-index.json",
        v5_review_index
    )

    write_json(
        v5_output_dir / "gap-index.json",
        v5_gap_units
    )

    write_json(
        v5_output_dir / "security-graph.json",
        v5_security_graph
    )


    # ------------------------------------------------------------
    # V6 output artifacts
    # ------------------------------------------------------------

    v6_output_dir = (
        Path("/opt/codex-security/wpsec-output")
        / plugin_root.name
        / "v6"
    )

    v6_output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    v6_effort_counts = {}

    for unit in v6_review_index:
        effort = unit.get(
            "review_effort",
            "unknown"
        )

        v6_effort_counts[effort] = (
            v6_effort_counts.get(
                effort,
                0
            ) + 1
        )

    v6_reason_counts = {}

    for unit in v6_state_units:
        for reason in unit.get(
            "risk_reasons",
            []
        ):
            v6_reason_counts[reason] = (
                v6_reason_counts.get(
                    reason,
                    0
                ) + 1
            )

    v6_summary = {
        "schema_version": "6.0",

        "plugin":
            plugin_root.name,

        "security_state_units":
            len(v6_state_units),

        "review_units":
            len(v6_review_index),

        "review_effort":
            v6_effort_counts,

        "risk_reasons":
            v6_reason_counts,

        "purpose": (
            "authorization, identity, ownership, "
            "authentication, privilege and "
            "security-state transition review"
        ),
    }

    write_json(
        v6_output_dir / "summary.json",
        v6_summary
    )

    write_json(
        v6_output_dir / "review-index.json",
        v6_review_index
    )

    write_json(
        v6_output_dir / "security-state-graph.json",
        v6_state_units
    )


    # ------------------------------------------------------------
    # V6.1 output artifacts
    # ------------------------------------------------------------

    v61_output_dir = (
        Path("/opt/codex-security/wpsec-output")
        / plugin_root.name
        / "v6.1"
    )

    v61_output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    write_json(
        v61_output_dir / "semantic-review-plan.json",
        semantic_review_plan,
    )

    v61_summary = {
        "schema_version": "6.1",

        "plugin":
            plugin_root.name,

        "orphan_review_units":
            len(
                v61_orphan_review_index
            ),

        "semantic_review_packs":
            semantic_review_plan["pack_count"],

        "semantic_review_raw_units":
            semantic_review_plan["raw_unit_count"],

        "cross_state_dependencies":
            len(
                v61_cross_state_index
            ),

        "reverse_indexed_callees":
            len(
                v61_coverage.get(
                    "reverse_call_index",
                    {}
                )
            ),

        "state_writers":
            len(
                v61_coverage.get(
                    "state_accesses",
                    {}
                ).get(
                    "writes",
                    []
                )
            ),

        "state_readers":
            len(
                v61_coverage.get(
                    "state_accesses",
                    {}
                ).get(
                    "reads",
                    []
                )
            ),

        "security_consumers":
            len(
                v61_coverage.get(
                    "state_accesses",
                    {}
                ).get(
                    "consumers",
                    []
                )
            ),

        "purpose": (
            "coverage safety net for custom, "
            "reverse-reachable, and cross-state "
            "security logic"
        ),
    }

    write_json(
        v61_output_dir
        / "summary.json",
        v61_summary
    )

    write_json(
        v61_output_dir
        / "orphan-review-index.json",
        v61_orphan_review_index
    )


    write_json(
        v61_output_dir
        / "orphan-fallback-index.json",
        v61_coverage.get(
            "orphan_fallback_hypotheses",
            []
        )
    )

    write_json(
        v61_output_dir
        / "cross-state-index.json",
        v61_cross_state_index
    )

    write_json(
        v61_output_dir
        / "coverage-safety-net.json",
        v61_coverage
    )

    # ------------------------------------------------------------
    # V6.3 output artifacts
    # ------------------------------------------------------------

    v63_output_dir = (
        Path("/opt/codex-security/wpsec-output")
        / plugin_root.name
        / "v6.3"
    )

    v63_output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    write_json(
        v63_output_dir / "investigation-plan.json",
        adaptive_investigation,
    )

    write_json(
        v63_output_dir / "hypotheses.json",
        {
            "schema_version": "6.3",
            "purpose": "model-generated hypotheses are expected to be expanded during semantic investigation",
            "cases": [
                {
                    "id": case["id"],
                    "seed_id": case["seed_id"],
                    "seed_source": case["seed_source"],
                    "seed_function": case.get("seed_function"),
                    "seed_file": case.get("seed_file"),
                    "seed_line": case.get("seed_line"),
                    "seed_evidence": case.get("seed_evidence", {}),
                    "hypothesis_seeds": case["hypothesis_seeds"],
                    "status": "seed_only",
                }
                for case in adaptive_investigation["cases"]
            ],
        },
    )

    write_json(
        v63_output_dir / "investigation-cases.json",
        adaptive_investigation["cases"],
    )

    v63_summary = {
        "schema_version": "6.3",
        "plugin": plugin_root.name,
        "investigation_cases": adaptive_investigation["case_count"],
        "policy": adaptive_investigation["policy"],
        "purpose": "adaptive source-backed hypothesis generation and investigation",
    }

    write_json(
        v63_output_dir / "summary.json",
        v63_summary,
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
    print("WordPress Security Graph Mapper V5")
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
