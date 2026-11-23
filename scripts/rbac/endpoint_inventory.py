#!/usr/bin/env python3
# Copyright 2026 OpenObserve Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Export the upstream route parser and RBAC declarations without building the server."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

arguments = argparse.ArgumentParser()
arguments.add_argument("--check", action="store_true", help="Fail if the committed inventory is stale")
args = arguments.parse_args()

ROOT = Path(__file__).resolve().parents[2]
ROUTER = ROOT / "src/api/http/src/handler/http/router"
source = (ROUTER / "openapi_coverage/mod.rs").read_text()
rbac = (ROUTER / "rbac.rs").read_text()
engine = (ROOT / "src/extensions/rbac/src/lib.rs").read_text()


def item(text, start, end):
    return text[text.index(start):text.index(end, text.index(start))]


# Routers merged into mod.rs from other files: source, mount prefix and the mount it must sit in,
# or None for router-node proxies, which forward to the data-node routes already listed here.
EXTERNAL_ROUTERS = {
    "crate::oidc::routes": ("src/api/http/src/oidc.rs", "/auth", 'router.nest("/auth", auth_routes)'),
    "crate::router::http::create_router_routes": None,
    "crate::router::http::create_splunk_collector_proxy_routes": None,
    # The static web UI, which the route gate admits through its own static-asset rule.
    "ui_routes": None,
}
# Calls inside router mounts that build no routes of their own.
ROUTER_HELPERS = {
    "Router::new", "SwaggerUi::new", "middleware::from_fn", "openapi::ApiDoc::openapi",
    "DefaultBodyLimit::max", "RequestDecompressionLayer::new", "std::ptr::eq", "org_from_path", "routed_path",
}
METHODS = ("get", "post", "put", "delete", "patch", "head", "options", "trace", "any")


def call_arguments(text, open_paren):
    depth = 0
    for index in range(open_paren, len(text)):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        if depth == 0:
            return text[open_paren + 1:index]
    raise SystemExit("Unbalanced parentheses while reading router mounts")


def mounted_calls(source):
    """Every function a router mount calls, following variables back to their `let`."""
    local = set(re.findall(r"\bfn (\w+)", source))
    local |= set(re.findall(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*(?:move\s*)?\|", source))
    pending, seen, calls = [], set(), set()
    for mount in re.finditer(r"\.(?:merge|nest|nest_service|route_service|fallback_service)\(", source):
        pending.append(call_arguments(source, mount.end() - 1))
    while pending:
        expression = pending.pop()
        for call in re.finditer(r"(?<![.\w])([A-Za-z_][\w:]*)\s*\(", expression):
            name = call.group(1)
            if name.startswith("crate::") or name.split("::")[-1] not in local:
                calls.add(name)
        for variable in re.findall(r"(?<![.\w:])([a-z_]\w*)\s*(?=[),]|$)", expression):
            if variable in seen:
                continue
            seen.add(variable)
            for binding in re.finditer(rf"\blet\s+(?:mut\s+)?{variable}\b[^=;]*=([^;]*);", source):
                pending.append(binding.group(1))
    return {name for name in calls if name not in ROUTER_HELPERS and name not in METHODS}


def external_routes():
    """Routes the upstream parser cannot see because their router lives in another file."""
    source = (ROUTER / "mod.rs").read_text().split("\n#[cfg(test)]\nmod tests {")[0]
    source = re.sub(r"//[^\n]*", "", source)
    merged = mounted_calls(source)
    unknown = merged - EXTERNAL_ROUTERS.keys()
    if unknown:
        raise SystemExit(f"Classify these router calls in EXTERNAL_ROUTERS: {sorted(unknown)}")
    routes = []
    for path, prefix, mount in filter(None, (EXTERNAL_ROUTERS[name] for name in sorted(merged))):
        if mount not in source:
            raise SystemExit(f"{path} is no longer mounted as `{mount}`; update its prefix")
        text = (ROOT / path).read_text()
        for found in re.finditer(r"\.route\(", text):
            arguments = call_arguments(text, found.end() - 1)
            route = re.match(r'\s*"([^"]+)"\s*,', arguments)
            methods = re.findall(rf"\b({'|'.join(METHODS)})\(", arguments)
            if not route or not methods:
                raise SystemExit(f"Cannot read the route `{arguments.strip()[:60]}` in {path}")
            routes += [f"{method.upper()} {prefix}{route.group(1)}" for method in methods]
    return routes


def check_cluster_methods():
    declared = set()
    for proto in (ROOT / "src/proto/proto/cluster").glob("*.proto"):
        source = re.sub(r"//[^\n]*|/\*.*?\*/", "", proto.read_text(), flags=re.S)
        service = None
        for line in source.splitlines():
            if match := re.match(r"\s*service\s+(\w+)\s*\{", line):
                service = match.group(1)
            elif service and (match := re.match(r"\s*rpc\s+(\w+)\s*\(", line)):
                declared.add((service, match.group(1)))
            elif line.strip() == "}":
                service = None
    documented = set()
    for line in (ROOT / "docs/rbac/rpc.md").read_text().splitlines():
        if not line.startswith("| "):
            continue
        service, methods, _ = (field.strip() for field in line.strip("|").split("|"))
        if service in {"Service", "---", "Arrow Flight"} or service.startswith("OTLP "):
            continue
        documented.update((service, method.strip()) for method in methods.split(","))
    if not declared or declared != documented:
        raise SystemExit(f"Review the gRPC matrix: missing {sorted(declared - documented)}, "
                         f"obsolete {sorted(documented - declared)}")


check_cluster_methods()
with tempfile.TemporaryDirectory(prefix="o2-rbac-inventory-") as temporary:
    crate = Path(temporary)
    (crate / "src").mkdir()
    (crate / "Cargo.toml").write_text('''[package]
name = "o2-rbac-route-inventory"
version = "0.0.0"
edition = "2024"
[dependencies]
regex = "1"
[features]
enterprise = []
cloud = []
cpu-profiling = []
profiling = []
''')
    enums = ""
    for name in ["Action", "ResourceKind"]:
        start = engine.index("pub enum " + name)
        end = engine.index("}", start) + 1
        enums += "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n" + engine[start:end] + "\n"
    disposition = item(rbac, "pub(super) enum Disposition", "#[derive(Clone)]")
    classifier = item(rbac, "pub(super) fn disposition", "pub(super) fn forbidden")
    types = item(source, "#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]\nstruct ParsedRoute", "struct PublishedOp")
    parser = item(source, "fn strip_comments", "fn parsed_routes")
    constants = item(source, "const VERBS", "/// Canonical") + item(source, "const ROUTER_ROOT", "/// What a handler")
    code = "use std::{collections::BTreeSet, ops::Range};\nuse regex::Regex;\ntype MountSpan = (Range<usize>, String, bool);\n"
    code += enums + "#[derive(Debug)]\n" + disposition.replace("pub(super)", "pub")
    code += classifier.replace("pub(super)", "pub") + types + constants + parser
    code += '''fn main() {
    let source = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let routes = parse_router(&source);
    assert!(routes.len() >= 900);
    let external = std::fs::read_to_string(std::env::args().nth(2).unwrap()).unwrap();
    println!("# HTTP endpoint authorization matrix\\n\\nGenerated by `python3 scripts/rbac/endpoint_inventory.py` from the existing upstream route parser and RBAC classifier. Includes inactive Enterprise/Cloud routes for upgrade review. Unsupported means HTTP 403 while enabled, not implemented authorization. UI static service mounts are separately declared in the outer gate. Versioned internal RBAC forwarding aliases share these canonical classifications and exist only on enforcing data nodes.\\n\\n| Method | Route | Active in OSS | RBAC disposition |\\n| --- | --- | --- | --- |");
    for route in routes {
        println!("| {} | `{}` | {} | {:?} |", route.method, route.path, route.active, disposition(&route.method, &route.path));
    }
    for (method, path) in external.lines().filter_map(|line| line.split_once(' ')) {
        println!("| {method} | `{path}` | true | {:?} |", disposition(method, path));
    }
}
'''
    (crate / "src/main.rs").write_text(code)
    (crate / "external.txt").write_text("\n".join(external_routes()))
    result = subprocess.run(["cargo", "+stable", "run", "--quiet", "--offline", "--manifest-path", str(crate / "Cargo.toml"), "--", str(ROUTER / "mod.rs"), str(crate / "external.txt")], check=True, capture_output=True, text=True)
    destination = ROOT / "docs/rbac/endpoints.md"
    if args.check:
        if not destination.exists() or destination.read_text() != result.stdout:
            raise SystemExit("RBAC endpoint inventory is stale; review and regenerate it")
        print("RBAC endpoint inventory matches route parser and authorization declarations")
    else:
        destination.write_text(result.stdout)
        print(f"Wrote docs/rbac/endpoints.md ({len(result.stdout.splitlines()) - 6} rows)")
