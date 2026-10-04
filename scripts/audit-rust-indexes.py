#!/usr/bin/env python3
"""Enumerate Rust indexing candidates, not prove absence of indexing panics.

Run with tree-sitter==0.25.2 and tree-sitter-rust==0.24.2. Macro token trees
are inspected heuristically; this does not expand macros or evaluate all cfgs.
The output includes exact source locations so each candidate can be reviewed.
"""
import json
from importlib.metadata import version
from pathlib import Path

import tree_sitter
import tree_sitter_rust

ROOT = Path(__file__).resolve().parents[1]
SOURCE_GLOBS = ("crates/**/src/**/*.rs", "guest/aiec-guest/src/**/*.rs")
TEST_ATTRIBUTES = {"#[cfg(test)]", "#[cfg(all(test,unix))]", "#[test]"}


def is_test_item(node, source):
    if not node.type.endswith("_item") or node.type == "attribute_item":
        return False
    previous = node.prev_named_sibling
    while previous and previous.type in ("attribute_item", "line_comment", "block_comment"):
        if previous.type == "attribute_item":
            attribute = "".join(source[previous.start_byte:previous.end_byte].decode().split())
            if attribute in TEST_ATTRIBUTES or attribute.startswith("#[tokio::test"):
                return True
        previous = previous.prev_named_sibling
    name = node.child_by_field_name("name") if node.type == "mod_item" else None
    return name is not None and source[name.start_byte:name.end_byte] == b"tests"


def collect(node, source, path, sites, macro_candidates):
    if is_test_item(node, source):
        return
    if node.type == "index_expression":
        sites.append(site(node, source, path, node.start_byte))
    if node.type == "token_tree" and source[node.start_byte:node.start_byte + 1] == b"[":
        previous = node.prev_sibling
        if previous is not None and (
            previous.type in ("identifier", "self")
            or (previous.type == "token_tree"
                and source[previous.end_byte - 1:previous.end_byte] in (b")", b"]", b"}"))
        ):
            start = previous.start_byte
            before = previous.prev_sibling
            while before is not None and before.type in ("identifier", "self", ".", "::"):
                start = before.start_byte
                before = before.prev_sibling
            macro_candidates.append(site(node, source, path, start))
    for child in node.named_children:
        collect(child, source, path, sites, macro_candidates)


def site(node, source, path, start):
    return {
        "path": str(path.relative_to(ROOT)),
        "line": node.start_point.row + 1,
        "expr": source[start:node.end_byte].decode(),
    }


def main():
    parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))
    sites, macro_candidates, errors = [], [], []
    files = 0
    for path in sorted(path for pattern in SOURCE_GLOBS for path in ROOT.glob(pattern)):
        if "tests" in path.relative_to(ROOT).parts or path.name == "tests.rs" or path.stem.endswith("_tests"):
            continue
        files += 1
        source = path.read_bytes()
        tree = parser.parse(source)
        if tree.root_node.has_error:
            errors.append(str(path.relative_to(ROOT)))
        collect(tree.root_node, source, path, sites, macro_candidates)
    print(json.dumps({
        "parser_versions": {name: version(name) for name in ("tree-sitter", "tree-sitter-rust")},
        "source_globs": list(SOURCE_GLOBS),
        "files": files,
        "errors": errors,
        "index_nodes": len(sites),
        "macro_candidate_count": len(macro_candidates),
        "sites": sites,
        "macro_candidates": macro_candidates,
    }, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
