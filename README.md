# websocket-claim-audit

Offline, standard-library-only audit of documented framed socket capabilities against Python AST evidence. Version 0.1.0, Python 3.9 or later.

Install and run:

```sh
python3 -m pip install .
websocket-claim-audit /path/to/project --json
python3 -m websocket_claim_audit /path/to/project --verbose
python3 -m unittest discover -s tests -v
python3 -m build
```

The scanner reads root README.md and Markdown files with a docs path component. It excludes fenced blocks, counts inline code, joins paragraph lines, lowercases text, expands contractions, and converts hyphens to spaces. Negative spans are removed before positive matching. Exact word-boundary templates alone count; the complete template lists are in the package's POSITIVE and NEGATIVE constants.

Production evidence comes from alias-resolved library calls, annotated parameters that accept a channel, or paired object creation and activation calls in the same module. Source is parsed, never executed. Tests, fixtures, documentation, examples, and symlinked files are excluded from production evidence. Evidence confined to tests produces a MEDIUM finding. Environment files are never read.

Options: `--json` emits a JSON object with verdict, findings, claim flags, evidence paths and routes, and parse errors. `--verbose` lists evidence in human output. Repeat `--ignore GLOB` to exclude root-relative paths. `--fail-on HIGH` is the default; `--fail-on MEDIUM` also fails on MEDIUM findings. `--version` prints the version. Exit 0 means PASS, 2 means findings meet the threshold, and 1 means a usage or root access error.

Rule identifiers:

```text
documented-websocket-claim-false
documented-no-websocket-claim-false
```

## Limitations

Only the exact phrase templates in the constants count as claims. Bare websocket, web socket, socket, live, real time, and real-time words do not count. HTTP polling, TCP sockets, HTTP hooks, and chunked output do not establish a framed socket channel. Imports, names, comments, docstrings, decorators alone, and string literals are insufficient evidence. Static patterns cannot prove runtime behavior. Paired calls need only share a module; they need not share a receiver. Invalid source is reported in parse_errors and supplies no evidence. A positive promise without source fails; a negative promise without source passes. Each family yields at most one finding. This repository deliberately describes the audit using paraphrases so its own prose contains no audited claim.
