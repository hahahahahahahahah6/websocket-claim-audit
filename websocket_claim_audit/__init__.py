"""Offline documentation and AST audit."""
import argparse
import ast
import fnmatch
import json
import re
from pathlib import Path

__version__ = '0.1.0'
WS_MODULES = {'websockets', 'websocket', 'websocket_client'}
POSITIVE = [
    'websocket support', 'web socket support', 'websocket connections',
    'web socket connections', 'websocket connection', 'web socket connection',
    'websocket server', 'web socket server', 'websocket client', 'web socket client',
    'websocket api', 'websocket endpoint', 'websocket endpoints',
    'supports websockets', 'supports web sockets', 'supports websocket',
    'support for websockets', 'support for web sockets', 'support for websocket',
    'uses websockets', 'uses web sockets', 'uses websocket',
    'using websockets', 'using web sockets', 'using websocket',
    'over websockets', 'over web sockets', 'over websocket',
    'via websockets', 'via web sockets', 'via websocket',
    'websocket based', 'websocket powered',
]
NEGATIVE = [
    'no websocket support', 'no web socket support',
    'does not support websockets', 'does not support web sockets',
    'does not support websocket', 'does not use websockets',
    'does not use web sockets', 'does not use websocket',
    'websocket not supported', 'web socket not supported',
    'without websockets', 'without web sockets', 'without websocket',
    'no websockets', 'no web sockets', 'no websocket',
]


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b')


def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(fence[1]) + r',}\s*$', line):
                fence = None
            lines.append('')
        elif match:
            fence = (match[1][0], len(match[1]))
            lines.append('')
        else:
            lines.append(line)
    positive = negative = False
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        normalized = re.sub(r'\s+', ' ', paragraph.lower().replace("n't", ' not').replace('-', ' '))
        negative |= bool(pattern(NEGATIVE).search(normalized))
        normalized = pattern(NEGATIVE).sub(' ', normalized)
        positive |= bool(pattern(POSITIVE).search(normalized))
    return positive, negative


def evidence(text):
    tree = ast.parse(text)
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                imports[alias.asname or alias.name] = node.module + '.' + alias.name

    def resolved(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = resolved(node.value)
            return base + '.' + node.attr if base else ''
        return ''

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    methods = {n.func.attr for n in calls if isinstance(n.func, ast.Attribute)}
    for call in calls:
        func = call.func
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.attr in {'serve', 'connect', 'create_connection'}
                and imports.get(func.value.id, '').split('.')[0] in WS_MODULES):
            return 'A'
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            args += [a for a in (node.args.vararg, node.args.kwarg) if a]
            for arg in args:
                annotation = arg.annotation
                name = annotation.id if isinstance(annotation, ast.Name) else annotation.attr if isinstance(annotation, ast.Attribute) else ''
                if name == 'WebSocket':
                    for child in ast.walk(node):
                        if (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                                and child.func.attr == 'accept' and isinstance(child.func.value, ast.Name)
                                and child.func.value.id == arg.arg):
                            return 'B'
    for call in calls:
        name = resolved(call.func)
        module, _, cls = name.rpartition('.')
        root = module.split('.')[0]
        if cls == 'WebSocketApp' and root in WS_MODULES and 'run_forever' in methods:
            return 'C'
        if cls == 'WebSocketResponse' and root == 'aiohttp' and 'prepare' in methods:
            return 'C'
        if cls in {'Server', 'AsyncServer'} and root == 'socketio' and methods & {'emit', 'send', 'on'}:
            return 'C'
        if ((cls == 'WebsocketServer' and root == 'websocket_server') or
                (cls == 'SimpleWebSocketServer' and root == 'SimpleWebSocketServer')) and methods & {'serve_forever', 'run_forever'}:
            return 'C'
    return None


def audit(root, ignore=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir() or not root.stat().st_mode & 0o444:
        raise ValueError('root must be a readable directory')
    positive = negative = False
    production = []
    testing = []
    errors = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root.parent):
            continue
        relative = path.relative_to(root)
        name = relative.as_posix()
        if any(fnmatch.fnmatchcase(name, glob) for glob in ignore):
            continue
        if not path.is_file():
            continue
        if (name == 'README.md' or ('docs' in relative.parts[:-1] and path.suffix.lower() == '.md')):
            p, n = claims(path.read_text(encoding='utf-8'))
            positive |= p
            negative |= n
        if path.suffix != '.py':
            continue
        is_test = 'tests' in relative.parts[:-1] or path.name.startswith('test_') or path.name.endswith('_test.py')
        if {'fixtures', 'docs', 'examples'} & set(relative.parts[:-1]):
            continue
        try:
            route = evidence(path.read_text(encoding='utf-8'))
        except (SyntaxError, UnicodeError) as exc:
            errors.append(name + ': ' + str(exc))
            continue
        if route:
            (testing if is_test else production).append({'path': name, 'route': route})
    findings = []
    if positive and not production:
        findings.append({'rule': 'documented-websocket-claim-false', 'severity': 'MEDIUM' if testing else 'HIGH', 'message': 'Documented live socket link lacks production evidence.'})
    if negative and production:
        findings.append({'rule': 'documented-no-websocket-claim-false', 'severity': 'HIGH', 'message': 'Documented absence conflicts with production evidence.'})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'verdict': 'FAIL' if failed else 'PASS', 'findings': findings,
            'claims': {'positive': positive, 'negative': negative},
            'evidence': production, 'test_evidence': testing, 'parse_errors': errors}


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            self.print_usage()
            self.exit(1, message + '\n')
    parser = Parser(description=__doc__)
    parser.add_argument('root')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='HIGH')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore, args.fail_on)
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc) + '\n')
    if args.json:
        print(json.dumps(result))
    else:
        print(result['verdict'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        if args.verbose:
            for item in result['evidence'] + result['test_evidence']:
                print('Evidence {path}: route {route}'.format(**item))
            for error in result['parse_errors']:
                print('Parse error: ' + error)
    return 2 if result['verdict'] == 'FAIL' else 0
