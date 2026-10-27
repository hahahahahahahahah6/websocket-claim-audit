import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from websocket_claim_audit import audit, claims, evidence, main

ROOT = Path(__file__).resolve().parents[1]
A = 'import websockets\nwebsockets.serve(handler, "localhost", 8765)'


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                code = main(list(args))
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue()

    def case(self, claim, source=None, severity=None, rule='documented-websocket-claim-false'):
        self.put('README.md', claim)
        if source is not None:
            self.put('app.py', source)
        code, output = self.run_cli(str(self.root), '--json')
        result = json.loads(output)
        if severity:
            self.assertEqual([(f['rule'], f['severity']) for f in result['findings']], [(rule, severity)])
        else:
            self.assertEqual(result['findings'], [])
        self.assertEqual(code, 2 if severity == 'HIGH' else 0)
        self.assertEqual(result['verdict'], 'FAIL' if code == 2 else 'PASS')
        return result

    def test_01_serve(self):
        self.case('websocket server', A)

    def test_02_connect(self):
        self.case('supports websockets', 'import websockets\nwebsockets.connect("ws://localhost:8765")')

    def test_03_framework(self):
        self.case('websocket endpoint', 'async def endpoint(ws: WebSocket):\n await ws.accept()')

    def test_04_app(self):
        self.case('uses websockets', 'from websocket import WebSocketApp\na = WebSocketApp(url)\na.run_forever()')

    def test_05_aiohttp(self):
        self.case('websocket support', 'from aiohttp.web import WebSocketResponse\na = WebSocketResponse()\na.prepare(request)')

    def test_06_socketio(self):
        self.case('over websockets', 'import socketio\na = socketio.AsyncServer()\na.emit("event")')

    def test_07_handler(self):
        self.case('websocket server', 'def websocket_handler():\n print("hi")\n return []', 'HIGH')

    def test_08_import(self):
        for module in ['websockets', 'websocket', 'websocket_client', 'socketio', 'aiohttp']:
            with self.subTest(module=module):
                self.case('supports websocket', 'import ' + module, 'HIGH')

    def test_09_tcp(self):
        self.case('websocket connection', 'import socket\ns = socket.socket()\ns.send(b"hi")\ns.recv(10)', 'HIGH')

    def test_10_polling(self):
        self.case('websocket client', 'import requests, time\nwhile True:\n requests.get(url)\n time.sleep(1)', 'HIGH')

    def test_11_no_accept(self):
        self.case('websocket endpoint', '@app.websocket("/ws")\ndef endpoint(ws: WebSocket):\n return 1', 'HIGH')

    def test_12_no_prepare(self):
        self.case('websocket support', 'from aiohttp import WebSocketResponse\na = WebSocketResponse()', 'HIGH')

    def test_13_negative(self):
        self.case('no websocket support', A, 'HIGH', 'documented-no-websocket-claim-false')

    def test_14_no_claim(self):
        self.case('A small utility.', A)

    def test_15_bare_noun(self):
        self.case('the websocket chapter explains the protocol', 'import websockets')

    def test_16_polling_claim(self):
        self.case('polls every second for updates', 'while True:\n requests.get(url)')

    def test_17_no_source(self):
        self.case('supports websockets', severity='HIGH')
        self.case('no websocket support')

    def test_18_test_only(self):
        self.put('tests/test_link.py', A)
        result = self.case('supports websockets', severity='MEDIUM')
        self.assertEqual(result['evidence'], [])
        self.assertEqual(self.run_cli(str(self.root), '--fail-on', 'MEDIUM')[0], 2)

    def test_19_fences_inline(self):
        self.case('```text\nwebsocket support\n```')
        self.case('~~~\nwebsocket server\n~~~')
        self.case('`websocket support`', severity='HIGH')

    def test_20_negation(self):
        self.assertEqual(claims('does not support websockets'), (False, True))
        self.case('does not support websockets', A, 'HIGH', 'documented-no-websocket-claim-false')

    def test_21_generic_connect(self):
        for source in ['import sqlite3 as db\ndb.connect("db")', 'client.connect(url)', 'connect(url)']:
            self.case('supports websockets', source, 'HIGH')

    def test_22_cli(self):
        self.assertEqual(self.run_cli('--version'), (0, '0.1.0\n'))
        self.put('app.py', A)
        self.put('docs/guide.md', 'no websocket support')
        self.assertEqual(self.run_cli(str(self.root), '--json')[0], 2)
        code, output = self.run_cli(str(self.root), '--verbose', '--ignore', 'docs/*')
        self.assertEqual(code, 0)
        self.assertIn('Evidence app.py: route A', output)
        self.assertEqual(self.run_cli(str(self.root / 'missing'))[0], 1)
        self.assertEqual(self.run_cli('--bad')[0], 1)

    def test_23_self(self):
        result = audit(ROOT)
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['claims'], {'positive': False, 'negative': False})

    def test_24_env_guard(self):
        self.put('fixtures/.env', 'MARKER_ONLY_NOT_A_SECRET')
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.case('A utility', A)

    def test_25_packaging(self):
        bare = re.compile(r'\b' + 'py' + r'thon\b(?!3)')
        for path in list((ROOT / 'websocket_claim_audit').glob('*.py')) + list((ROOT / 'tests').rglob('*.py')) + [ROOT / 'README.md']:
            self.assertIsNone(bare.search(path.read_text()), str(path))
        config = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('setuptools>=77', config)
        self.assertIn('license = "MIT"', config)
        self.assertIn('recursive-include tests', (ROOT / 'MANIFEST.in').read_text())

    def test_26_aliases(self):
        for source in ['import websockets as ws\nws.connect(url)', 'from websockets import sync as ws\nws.connect(url)', 'import websocket as ws\nws.create_connection(url)', 'from websocket import WebSocketApp as App\na=App(url)\na.run_forever()', 'from websocket_server import WebsocketServer as S\ns=S()\ns.serve_forever()', 'import SimpleWebSocketServer as sw\ns=sw.SimpleWebSocketServer()\ns.run_forever()']:
            self.assertIsNotNone(evidence(source))

    def test_27_incomplete_and_fake(self):
        for source in ['WebSocketApp(url)\na.run_forever()', 'from websocket import WebSocketApp\na=WebSocketApp(url)', 'import socketio\ns=socketio.Server()', 'import socketio\ns.emit("x")', '"websockets.connect(url)"', 'class WebSocketResponse: pass\na=WebSocketResponse()\na.prepare(r)', '@app.websocket("/")\ndef handler():\n return 1']:
            self.assertIsNone(evidence(source))

    def test_28_scope_and_pairing(self):
        self.put('README.md', 'websocket support')
        for name in ['fixtures/a.py', 'examples/a.py', 'docs/a.py']:
            self.put(name, A)
        self.put('a.py', 'from websocket import WebSocketApp\na=WebSocketApp(url)')
        self.put('b.py', 'a.run_forever()')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'HIGH')
        self.put('test_link.py', A)
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'MEDIUM')
        self.put('link.py', '').unlink()
        (self.root / 'link.py').symlink_to(self.root / 'test_link.py')
        self.assertEqual(audit(self.root)['evidence'], [])

    def test_29_normalization(self):
        self.assertEqual(claims("doesn't use websockets"), (False, True))
        self.assertEqual(claims('WebSocket-\nsupport'), (True, False))
        self.assertEqual(claims('websocket\n\nsupport'), (False, False))
        self.assertEqual(claims('xwebsocket supportx'), (False, False))
        self.assertEqual(claims('tcp socket; webhook; streams results; real-time'), (False, False))

    def test_30_both_families(self):
        result = self.case('websocket support. No websockets.', severity='HIGH')
        self.assertEqual(result['claims'], {'positive': True, 'negative': True})
        self.put('docs/negative.md', 'no websockets')
        self.put('app.py', A)
        result = audit(self.root)
        self.assertEqual([f['rule'] for f in result['findings']], ['documented-no-websocket-claim-false'])


if __name__ == '__main__':
    unittest.main()
