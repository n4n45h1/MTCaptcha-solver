"""Offline regression checks; no CAPTCHA provider calls or API credentials."""
import ast
import math
import os
import subprocess
import types
import unittest
from pathlib import Path

SOURCE = Path("MTCaptcha.py").read_text(encoding="utf-8")
BASE_SHA = "7084b6c44c7df0b2f6afa62a77f42bda8753cdbd"


def extract_core(source):
    """Load only the pure transformation functions, never the network client."""
    tree = ast.parse(source)
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "FoldChlg":
            nodes.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in (
            "int32", "transactionSignature"
        ):
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id.startswith("_URLSAFE_B64")
            for t in node.targets
        ):
            nodes.append(node)
    namespace = {"math": math}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<core>", "exec"), namespace)
    return namespace


class OfflineRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = subprocess.check_output(
            ["git", "show", f"{BASE_SHA}:MTCaptcha.py"], text=True
        )
        cls.before = extract_core(baseline)
        cls.after = extract_core(SOURCE)

    def test_int32_compatibility(self):
        for value in (-2**65, -2**32, -2**31, -1, 0, 1, 2**31, 2**32, 2**65):
            with self.subTest(value=value):
                self.assertEqual(self.before["int32"](value), self.after["int32"](value))

    def test_base64_mapping_compatibility(self):
        old = self.before["FoldChlg"]()
        new = self.after["FoldChlg"]()
        # Character mappings are defined on ASCII input.
        for number in range(0, 256):
            char = chr(number)
            with self.subTest(char=number):
                self.assertEqual(old.URLSafeBase64CharToInt(char), new.URLSafeBase64CharToInt(char))
                self.assertEqual(old.URLSafeBase64IntToChar(number), new.URLSafeBase64IntToChar(number))

    def test_fold_outputs_compatible(self):
        old = self.before["FoldChlg"]()
        new = self.after["FoldChlg"]()
        for seed in ("0123456789", "Az-_09", "A", "____", "abcde"):
            for slots in (0, 1, 3, 5):
                for depth in (0, 1, 7, 31):
                    with self.subTest(seed=seed, slots=slots, depth=depth):
                        self.assertEqual(old.solve(seed, slots, depth), new.solve(seed, slots, depth))

    @unittest.skipUnless(os.environ.get("GITHUB_EVENT_NAME") == "pull_request",
                         "PR-specific behavior check")
    def test_pr_handles_network_error_without_network(self):
        tree = ast.parse(SOURCE)
        target = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "solve")
        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.proxies = {}
            def get(self, *_args, **_kwargs):
                raise OSError("simulated offline connection failure")

        fake_globals = {
            "Options": types.SimpleNamespace,
            "VersionRange": lambda *_args: None,
            "curl_cffi": types.SimpleNamespace(Session=lambda **_kw: FakeSession()),
            "ua_generator": types.SimpleNamespace(generate=lambda **_kw: types.SimpleNamespace(text="test")),
            "uuid": types.SimpleNamespace(uuid4=lambda: "test-id"),
        }
        exec(compile(ast.Module(body=[target], type_ignores=[]), "<solve>", "exec"), fake_globals)
        self.assertEqual(fake_globals["solve"]("test-key", "https://example.org/"), "Failed")

    @unittest.skipUnless(os.environ.get("GITHUB_EVENT_NAME") == "pull_request",
                         "PR-specific behavior check")
    def test_pr_uses_millisecond_timestamps(self):
        tree = ast.parse(SOURCE)
        target = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "solve")
        timestamps = []
        for node in ast.walk(target):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "rt":
                    timestamps.append(value)
        self.assertEqual(len(timestamps), 2)
        for expression in timestamps:
            self.assertTrue(
                any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult)
                    and isinstance(n.right, ast.Constant) and n.right.value == 1000
                    for n in ast.walk(expression)),
                "rt must use time.time() * 1000 for milliseconds",
            )


if __name__ == "__main__":
    unittest.main()
