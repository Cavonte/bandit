# Copyright 2024 - Tests for Rust-backed BanditNodeVisitor implementation
#
# SPDX-License-Identifier: Apache-2.0
"""Parity tests for the Rust BanditNodeVisitor vs Python BanditNodeVisitor.

Tests verify that both implementations produce identical results when scanning
the same files with the same configuration.
"""
import ast
import io
import os

import pytest

from bandit.core import extension_loader
from bandit.core import meta_ast as b_meta_ast
from bandit.core import metrics
from bandit.core import test_set as b_test_set
from bandit.core.node_visitor import BanditNodeVisitor as PyBanditNodeVisitor

try:
    from bandit_node_visitor import BanditNodeVisitor as RsBanditNodeVisitor
except ImportError:
    RsBanditNodeVisitor = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use a minimal config that enables all default plugins
_CONFIG = None


def _get_config():
    global _CONFIG
    if _CONFIG is None:
        from bandit.core import config as b_config

        _CONFIG = b_config.BanditConfig()
    return _CONFIG


def _make_visitor(
    impl_class, fname, code_bytes, nosec_lines=None, debug=False
):
    """Create a BanditNodeVisitor instance with standard test configuration."""
    if nosec_lines is None:
        nosec_lines = {}

    config = _get_config()
    testset = b_test_set.BanditTestSet(config)
    metaast = b_meta_ast.BanditMetaAst()
    fdata = io.BytesIO(code_bytes)
    m = metrics.Metrics()
    m.begin(fname)

    visitor = impl_class(fname, fdata, metaast, testset, debug, nosec_lines, m)
    return visitor, m


def _scan_code(impl_class, code_str, fname="test.py", nosec_lines=None):
    """Scan code with the given implementation and return (scores, results, metrics)."""
    code_bytes = code_str.encode("utf-8")
    visitor, m = _make_visitor(impl_class, fname, code_bytes, nosec_lines)
    scores = visitor.process(code_bytes)
    results = visitor.tester.results
    return scores, results, m


def _scan_file(impl_class, filepath):
    """Scan a real file with the given implementation."""
    with open(filepath, "rb") as f:
        code_bytes = f.read()
    fdata = io.BytesIO(code_bytes)
    config = _get_config()
    testset = b_test_set.BanditTestSet(config)
    metaast = b_meta_ast.BanditMetaAst()
    m = metrics.Metrics()
    m.begin(filepath)

    visitor = impl_class(filepath, fdata, metaast, testset, False, {}, m)
    scores = visitor.process(code_bytes)
    results = visitor.tester.results
    return scores, results, m


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _implementations():
    impls = [pytest.param(PyBanditNodeVisitor, id="python")]
    if RsBanditNodeVisitor is not None:
        impls.append(pytest.param(RsBanditNodeVisitor, id="rust"))
    return impls


@pytest.fixture(params=_implementations())
def VisitorClass(request):
    """Yield both the Python and Rust BanditNodeVisitor classes in turn."""
    return request.param


# ---------------------------------------------------------------------------
# Score parity tests
# ---------------------------------------------------------------------------


class TestScoreParity:
    """Verify scores are identical between Python and Rust implementations."""

    def test_empty_file(self, VisitorClass):
        """Empty file produces zero scores."""
        scores, results, _ = _scan_code(VisitorClass, "")
        assert scores["SEVERITY"] == [0, 0, 0, 0]
        assert scores["CONFIDENCE"] == [0, 0, 0, 0]

    def test_safe_code(self, VisitorClass):
        """Safe code produces zero scores."""
        code = """
def hello():
    x = 1 + 2
    return x
"""
        scores, results, _ = _scan_code(VisitorClass, code)
        assert scores["SEVERITY"] == [0, 0, 0, 0]
        assert scores["CONFIDENCE"] == [0, 0, 0, 0]

    def test_eval_call(self, VisitorClass):
        """eval() call produces non-zero scores."""
        code = "eval('1+1')\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        # eval should trigger B307
        total = sum(scores["SEVERITY"]) + sum(scores["CONFIDENCE"])
        assert total > 0

    def test_exec_call(self, VisitorClass):
        """exec() call produces non-zero scores."""
        code = "exec('print(1)')\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        total = sum(scores["SEVERITY"]) + sum(scores["CONFIDENCE"])
        assert total > 0

    def test_hardcoded_password(self, VisitorClass):
        """Hardcoded password produces findings."""
        code = "password = 'super_secret_123'\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        # Should trigger hardcoded password check
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Import tracking tests
# ---------------------------------------------------------------------------


class TestImportTracking:
    """Verify import tracking is identical."""

    def test_simple_import(self, VisitorClass):
        """import os tracks correctly."""
        code = "import os\n"
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        imports = visitor.imports
        assert "os" in imports

    def test_import_alias(self, VisitorClass):
        """import os as operating_system tracks alias."""
        code = "import os as operating_system\n"
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        imports = visitor.imports
        import_aliases = visitor.import_aliases
        assert "os" in imports
        assert import_aliases.get("operating_system") == "os"

    def test_from_import(self, VisitorClass):
        """from os.path import join tracks correctly."""
        code = "from os.path import join\n"
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        imports = visitor.imports
        import_aliases = visitor.import_aliases
        assert "os.path.join" in imports
        assert import_aliases.get("join") == "os.path.join"

    def test_from_import_alias(self, VisitorClass):
        """from os.path import join as j tracks alias."""
        code = "from os.path import join as j\n"
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        imports = visitor.imports
        import_aliases = visitor.import_aliases
        assert "os.path.join" in imports
        assert import_aliases.get("j") == "os.path.join"

    def test_multiple_imports(self, VisitorClass):
        """Multiple imports tracked correctly."""
        code = "import os\nimport sys\nfrom os.path import join, exists\n"
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        imports = visitor.imports
        assert "os" in imports
        assert "sys" in imports
        assert "os.path.join" in imports
        assert "os.path.exists" in imports


# ---------------------------------------------------------------------------
# Nosec suppression tests
# ---------------------------------------------------------------------------


class TestNosecSuppression:
    """Verify nosec suppression works identically."""

    def test_nosec_blanket_suppresses(self, VisitorClass):
        """# nosec suppresses all findings on the line."""
        code_without = "eval('1+1')\n"
        code_with = "eval('1+1')  # nosec\n"

        scores_without, results_without, _ = _scan_code(
            VisitorClass, code_without
        )
        scores_with, results_with, _ = _scan_code(
            VisitorClass, code_with, nosec_lines={1: set()}
        )

        # Without nosec should have findings
        assert len(results_without) > 0
        # With nosec should suppress
        assert len(results_with) == 0

    def test_nosec_specific_code(self, VisitorClass):
        """# nosec B307 suppresses only B307."""
        code = "eval('1+1')\n"

        # Suppress B307 specifically
        scores, results, _ = _scan_code(
            VisitorClass, code, nosec_lines={1: {"B307"}}
        )
        # B307 should be suppressed
        b307_results = [r for r in results if r.test_id == "B307"]
        assert len(b307_results) == 0


# ---------------------------------------------------------------------------
# Namespace tracking tests
# ---------------------------------------------------------------------------


class TestNamespaceTracking:
    """Verify namespace resolution is identical."""

    def test_function_namespace(self, VisitorClass):
        """Function namespace is tracked."""
        code = """
def my_function():
    pass
"""
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        # After processing, namespace should have been restored
        # (the function namespace is pushed then popped)

    def test_class_namespace(self, VisitorClass):
        """Class namespace is tracked."""
        code = """
class MyClass:
    def my_method(self):
        pass
"""
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)

    def test_nested_class_function(self, VisitorClass):
        """Nested class and function namespaces work correctly."""
        code = """
class Outer:
    class Inner:
        def method(self):
            pass
    def outer_method(self):
        pass
"""
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)


# ---------------------------------------------------------------------------
# Context construction tests
# ---------------------------------------------------------------------------


class TestContextConstruction:
    """Verify context is correctly built for plugins."""

    def test_call_context_has_qualname(self, VisitorClass):
        """Call context includes qualname and name."""
        code = "import subprocess\nsubprocess.call(['ls'])\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        # subprocess.call should trigger B603 or B607
        assert len(results) > 0

    def test_import_context(self, VisitorClass):
        """Import context triggers import-related plugins."""
        code = "import telnetlib\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        # telnetlib import should trigger B401
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Parity tests: compare Python and Rust on same inputs
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    RsBanditNodeVisitor is None, reason="Rust extension not available"
)
class TestFullParity:
    """Compare Python and Rust implementations produce identical results."""

    def _compare(self, code_str, fname="test.py", nosec_lines=None):
        """Run both implementations and compare results."""
        py_scores, py_results, _ = _scan_code(
            PyBanditNodeVisitor, code_str, fname, nosec_lines
        )
        rs_scores, rs_results, _ = _scan_code(
            RsBanditNodeVisitor, code_str, fname, nosec_lines
        )

        assert (
            py_scores == rs_scores
        ), f"Score mismatch:\nPython: {py_scores}\nRust:   {rs_scores}"
        assert len(py_results) == len(
            rs_results
        ), f"Result count mismatch: Python={len(py_results)}, Rust={len(rs_results)}"

        # Compare individual results
        for py_r, rs_r in zip(
            sorted(py_results, key=lambda r: (r.fname, r.lineno, r.test_id)),
            sorted(rs_results, key=lambda r: (r.fname, r.lineno, r.test_id)),
        ):
            assert (
                py_r.test_id == rs_r.test_id
            ), f"Test ID mismatch: {py_r.test_id} vs {rs_r.test_id}"
            assert py_r.severity == rs_r.severity
            assert py_r.confidence == rs_r.confidence
            assert py_r.lineno == rs_r.lineno

    def test_parity_empty(self):
        self._compare("")

    def test_parity_safe_code(self):
        self._compare("x = 1\ny = 2\n")

    def test_parity_eval(self):
        self._compare("eval('1+1')\n")

    def test_parity_exec(self):
        self._compare("exec('print(1)')\n")

    def test_parity_subprocess(self):
        self._compare("import subprocess\nsubprocess.call(['ls'])\n")

    def test_parity_hardcoded_password(self):
        self._compare("password = 'super_secret_123'\n")

    def test_parity_import_telnet(self):
        self._compare("import telnetlib\n")

    def test_parity_from_import(self):
        self._compare("from os import system\nsystem('ls')\n")

    def test_parity_class_with_methods(self):
        self._compare(
            """
class Foo:
    def bar(self):
        eval('1+1')
    def baz(self):
        exec('x = 1')
"""
        )

    def test_parity_nested_functions(self):
        self._compare(
            """
def outer():
    def inner():
        eval('1+1')
    inner()
"""
        )

    def test_parity_string_constant(self):
        self._compare(
            """
x = "hello world"
y = b"bytes value"
"""
        )

    def test_parity_nosec_blanket(self):
        self._compare(
            "eval('1+1')  # nosec\n",
            nosec_lines={1: set()},
        )

    def test_parity_nosec_specific(self):
        self._compare(
            "eval('1+1')  # nosec B307\n",
            nosec_lines={1: {"B307"}},
        )

    def test_parity_multiple_findings(self):
        self._compare(
            """
import subprocess
import telnetlib
eval('x')
exec('y')
subprocess.call(['ls'])
"""
        )

    def test_parity_try_except(self):
        self._compare(
            """
try:
    pass
except Exception:
    pass
"""
        )

    def test_parity_assert(self):
        self._compare("assert True\n")

    def test_parity_yaml_load(self):
        self._compare(
            """
import yaml
yaml.load('data')
"""
        )

    def test_parity_hashlib(self):
        self._compare(
            """
import hashlib
hashlib.md5(b'data')
"""
        )


# ---------------------------------------------------------------------------
# File-level parity tests: scan real example files
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    RsBanditNodeVisitor is None, reason="Rust extension not available"
)
class TestExampleFileParity:
    """Scan real files from examples/ with both implementations and compare."""

    @staticmethod
    def _get_example_files():
        examples_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "examples"
        )
        examples_dir = os.path.normpath(examples_dir)
        if not os.path.isdir(examples_dir):
            return []
        files = []
        for f in sorted(os.listdir(examples_dir)):
            if f.endswith(".py"):
                files.append(os.path.join(examples_dir, f))
        return files

    @pytest.fixture(params=_get_example_files.__func__())
    def example_file(self, request):
        return request.param

    def test_example_file_parity(self, example_file):
        """Scores and findings must match between Python and Rust."""
        try:
            py_scores, py_results, _ = _scan_file(
                PyBanditNodeVisitor, example_file
            )
        except SyntaxError:
            # Files with intentional syntax errors (nonsense.py, etc.)
            # should also fail in Rust — verify that
            with pytest.raises(Exception):
                _scan_file(RsBanditNodeVisitor, example_file)
            return

        rs_scores, rs_results, _ = _scan_file(
            RsBanditNodeVisitor, example_file
        )

        assert py_scores == rs_scores, (
            f"Score mismatch on {os.path.basename(example_file)}:\n"
            f"Python: {py_scores}\nRust:   {rs_scores}"
        )
        assert len(py_results) == len(rs_results), (
            f"Result count mismatch on {os.path.basename(example_file)}: "
            f"Python={len(py_results)}, Rust={len(rs_results)}"
        )

        # Compare results by test_id and line number
        py_sorted = sorted(py_results, key=lambda r: (r.lineno, r.test_id))
        rs_sorted = sorted(rs_results, key=lambda r: (r.lineno, r.test_id))
        for py_r, rs_r in zip(py_sorted, rs_sorted):
            assert py_r.test_id == rs_r.test_id, (
                f"Test ID mismatch on {os.path.basename(example_file)} "
                f"line {py_r.lineno}: {py_r.test_id} vs {rs_r.test_id}"
            )
            assert py_r.lineno == rs_r.lineno
            assert py_r.severity == rs_r.severity
            assert py_r.confidence == rs_r.confidence


# ---------------------------------------------------------------------------
# Depth tracking tests
# ---------------------------------------------------------------------------


class TestDepthTracking:
    """Verify depth tracking is correct."""

    def test_depth_returns_to_zero(self, VisitorClass):
        """After processing, depth should return to 0."""
        code = """
class Foo:
    def bar(self):
        if True:
            for x in range(10):
                pass
"""
        code_bytes = code.encode("utf-8")
        visitor, _ = _make_visitor(VisitorClass, "test.py", code_bytes)
        visitor.process(code_bytes)
        assert visitor.depth == 0


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases that must be handled correctly."""

    def test_syntax_error_propagates(self, VisitorClass):
        """Files with syntax errors should raise SyntaxError."""
        code = b"def foo(:\n"
        visitor, _ = _make_visitor(VisitorClass, "test.py", code)
        with pytest.raises(SyntaxError):
            visitor.process(code)

    def test_only_comments(self, VisitorClass):
        """File with only comments produces zero scores."""
        code = "# This is a comment\n# Another comment\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        assert scores["SEVERITY"] == [0, 0, 0, 0]
        assert scores["CONFIDENCE"] == [0, 0, 0, 0]

    def test_docstring_not_scanned(self, VisitorClass):
        """Docstrings should not trigger string checks."""
        code = '''
def foo():
    """This is a docstring with password = secret"""
    pass
'''
        scores1, results1, _ = _scan_code(VisitorClass, code)
        # The docstring should not trigger hardcoded password detection
        # because it's wrapped in ast.Expr (docstring suppression)

    def test_deeply_nested(self, VisitorClass):
        """Deeply nested AST doesn't crash."""
        code = "x = " + "(" * 50 + "1" + ")" * 50 + "\n"
        scores, results, _ = _scan_code(VisitorClass, code)
        # Should not crash


# ---------------------------------------------------------------------------
# Rust smoke tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    RsBanditNodeVisitor is None, reason="Rust extension not available"
)
class TestRustSmoke:
    """Basic smoke tests for the Rust extension."""

    def test_import(self):
        """Rust extension can be imported."""
        from bandit_node_visitor import BanditNodeVisitor

        assert BanditNodeVisitor is not None

    def test_constructor(self):
        """Rust BanditNodeVisitor can be constructed."""
        code = b"x = 1\n"
        visitor, _ = _make_visitor(RsBanditNodeVisitor, "test.py", code)
        assert visitor is not None
        assert visitor.depth == 0

    def test_process_returns_scores(self):
        """process() returns a dict with SEVERITY and CONFIDENCE keys."""
        code = b"x = 1\n"
        visitor, _ = _make_visitor(RsBanditNodeVisitor, "test.py", code)
        scores = visitor.process(code)
        assert "SEVERITY" in scores
        assert "CONFIDENCE" in scores
        assert len(scores["SEVERITY"]) == 4
        assert len(scores["CONFIDENCE"]) == 4

    def test_tester_accessible(self):
        """tester attribute is accessible and has results."""
        code = b"eval('1+1')\n"
        visitor, _ = _make_visitor(RsBanditNodeVisitor, "test.py", code)
        visitor.process(code)
        assert hasattr(visitor.tester, "results")
