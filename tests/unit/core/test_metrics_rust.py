# Copyright 2024 - Tests for Rust-backed Metrics implementation
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Rust-backed bandit_metrics.Metrics class.

Every scenario from docs/metrics_analysis.md §12 Acceptance Criteria is covered.
A parametrized parity test runs each scenario against both the Python and Rust
implementations and asserts identical output.
"""
import pytest

from bandit.core.metrics import Metrics as PyMetrics

try:
    from bandit_metrics import Metrics as RsMetrics
except ImportError:
    RsMetrics = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ISSUE_COUNT_KEYS = [
    "SEVERITY.UNDEFINED",
    "SEVERITY.LOW",
    "SEVERITY.MEDIUM",
    "SEVERITY.HIGH",
    "CONFIDENCE.UNDEFINED",
    "CONFIDENCE.LOW",
    "CONFIDENCE.MEDIUM",
    "CONFIDENCE.HIGH",
]

ALL_TOTALS_KEYS = ["loc", "nosec", "skipped_tests"] + ISSUE_COUNT_KEYS


def _make_metrics(impl_class):
    """Instantiate the given Metrics class."""
    return impl_class()


# ---------------------------------------------------------------------------
# Fixtures: parametrize over both implementations
# ---------------------------------------------------------------------------


def _implementations():
    impls = [pytest.param(PyMetrics, id="python")]
    if RsMetrics is not None:
        impls.append(pytest.param(RsMetrics, id="rust"))
    return impls


@pytest.fixture(params=_implementations())
def MetricsClass(request):
    """Yield both the Python and Rust Metrics classes in turn."""
    return request.param


# ---------------------------------------------------------------------------
# §12.1 Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    """AC-INIT-1, AC-INIT-2, AC-INIT-3."""

    def test_ac_init_1_totals_has_11_keys_all_zero(self, MetricsClass):
        """AC-INIT-1: _totals has exactly 11 keys, all zero."""
        m = _make_metrics(MetricsClass)
        totals = m.data["_totals"]
        for key in ALL_TOTALS_KEYS:
            assert key in totals, f"Missing key: {key}"
            assert totals[key] == 0, f"{key} should be 0, got {totals[key]}"
        assert len(totals) == 11

    def test_ac_init_2_data_has_only_totals(self, MetricsClass):
        """AC-INIT-2: data contains exactly one key ('_totals')."""
        m = _make_metrics(MetricsClass)
        assert list(m.data.keys()) == ["_totals"]

    def test_ac_init_3_no_current_before_begin(self, MetricsClass):
        """AC-INIT-3: note_nosec / count_locs before begin() must raise."""
        m = _make_metrics(MetricsClass)
        with pytest.raises((AttributeError, Exception)):
            m.note_nosec()
        m2 = _make_metrics(MetricsClass)
        with pytest.raises((AttributeError, Exception)):
            m2.count_locs([b"x"])

    def test_ac_init_4_count_issues_empty_before_begin(self, MetricsClass):
        """AC-INIT-4: count_issues([]) before begin() must raise, even with empty scores."""
        m = _make_metrics(MetricsClass)
        with pytest.raises((AttributeError, Exception)):
            m.count_issues([])


# ---------------------------------------------------------------------------
# §12.2 Per-file lifecycle
# ---------------------------------------------------------------------------


class TestPerFileLifecycle:
    """AC-BEGIN-1 through AC-ISSUES-2."""

    def test_ac_begin_1_creates_per_file_entry(self, MetricsClass):
        """AC-BEGIN-1: begin('foo.py') creates entry with loc/nosec/skipped_tests only."""
        m = _make_metrics(MetricsClass)
        m.begin("foo.py")
        entry = m.data["foo.py"]
        assert entry["loc"] == 0
        assert entry["nosec"] == 0
        assert entry["skipped_tests"] == 0
        # Must NOT contain issue-count keys yet
        for key in ISSUE_COUNT_KEYS:
            assert (
                key not in entry
            ), f"{key} should not be present before count_issues"

    def test_ac_begin_2_mutations_affect_current_file(self, MetricsClass):
        """AC-BEGIN-2: mutations after begin affect the correct file."""
        m = _make_metrics(MetricsClass)
        m.begin("foo.py")
        m.note_nosec()
        m.note_skipped_test()
        m.count_locs([b"code line"])
        assert m.data["foo.py"]["nosec"] == 1
        assert m.data["foo.py"]["skipped_tests"] == 1
        assert m.data["foo.py"]["loc"] == 1
        # _totals must not have been affected by per-file mutations
        assert m.data["_totals"]["nosec"] == 0

    def test_ac_begin_3_switches_active_file(self, MetricsClass):
        """AC-BEGIN-3: begin('bar.py') switches active file."""
        m = _make_metrics(MetricsClass)
        m.begin("foo.py")
        m.note_nosec()
        m.begin("bar.py")
        m.note_nosec()
        m.note_nosec()
        assert m.data["foo.py"]["nosec"] == 1
        assert m.data["bar.py"]["nosec"] == 2

    def test_ac_loc_1_counts_non_blank_non_comment(self, MetricsClass):
        """AC-LOC-1: count_locs with mixed lines counts correctly."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        lines = [b"code", b"  ", b"# comment", b"  # comment", b"", b"more"]
        m.count_locs(lines)
        assert m.data["test.py"]["loc"] == 2

    def test_ac_loc_2_empty_lines_list(self, MetricsClass):
        """AC-LOC-2: count_locs([]) adds 0."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([])
        assert m.data["test.py"]["loc"] == 0

    def test_ac_loc_3_whitespace_only_not_counted(self, MetricsClass):
        """AC-LOC-3: lines with only whitespace don't count."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([b"   ", b"\t", b"  \t  ", b"\n"])
        assert m.data["test.py"]["loc"] == 0

    def test_ac_loc_4_comment_lines_not_counted(self, MetricsClass):
        """AC-LOC-4: lines starting with # after strip don't count."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([b"# comment", b"  # indented comment", b"\t# tabbed"])
        assert m.data["test.py"]["loc"] == 0

    def test_ac_nosec_1_increments_by_one(self, MetricsClass):
        """AC-NOSEC-1: note_nosec() increments by 1."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.note_nosec()
        m.note_nosec()
        m.note_nosec()
        assert m.data["test.py"]["nosec"] == 3

    def test_ac_nosec_2_increments_by_n(self, MetricsClass):
        """AC-NOSEC-2: note_nosec(5) increments by 5."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.note_nosec(5)
        assert m.data["test.py"]["nosec"] == 5

    def test_ac_skip_1_increments_by_one(self, MetricsClass):
        """AC-SKIP-1: note_skipped_test() increments by 1."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.note_skipped_test()
        m.note_skipped_test()
        assert m.data["test.py"]["skipped_tests"] == 2

    def test_ac_skip_2_increments_by_n(self, MetricsClass):
        """AC-SKIP-2: note_skipped_test(3) increments by 3."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.note_skipped_test(3)
        assert m.data["test.py"]["skipped_tests"] == 3

    def test_ac_issues_1_weighted_score_division(self, MetricsClass):
        """AC-ISSUES-1: count_issues with weighted scores produces correct counts."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        scores = [{"SEVERITY": [0, 3, 5, 10], "CONFIDENCE": [1, 0, 0, 0]}]
        m.count_issues(scores)
        entry = m.data["test.py"]
        # RANKING_VALUES: UNDEFINED=1, LOW=3, MEDIUM=5, HIGH=10
        assert entry["SEVERITY.UNDEFINED"] == 0  # 0 // 1
        assert entry["SEVERITY.LOW"] == 1  # 3 // 3
        assert entry["SEVERITY.MEDIUM"] == 1  # 5 // 5
        assert entry["SEVERITY.HIGH"] == 1  # 10 // 10
        assert entry["CONFIDENCE.UNDEFINED"] == 1  # 1 // 1
        assert entry["CONFIDENCE.LOW"] == 0  # 0 // 3
        assert entry["CONFIDENCE.MEDIUM"] == 0  # 0 // 5
        assert entry["CONFIDENCE.HIGH"] == 0  # 0 // 10

    def test_ac_issues_2_empty_scores_noop(self, MetricsClass):
        """AC-ISSUES-2: count_issues([]) is a no-op."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_issues([])
        entry = m.data["test.py"]
        # Should only have loc, nosec, skipped_tests — no issue-count keys
        for key in ISSUE_COUNT_KEYS:
            assert key not in entry


# ---------------------------------------------------------------------------
# §12.3 Aggregation
# ---------------------------------------------------------------------------


class TestAggregation:
    """AC-AGG-1 through AC-AGG-4."""

    def test_ac_agg_1_sums_per_file_entries(self, MetricsClass):
        """AC-AGG-1: aggregate sums all per-file entries into _totals."""
        m = _make_metrics(MetricsClass)
        m.begin("a.py")
        m.count_locs([b"line1", b"line2"])
        m.note_nosec(2)
        m.count_issues(
            [{"SEVERITY": [0, 3, 0, 0], "CONFIDENCE": [0, 0, 5, 0]}]
        )

        m.begin("b.py")
        m.count_locs([b"line1", b"line2", b"line3"])
        m.note_nosec(1)
        m.count_issues(
            [{"SEVERITY": [0, 6, 0, 0], "CONFIDENCE": [0, 0, 0, 10]}]
        )

        m.aggregate()
        totals = m.data["_totals"]
        assert totals["loc"] == 5  # 2 + 3
        assert totals["nosec"] == 3  # 2 + 1
        assert totals["SEVERITY.LOW"] == 3  # 1 + 2 (3//3 + 6//3)
        assert totals["CONFIDENCE.MEDIUM"] == 1  # 5//5 + 0
        assert totals["CONFIDENCE.HIGH"] == 1  # 0 + 10//10

    def test_ac_agg_2_totals_contains_all_keys(self, MetricsClass):
        """AC-AGG-2: after aggregate, _totals has all keys from any entry."""
        m = _make_metrics(MetricsClass)
        m.begin("a.py")
        m.count_locs([b"x"])
        m.count_issues(
            [{"SEVERITY": [0, 0, 0, 0], "CONFIDENCE": [0, 0, 0, 0]}]
        )
        m.aggregate()
        totals = m.data["_totals"]
        for key in ALL_TOTALS_KEYS:
            assert key in totals

    def test_ac_agg_3_no_files_scanned(self, MetricsClass):
        """AC-AGG-3: aggregate with no files leaves _totals all zeros."""
        m = _make_metrics(MetricsClass)
        m.aggregate()
        totals = m.data["_totals"]
        for key in ALL_TOTALS_KEYS:
            assert totals[key] == 0

    def test_ac_agg_4_double_aggregate_doubles(self, MetricsClass):
        """AC-AGG-4: calling aggregate twice doubles totals (matching Python bug)."""
        m = _make_metrics(MetricsClass)
        m.begin("a.py")
        m.count_locs([b"x", b"y"])
        m.note_nosec(1)
        m.count_issues(
            [{"SEVERITY": [0, 3, 0, 0], "CONFIDENCE": [0, 0, 0, 0]}]
        )
        m.aggregate()
        first_loc = m.data["_totals"]["loc"]
        first_nosec = m.data["_totals"]["nosec"]
        first_sev_low = m.data["_totals"]["SEVERITY.LOW"]
        m.aggregate()
        # Second aggregate includes old _totals, so values double
        assert m.data["_totals"]["loc"] == first_loc * 2
        assert m.data["_totals"]["nosec"] == first_nosec * 2
        assert m.data["_totals"]["SEVERITY.LOW"] == first_sev_low * 2


# ---------------------------------------------------------------------------
# §12.4 Serialisation compatibility
# ---------------------------------------------------------------------------


class TestSerialisation:
    """AC-SER-1 through AC-SER-3."""

    def test_ac_ser_1_key_format(self, MetricsClass):
        """AC-SER-1: data keys match expected format."""
        m = _make_metrics(MetricsClass)
        m.begin("example.py")
        m.count_locs([b"code"])
        m.count_issues(
            [{"SEVERITY": [0, 0, 0, 10], "CONFIDENCE": [1, 0, 0, 0]}]
        )
        m.aggregate()

        assert "_totals" in m.data
        assert "example.py" in m.data
        totals = m.data["_totals"]
        for key in ALL_TOTALS_KEYS:
            assert key in totals

    def test_ac_ser_2_values_are_integers(self, MetricsClass):
        """AC-SER-2: all values are non-negative integers."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([b"code"])
        m.note_nosec(2)
        m.count_issues(
            [{"SEVERITY": [0, 3, 5, 10], "CONFIDENCE": [1, 0, 0, 0]}]
        )
        m.aggregate()

        for fname, entry in m.data.items():
            for key, value in entry.items():
                assert isinstance(
                    value, int
                ), f"{fname}.{key} is {type(value)}, expected int"
                assert value >= 0, f"{fname}.{key} is negative: {value}"

    def test_ac_ser_3_no_issue_keys_without_count_issues(self, MetricsClass):
        """AC-SER-3: per-file entries without count_issues have only 3 keys."""
        m = _make_metrics(MetricsClass)
        m.begin("partial.py")
        m.count_locs([b"code"])
        # Intentionally do NOT call count_issues
        entry = m.data["partial.py"]
        assert set(entry.keys()) == {"loc", "nosec", "skipped_tests"}


# ---------------------------------------------------------------------------
# §12.5 Formatter consumption
# ---------------------------------------------------------------------------


class TestFormatterConsumption:
    """AC-FMT-1 and AC-FMT-2."""

    def test_ac_fmt_1_totals_read_paths(self, MetricsClass):
        """AC-FMT-1: all read paths on _totals work correctly."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([b"a", b"b"])
        m.note_nosec(3)
        m.note_skipped_test(1)
        m.count_issues(
            [{"SEVERITY": [0, 0, 0, 10], "CONFIDENCE": [0, 0, 5, 0]}]
        )
        m.aggregate()

        totals = m.data["_totals"]
        assert isinstance(totals["loc"], int)
        assert isinstance(totals["nosec"], int)
        assert isinstance(totals["skipped_tests"], int)
        for rank in ["UNDEFINED", "LOW", "MEDIUM", "HIGH"]:
            assert isinstance(totals[f"SEVERITY.{rank}"], int)
            assert isinstance(totals[f"CONFIDENCE.{rank}"], int)

    def test_ac_fmt_2_data_is_dict_of_dicts(self, MetricsClass):
        """AC-FMT-2: data is consumable as flat dict of dicts."""
        m = _make_metrics(MetricsClass)
        m.begin("a.py")
        m.count_locs([b"x"])
        m.count_issues(
            [{"SEVERITY": [0, 0, 0, 0], "CONFIDENCE": [0, 0, 0, 0]}]
        )
        m.aggregate()

        # Must be iterable as dict of dicts
        for fname, entry in m.data.items():
            assert isinstance(fname, str)
            assert isinstance(entry, dict)
            for k, v in entry.items():
                assert isinstance(k, str)
                assert isinstance(v, int)


# ---------------------------------------------------------------------------
# §12.6 Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """AC-EDGE-1 through AC-EDGE-3."""

    def test_ac_edge_1_nosec_can_exceed_loc(self, MetricsClass):
        """AC-EDGE-1: nosec > loc is allowed."""
        m = _make_metrics(MetricsClass)
        m.begin("test.py")
        m.count_locs([b"# only a comment"])  # loc stays 0
        m.note_nosec(5)
        assert m.data["test.py"]["nosec"] == 5
        assert m.data["test.py"]["loc"] == 0

    def test_ac_edge_2_begin_same_file_twice_overwrites(self, MetricsClass):
        """AC-EDGE-2: begin() with same filename overwrites previous entry."""
        m = _make_metrics(MetricsClass)
        m.begin("dup.py")
        m.count_locs([b"a", b"b", b"c"])
        m.note_nosec(10)
        assert m.data["dup.py"]["loc"] == 3
        assert m.data["dup.py"]["nosec"] == 10

        m.begin("dup.py")  # overwrite
        assert m.data["dup.py"]["loc"] == 0
        assert m.data["dup.py"]["nosec"] == 0

    def test_ac_edge_3_aggregate_without_count_issues(self, MetricsClass):
        """AC-EDGE-3: aggregate includes files where count_issues was never called."""
        m = _make_metrics(MetricsClass)
        m.begin("partial.py")
        m.count_locs([b"a", b"b"])
        m.note_nosec(1)
        m.note_skipped_test(2)
        # No count_issues call
        m.aggregate()
        totals = m.data["_totals"]
        assert totals["loc"] == 2
        assert totals["nosec"] == 1
        assert totals["skipped_tests"] == 2


# ---------------------------------------------------------------------------
# §12.6a Additional edge-case tests requested by review
# ---------------------------------------------------------------------------


class TestAdditionalEdgeCases:
    """Tests added to address review comments: multi-score bug, non-ASCII,
    negative num, and large file stress test."""

    def test_multi_score_only_first_values_recorded(self, MetricsClass):
        """Multi-score bug: only the first score's values are recorded per label.

        The Python implementation has a latent bug where accumulation is inside
        the ``if label not in issue_counts`` guard, so subsequent scores are
        silently discarded. The Rust implementation must replicate this.
        """
        m = _make_metrics(MetricsClass)
        m.begin("multi.py")
        score1 = {"SEVERITY": [1, 3, 5, 10], "CONFIDENCE": [1, 0, 0, 0]}
        score2 = {"SEVERITY": [0, 0, 0, 100], "CONFIDENCE": [0, 0, 0, 100]}
        m.count_issues([score1, score2])
        entry = m.data["multi.py"]
        # score2's values must be discarded — only score1 counts
        assert entry["SEVERITY.UNDEFINED"] == 1  # 1 // 1
        assert entry["SEVERITY.LOW"] == 1  # 3 // 3
        assert entry["SEVERITY.MEDIUM"] == 1  # 5 // 5
        assert entry["SEVERITY.HIGH"] == 1  # 10 // 10
        assert entry["CONFIDENCE.UNDEFINED"] == 1  # 1 // 1
        assert entry["CONFIDENCE.LOW"] == 0  # 0 // 3
        assert entry["CONFIDENCE.MEDIUM"] == 0  # 0 // 5
        assert entry["CONFIDENCE.HIGH"] == 0  # 0 // 10

    def test_non_ascii_bytes_in_count_locs(self, MetricsClass):
        """Non-ASCII bytes: count_locs handles UTF-8 BOM and non-ASCII content."""
        m = _make_metrics(MetricsClass)
        m.begin("utf8.py")
        lines = [
            b"\xef\xbb\xbfimport os",  # UTF-8 BOM + code
            b"x = '\xc3\xa9'",  # UTF-8 accented char
            b"\xc0\xc1",  # invalid UTF-8 but non-empty, non-comment
            b"# \xe2\x80\x93 comment",  # comment with en-dash
            b"  ",  # whitespace only
        ]
        m.count_locs(lines)
        # BOM line, x= line, and invalid-UTF8 line all count as code (3)
        # comment line and whitespace line don't count
        assert m.data["utf8.py"]["loc"] == 3

    def test_negative_num_note_nosec(self, MetricsClass):
        """Negative num argument: note_nosec(-1) decrements the counter."""
        m = _make_metrics(MetricsClass)
        m.begin("neg.py")
        m.note_nosec(5)
        m.note_nosec(-2)
        # Python allows negative increments — Rust must match
        assert m.data["neg.py"]["nosec"] == 3

    def test_negative_num_note_skipped_test(self, MetricsClass):
        """Negative num argument: note_skipped_test(-1) decrements the counter."""
        m = _make_metrics(MetricsClass)
        m.begin("neg.py")
        m.note_skipped_test(5)
        m.note_skipped_test(-3)
        assert m.data["neg.py"]["skipped_tests"] == 2

    def test_large_file_stress(self, MetricsClass):
        """Large file stress test: 10K+ lines processed correctly."""
        m = _make_metrics(MetricsClass)
        m.begin("large.py")
        # Generate 10,000 lines: mix of code, comments, blank
        lines = []
        expected_loc = 0
        for i in range(10_000):
            if i % 5 == 0:
                lines.append(b"# comment line")
            elif i % 7 == 0:
                lines.append(b"   ")
            elif i % 11 == 0:
                lines.append(b"")
            else:
                lines.append(f"x_{i} = {i}".encode())
                expected_loc += 1
        m.count_locs(lines)
        assert m.data["large.py"]["loc"] == expected_loc
        # Verify it's a reasonable number (should be ~6000+)
        assert expected_loc > 6000


# ---------------------------------------------------------------------------
# §12.7 Parity tests: Python vs Rust produce identical output
# ---------------------------------------------------------------------------


@pytest.mark.skipif(RsMetrics is None, reason="Rust extension not installed")
class TestParity:
    """AC-COMPAT-1, AC-COMPAT-2: Rust and Python produce identical data."""

    @staticmethod
    def _run_scenario(impl_class):
        """Run a representative pipeline and return the data dict."""
        m = impl_class()
        # File A: some code, some nosecs, some issues
        m.begin("a.py")
        m.count_locs([b"import os", b"", b"# comment", b"x = 1", b"  "])
        m.note_nosec(2)
        m.note_skipped_test(1)
        m.count_issues(
            [
                {
                    "SEVERITY": [0, 3, 5, 10],
                    "CONFIDENCE": [1, 0, 0, 0],
                }
            ]
        )

        # File B: empty file
        m.begin("b.py")
        m.count_locs([])
        m.count_issues(
            [
                {
                    "SEVERITY": [0, 0, 0, 0],
                    "CONFIDENCE": [0, 0, 0, 0],
                }
            ]
        )

        # File C: only code, no issues (simulates SyntaxError path)
        m.begin("c.py")
        m.count_locs([b"pass"])
        # No count_issues

        m.aggregate()
        return m.data

    def test_ac_compat_1_identical_totals(self):
        """AC-COMPAT-1: Rust and Python produce identical _totals."""
        py_data = self._run_scenario(PyMetrics)
        rs_data = self._run_scenario(RsMetrics)

        py_totals = py_data["_totals"]
        rs_totals = rs_data["_totals"]

        # Check all keys match
        assert set(py_totals.keys()) == set(
            rs_totals.keys()
        ), f"Key mismatch: py={set(py_totals.keys())}, rs={set(rs_totals.keys())}"
        for key in py_totals:
            assert (
                py_totals[key] == rs_totals[key]
            ), f"_totals['{key}']: py={py_totals[key]}, rs={rs_totals[key]}"

    def test_ac_compat_2_identical_per_file_entries(self):
        """AC-COMPAT-2: Rust and Python produce identical per-file entries."""
        py_data = self._run_scenario(PyMetrics)
        rs_data = self._run_scenario(RsMetrics)

        assert set(py_data.keys()) == set(
            rs_data.keys()
        ), f"Top-level key mismatch: py={set(py_data.keys())}, rs={set(rs_data.keys())}"

        for fname in py_data:
            py_entry = py_data[fname]
            rs_entry = rs_data[fname]
            assert set(py_entry.keys()) == set(rs_entry.keys()), (
                f"Key mismatch for '{fname}': "
                f"py={set(py_entry.keys())}, rs={set(rs_entry.keys())}"
            )
            for key in py_entry:
                assert (
                    py_entry[key] == rs_entry[key]
                ), f"'{fname}'['{key}']: py={py_entry[key]}, rs={rs_entry[key]}"

    def test_parity_construction(self):
        """Parity: both implementations produce identical initial state."""
        py = PyMetrics()
        rs = RsMetrics()
        assert dict(py.data["_totals"]) == dict(rs.data["_totals"])
        assert list(py.data.keys()) == list(rs.data.keys())

    def test_parity_begin_and_mutations(self):
        """Parity: begin + mutations produce identical state."""
        py = PyMetrics()
        py.begin("x.py")
        py.note_nosec(3)
        py.note_skipped_test(2)
        py.count_locs([b"a", b"  ", b"# c", b"d"])

        rs = RsMetrics()
        rs.begin("x.py")
        rs.note_nosec(3)
        rs.note_skipped_test(2)
        rs.count_locs([b"a", b"  ", b"# c", b"d"])

        assert dict(py.data["x.py"]) == dict(rs.data["x.py"])

    def test_parity_count_issues(self):
        """Parity: count_issues produces identical results."""
        scores = [{"SEVERITY": [1, 6, 10, 20], "CONFIDENCE": [2, 3, 0, 0]}]
        py = PyMetrics()
        py.begin("t.py")
        py.count_issues(scores)

        rs = RsMetrics()
        rs.begin("t.py")
        rs.count_issues(scores)

        assert dict(py.data["t.py"]) == dict(rs.data["t.py"])

    def test_parity_aggregate_no_files(self):
        """Parity: aggregate with no files."""
        py = PyMetrics()
        py.aggregate()
        rs = RsMetrics()
        rs.aggregate()
        assert dict(py.data["_totals"]) == dict(rs.data["_totals"])

    def test_parity_edge_begin_same_file_twice(self):
        """Parity: begin same file twice produces identical results."""
        py = PyMetrics()
        py.begin("dup.py")
        py.count_locs([b"a", b"b"])
        py.note_nosec(5)
        py.begin("dup.py")
        py.count_locs([b"c"])
        py.aggregate()

        rs = RsMetrics()
        rs.begin("dup.py")
        rs.count_locs([b"a", b"b"])
        rs.note_nosec(5)
        rs.begin("dup.py")
        rs.count_locs([b"c"])
        rs.aggregate()

        assert dict(py.data["_totals"]) == dict(rs.data["_totals"])
        assert dict(py.data["dup.py"]) == dict(rs.data["dup.py"])


# ---------------------------------------------------------------------------
# Rust-only sanity tests (importability and basic smoke)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(RsMetrics is None, reason="Rust extension not installed")
class TestRustSmoke:
    """Basic smoke tests to confirm the Rust extension works end-to-end."""

    def test_import(self):
        """Rust extension can be imported."""
        from bandit_metrics import Metrics

        assert Metrics is not None

    def test_full_lifecycle(self):
        """Full lifecycle: construct → begin → mutations → aggregate → read."""
        m = RsMetrics()
        m.begin("lifecycle.py")
        m.count_locs([b"import os", b"x = 1", b"# comment", b""])
        m.note_nosec(1)
        m.note_skipped_test(2)
        m.count_issues(
            [
                {
                    "SEVERITY": [0, 0, 5, 10],
                    "CONFIDENCE": [1, 3, 0, 0],
                }
            ]
        )
        m.aggregate()

        totals = m.data["_totals"]
        assert totals["loc"] == 2
        assert totals["nosec"] == 1
        assert totals["skipped_tests"] == 2
        assert totals["SEVERITY.MEDIUM"] == 1
        assert totals["SEVERITY.HIGH"] == 1
        assert totals["CONFIDENCE.UNDEFINED"] == 1
        assert totals["CONFIDENCE.LOW"] == 1

    def test_data_direct_mutation(self):
        """Tests can directly mutate data dict (formatter test pattern)."""
        m = RsMetrics()
        # Use the data setter to replace the entire dict
        m.data = {"_totals": {"loc": 1000, "nosec": 50}}
        assert m.data["_totals"]["loc"] == 1000
        assert m.data["_totals"]["nosec"] == 50

    def test_multiple_files(self):
        """Multiple files tracked correctly."""
        m = RsMetrics()
        m.begin("a.py")
        m.count_locs([b"a1", b"a2"])
        m.note_nosec(1)
        m.count_issues(
            [{"SEVERITY": [0, 3, 0, 0], "CONFIDENCE": [0, 0, 0, 0]}]
        )

        m.begin("b.py")
        m.count_locs([b"b1"])
        m.note_nosec(2)
        m.count_issues(
            [{"SEVERITY": [0, 0, 5, 0], "CONFIDENCE": [0, 0, 0, 0]}]
        )

        m.aggregate()

        assert m.data["a.py"]["loc"] == 2
        assert m.data["b.py"]["loc"] == 1
        assert m.data["_totals"]["loc"] == 3
        assert m.data["_totals"]["nosec"] == 3
        assert m.data["_totals"]["SEVERITY.LOW"] == 1
        assert m.data["_totals"]["SEVERITY.MEDIUM"] == 1
