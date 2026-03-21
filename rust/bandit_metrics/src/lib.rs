use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::HashMap;

/// The ranking levels, matching bandit.core.constants.RANKING.
const RANKING: [&str; 4] = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"];

/// The ranking divisor values, matching bandit.core.constants.RANKING_VALUES.
const RANKING_VALUES: [i64; 4] = [1, 3, 5, 10];

/// The criteria names, matching bandit.core.constants.CRITERIA first elements.
const CRITERIA: [&str; 2] = ["SEVERITY", "CONFIDENCE"];

/// Pre-computed label strings for all criteria×ranking combinations.
/// Avoids `format!` allocations in hot loops.
const LABELS: [&str; 8] = [
    "SEVERITY.UNDEFINED",
    "SEVERITY.LOW",
    "SEVERITY.MEDIUM",
    "SEVERITY.HIGH",
    "CONFIDENCE.UNDEFINED",
    "CONFIDENCE.LOW",
    "CONFIDENCE.MEDIUM",
    "CONFIDENCE.HIGH",
];

/// Native Rust per-file metrics struct.
/// All mutations are pure Rust field increments — zero FFI overhead.
#[derive(Clone, Default)]
struct FileMetrics {
    loc: i64,
    nosec: i64,
    skipped_tests: i64,
    /// Issue counts indexed same as LABELS.
    /// `None` means count_issues was never called for this file.
    issue_counts: Option<[i64; 8]>,
}

impl FileMetrics {
    /// Convert to a Python dict.
    fn to_pydict<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyDict>> {
        let d = PyDict::new_bound(py);
        d.set_item("loc", self.loc)?;
        d.set_item("nosec", self.nosec)?;
        d.set_item("skipped_tests", self.skipped_tests)?;
        if let Some(ref counts) = self.issue_counts {
            for (i, label) in LABELS.iter().enumerate() {
                d.set_item(*label, counts[i])?;
            }
        }
        Ok(d)
    }

    /// Create a totals entry with all 11 keys set to zero.
    fn totals_default() -> Self {
        FileMetrics {
            loc: 0,
            nosec: 0,
            skipped_tests: 0,
            issue_counts: Some([0; 8]),
        }
    }
}

/// Rust-backed drop-in replacement for bandit.core.metrics.Metrics.
///
/// Stores all metrics natively in Rust structs. The `data` property
/// materializes a Python dict on each access for compatibility with
/// callers that read `metrics.data["_totals"]["loc"]` etc.
#[pyclass]
struct Metrics {
    /// Per-file metrics stored natively in Rust.
    entries: HashMap<String, FileMetrics>,
    /// The _totals entry, always present.
    totals: FileMetrics,
    /// Key of the currently active file, or None if `begin()` has not been called.
    current_key: Option<String>,
}

#[pymethods]
impl Metrics {
    #[new]
    fn new() -> Self {
        Metrics {
            entries: HashMap::new(),
            totals: FileMetrics::totals_default(),
            current_key: None,
        }
    }

    /// The `data` property — materializes a `dict[str, dict[str, int]]` on each access.
    /// This preserves the exact interface callers expect: `m.data["_totals"]["loc"]`.
    #[getter]
    fn data(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let data = PyDict::new_bound(py);
        let totals_dict = self.totals.to_pydict(py)?;
        data.set_item("_totals", &totals_dict)?;
        for (fname, metrics) in &self.entries {
            let entry_dict = metrics.to_pydict(py)?;
            data.set_item(fname.as_str(), &entry_dict)?;
        }
        Ok(data.unbind())
    }

    /// Setter for `data` — allows `m.data["_totals"] = {...}` pattern used by formatter tests.
    /// Parses the Python dict back into native Rust state.
    #[setter]
    fn set_data(&mut self, _py: Python<'_>, value: &Bound<'_, PyDict>) -> PyResult<()> {
        self.entries.clear();
        self.totals = FileMetrics::totals_default();
        for (key, val) in value.iter() {
            let k: String = key.extract()?;
            let entry_dict: &Bound<'_, PyDict> = val.downcast()?;
            let metrics = Self::parse_file_metrics(entry_dict)?;
            if k == "_totals" {
                self.totals = metrics;
            } else {
                self.entries.insert(k, metrics);
            }
        }
        Ok(())
    }

    /// Begin a new metric block for *fname* and make it the active file.
    fn begin(&mut self, fname: &str) {
        self.entries
            .insert(fname.to_owned(), FileMetrics::default());
        self.current_key = Some(fname.to_owned());
    }

    /// Increment the currently active file's nosec count by *num* (default 1).
    #[pyo3(signature = (num=1))]
    fn note_nosec(&mut self, num: i64) -> PyResult<()> {
        let current = self.get_current_mut()?;
        current.nosec += num;
        Ok(())
    }

    /// Increment the currently active file's skipped_tests count by *num* (default 1).
    #[pyo3(signature = (num=1))]
    fn note_skipped_test(&mut self, num: i64) -> PyResult<()> {
        let current = self.get_current_mut()?;
        current.skipped_tests += num;
        Ok(())
    }

    /// Count lines of code in *lines* (a list of bytes objects).
    ///
    /// A line counts as code if, after stripping ASCII whitespace, it is
    /// non-empty and does not start with b"#".
    fn count_locs(&mut self, lines: &Bound<'_, PyList>) -> PyResult<()> {
        let mut count: i64 = 0;
        for item in lines.iter() {
            let line: &[u8] = item.downcast::<PyBytes>()?.as_bytes();
            let trimmed = line.trim_ascii();
            if !trimmed.is_empty() && !trimmed.starts_with(b"#") {
                count += 1;
            }
        }
        let current = self.get_current_mut()?;
        current.loc += count;
        Ok(())
    }

    /// Record issue counts derived from *scores* into the current file entry.
    ///
    /// Replicates the exact behaviour of the Python implementation including
    /// the latent bug where only the first score's values are recorded for
    /// each label (the accumulation line is inside the `if label not in` guard).
    fn count_issues(&mut self, scores: &Bound<'_, PyList>) -> PyResult<()> {
        let issue_counts = Self::get_issue_counts(scores)?;
        if issue_counts.is_none() {
            return Ok(());
        }
        let current = self.get_current_mut()?;
        current.issue_counts = issue_counts;
        Ok(())
    }

    /// Final aggregation: sum all entries (including old _totals) into new _totals.
    /// Pure Rust arithmetic — no Python interaction at all.
    fn aggregate(&mut self) {
        let mut new_totals = FileMetrics::totals_default();
        let counts = new_totals.issue_counts.as_mut().unwrap();

        // Sum the existing _totals first (replicates Python Counter addition
        // where old _totals is included in the sum)
        new_totals.loc += self.totals.loc;
        new_totals.nosec += self.totals.nosec;
        new_totals.skipped_tests += self.totals.skipped_tests;
        if let Some(ref tc) = self.totals.issue_counts {
            for i in 0..8 {
                counts[i] += tc[i];
            }
        }

        // Sum all per-file entries
        for metrics in self.entries.values() {
            new_totals.loc += metrics.loc;
            new_totals.nosec += metrics.nosec;
            new_totals.skipped_tests += metrics.skipped_tests;
            if let Some(ref ic) = metrics.issue_counts {
                for i in 0..8 {
                    counts[i] += ic[i];
                }
            }
        }

        self.totals = new_totals;
    }
}

impl Metrics {
    /// Get a mutable reference to the current file's metrics.
    /// Raises AttributeError if begin() has not been called, matching the Python behaviour.
    fn get_current_mut(&mut self) -> PyResult<&mut FileMetrics> {
        let key = self.current_key.as_ref().ok_or_else(|| {
            PyAttributeError::new_err("'Metrics' object has no attribute 'current'")
        })?;
        self.entries.get_mut(key).ok_or_else(|| {
            PyAttributeError::new_err("'Metrics' object has no attribute 'current'")
        })
    }

    /// Parse a Python dict into a FileMetrics struct.
    fn parse_file_metrics(d: &Bound<'_, PyDict>) -> PyResult<FileMetrics> {
        let loc = d
            .get_item("loc")?
            .map(|v| v.extract::<i64>())
            .transpose()?
            .unwrap_or(0);
        let nosec = d
            .get_item("nosec")?
            .map(|v| v.extract::<i64>())
            .transpose()?
            .unwrap_or(0);
        let skipped_tests = d
            .get_item("skipped_tests")?
            .map(|v| v.extract::<i64>())
            .transpose()?
            .unwrap_or(0);

        let mut has_issues = false;
        let mut counts = [0i64; 8];
        for (i, label) in LABELS.iter().enumerate() {
            if let Some(val) = d.get_item(*label)? {
                counts[i] = val.extract::<i64>()?;
                has_issues = true;
            }
        }

        Ok(FileMetrics {
            loc,
            nosec,
            skipped_tests,
            issue_counts: if has_issues { Some(counts) } else { None },
        })
    }

    /// Static helper replicating `_get_issue_counts`.
    ///
    /// Faithfully reproduces the Python behaviour: the accumulation is inside
    /// the `if label not in issue_counts` guard, so only the first score's
    /// value for each label is ever counted.
    ///
    /// Returns `None` for empty scores (no-op), or `Some([i64; 8])` with counts.
    fn get_issue_counts(scores: &Bound<'_, PyList>) -> PyResult<Option<[i64; 8]>> {
        if scores.len() == 0 {
            return Ok(None);
        }

        let mut counts = [0i64; 8];
        let mut seen = [false; 8];

        for score_item in scores.iter() {
            let score: &Bound<'_, PyDict> = score_item.downcast()?;
            for (ci, criteria) in CRITERIA.iter().enumerate() {
                let arr = score
                    .get_item(*criteria)?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyKeyError::new_err(criteria.to_string())
                    })?;
                let values: &Bound<'_, PyList> = arr.downcast()?;

                for ri in 0..4 {
                    let idx = ci * 4 + ri;
                    // Replicate the Python bug: only set if not already seen
                    if !seen[idx] {
                        let raw: i64 = values.get_item(ri)?.extract()?;
                        counts[idx] = raw / RANKING_VALUES[ri];
                        seen[idx] = true;
                    }
                }
            }
        }

        Ok(Some(counts))
    }
}

/// Python module definition.
#[pymodule]
fn bandit_metrics(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Metrics>()?;
    Ok(())
}
