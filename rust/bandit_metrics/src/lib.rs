use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

/// The ranking levels, matching bandit.core.constants.RANKING.
const RANKING: &[&str] = &["UNDEFINED", "LOW", "MEDIUM", "HIGH"];

/// The ranking divisor values, matching bandit.core.constants.RANKING_VALUES.
const RANKING_VALUES: &[i64] = &[1, 3, 5, 10]; // indexed same as RANKING

/// The criteria names, matching bandit.core.constants.CRITERIA first elements.
const CRITERIA: &[&str] = &["SEVERITY", "CONFIDENCE"];

/// Rust-backed drop-in replacement for bandit.core.metrics.Metrics.
///
/// Exposes the identical public interface so that callers can access
/// `metrics.data["_totals"]["loc"]` etc. without any changes.
#[pyclass]
struct Metrics {
    /// The metrics data dict – `dict[str, dict[str, int]]`.
    /// Stored as a Python dict so callers get the exact same object semantics
    /// (direct mutation, iteration, JSON serialisation) as the pure-Python version.
    #[pyo3(get)]
    data: Py<PyDict>,

    /// Key of the currently active file, or None if `begin()` has not been called.
    current_key: Option<String>,
}

#[pymethods]
impl Metrics {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let data = PyDict::new_bound(py);

        // Build _totals with {loc:0, nosec:0, skipped_tests:0, + 8 issue-count keys}
        let totals = PyDict::new_bound(py);
        totals.set_item("loc", 0)?;
        totals.set_item("nosec", 0)?;
        totals.set_item("skipped_tests", 0)?;
        for rank in RANKING {
            for criteria in CRITERIA {
                let label = format!("{criteria}.{rank}");
                totals.set_item(&label, 0)?;
            }
        }
        data.set_item("_totals", &totals)?;

        Ok(Metrics {
            data: data.unbind(),
            current_key: None,
        })
    }

    /// Begin a new metric block for *fname* and make it the active file.
    fn begin(&mut self, py: Python<'_>, fname: &str) -> PyResult<()> {
        let entry = PyDict::new_bound(py);
        entry.set_item("loc", 0)?;
        entry.set_item("nosec", 0)?;
        entry.set_item("skipped_tests", 0)?;

        let data = self.data.bind(py);
        data.set_item(fname, &entry)?;
        self.current_key = Some(fname.to_owned());
        Ok(())
    }

    /// Increment the currently active file's nosec count by *num* (default 1).
    #[pyo3(signature = (num=1))]
    fn note_nosec(&self, py: Python<'_>, num: i64) -> PyResult<()> {
        let current = self.get_current(py)?;
        let old: i64 = current.get_item("nosec")?.unwrap().extract()?;
        current.set_item("nosec", old + num)?;
        Ok(())
    }

    /// Increment the currently active file's skipped_tests count by *num* (default 1).
    #[pyo3(signature = (num=1))]
    fn note_skipped_test(&self, py: Python<'_>, num: i64) -> PyResult<()> {
        let current = self.get_current(py)?;
        let old: i64 = current.get_item("skipped_tests")?.unwrap().extract()?;
        current.set_item("skipped_tests", old + num)?;
        Ok(())
    }

    /// Count lines of code in *lines* (a list of bytes objects).
    ///
    /// A line counts as code if, after stripping ASCII whitespace, it is
    /// non-empty and does not start with b"#".
    fn count_locs(&self, py: Python<'_>, lines: &Bound<'_, PyList>) -> PyResult<()> {
        let mut count: i64 = 0;
        for item in lines.iter() {
            let line: &[u8] = item.downcast::<PyBytes>()?.as_bytes();
            let trimmed = trim_ascii(line);
            if !trimmed.is_empty() && !trimmed.starts_with(b"#") {
                count += 1;
            }
        }

        let current = self.get_current(py)?;
        let old: i64 = current.get_item("loc")?.unwrap().extract()?;
        current.set_item("loc", old + count)?;
        Ok(())
    }

    /// Record issue counts derived from *scores* into the current file entry.
    ///
    /// Replicates the exact behaviour of the Python implementation including
    /// the latent bug where only the first score's values are recorded for
    /// each label (the accumulation line is inside the `if label not in` guard).
    fn count_issues(&self, py: Python<'_>, scores: &Bound<'_, PyList>) -> PyResult<()> {
        let issue_counts = Self::get_issue_counts(scores)?;
        if issue_counts.is_empty() {
            return Ok(());
        }

        let current = self.get_current(py)?;
        for (label, value) in &issue_counts {
            current.set_item(label.as_str(), *value)?;
        }
        Ok(())
    }

    /// Final aggregation: sum all entries (including old _totals) into new _totals.
    fn aggregate(&self, py: Python<'_>) -> PyResult<()> {
        let data = self.data.bind(py);

        // Collect all keys that appear in any entry
        let mut all_keys: Vec<String> = Vec::new();
        for (_, value) in data.iter() {
            let entry: &Bound<'_, PyDict> = value.downcast()?;
            for (k, _) in entry.iter() {
                let key: String = k.extract()?;
                if !all_keys.contains(&key) {
                    all_keys.push(key);
                }
            }
        }

        // Sum values for each key across all entries
        let new_totals = PyDict::new_bound(py);
        for key in &all_keys {
            let mut total: i64 = 0;
            for (_, value) in data.iter() {
                let entry: &Bound<'_, PyDict> = value.downcast()?;
                if let Some(val) = entry.get_item(key.as_str())? {
                    let v: i64 = val.extract()?;
                    total += v;
                }
            }
            new_totals.set_item(key.as_str(), total)?;
        }

        data.set_item("_totals", &new_totals)?;
        Ok(())
    }
}

impl Metrics {
    /// Get a reference to the current file's dict. Raises AttributeError if
    /// begin() has not been called, matching the Python behaviour.
    fn get_current<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let key = self.current_key.as_ref().ok_or_else(|| {
            PyAttributeError::new_err("'Metrics' object has no attribute 'current'")
        })?;
        let data = self.data.bind(py);
        let entry = data
            .get_item(key)?
            .ok_or_else(|| {
                PyAttributeError::new_err("'Metrics' object has no attribute 'current'")
            })?;
        Ok(entry.downcast_into()?)
    }

    /// Static helper replicating `_get_issue_counts`.
    ///
    /// Faithfully reproduces the Python behaviour: the accumulation is inside
    /// the `if label not in issue_counts` guard, so only the first score's
    /// value for each label is ever counted.
    fn get_issue_counts(scores: &Bound<'_, PyList>) -> PyResult<Vec<(String, i64)>> {
        let mut issue_counts: Vec<(String, i64)> = Vec::new();

        for score_item in scores.iter() {
            let score: &Bound<'_, PyDict> = score_item.downcast()?;
            for criteria in CRITERIA {
                let arr = score
                    .get_item(*criteria)?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyKeyError::new_err(criteria.to_string())
                    })?;
                let values: &Bound<'_, PyList> = arr.downcast()?;

                for (i, rank) in RANKING.iter().enumerate() {
                    let label = format!("{criteria}.{rank}");

                    // Replicate the Python bug: only set if label not already present
                    if !issue_counts.iter().any(|(k, _)| k == &label) {
                        let raw: i64 = values.get_item(i)?.extract()?;
                        let count = raw / RANKING_VALUES[i]; // integer division
                        issue_counts.push((label, count));
                    }
                }
            }
        }

        Ok(issue_counts)
    }
}

/// Strip leading and trailing ASCII whitespace from a byte slice.
fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
    &s[start..end]
}

/// Python module definition.
#[pymodule]
fn bandit_metrics(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Metrics>()?;
    Ok(())
}
