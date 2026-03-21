# Comprehensive Analysis of `bandit/core/metrics.py`

> This document is the source of truth for rewriting `bandit.core.metrics.Metrics` in Rust.
> It covers every aspect of the class: its purpose, data model, API, callers, lifecycle,
> concurrency profile, edge cases, performance bottlenecks, Python-specific behaviours,
> and invariants.

---

## 1. Purpose and Role

`Metrics` is a **stateful accumulator** that collects quantitative data about a Bandit scan.
It answers the questions:

| Question | Key(s) |
|---|---|
| How many non-trivial lines of code were scanned (per file and total)? | `loc` |
| How many lines were suppressed by a blanket `# nosec` comment? | `nosec` |
| How many individual test skips were caused by `# nosec BXXX` comments? | `skipped_tests` |
| How many issues were found at each severity/confidence level? | `SEVERITY.{UNDEFINED,LOW,MEDIUM,HIGH}`, `CONFIDENCE.{UNDEFINED,LOW,MEDIUM,HIGH}` |

### Position in the scan pipeline

```
BanditManager.__init__()          # (1) Metrics() is constructed
        |
BanditManager.run_tests()         # (2) iterates over files
        |
  +-- _parse_file()               # (3) per file:
  |     metrics.begin(fname)      #     open a new per-file block
  |     metrics.count_locs(lines) #     count non-blank, non-comment lines
  |     _execute_ast_visitor()    #     walk the AST; tester calls
  |       |                       #       metrics.note_nosec() /
  |       |                       #       metrics.note_skipped_test()
  |     metrics.count_issues([score])  # record issue counts for this file
  |
  +-- metrics.aggregate()         # (4) sum all per-file blocks into _totals
        |
BanditManager.output_results()    # (5) formatter reads metrics.data
```

`Metrics` is therefore **write-heavy during scanning** (steps 2-4) and **read-only during
reporting** (step 5).

---

## 2. Data Model

### 2.1 Top-level structure

```python
self.data: dict[str, dict[str, int]]
```

`data` is a dictionary whose **keys** are either:

- **File paths** (strings, e.g. `"./example.py"` or `"<stdin>"`) — one entry per scanned file.
- **`"_totals"`** — a sentinel key holding the aggregate sums of all per-file entries.

Each **value** is a flat `dict[str, int]` with the following keys:

| Key | Type | Meaning |
|---|---|---|
| `"loc"` | `int` | Lines of code (non-blank, non-comment) |
| `"nosec"` | `int` | Count of blanket `# nosec` suppressions |
| `"skipped_tests"` | `int` | Count of specific `# nosec BXXX` suppressions |
| `"SEVERITY.UNDEFINED"` | `int` | Issue count at severity=UNDEFINED |
| `"SEVERITY.LOW"` | `int` | Issue count at severity=LOW |
| `"SEVERITY.MEDIUM"` | `int` | Issue count at severity=MEDIUM |
| `"SEVERITY.HIGH"` | `int` | Issue count at severity=HIGH |
| `"CONFIDENCE.UNDEFINED"` | `int` | Issue count at confidence=UNDEFINED |
| `"CONFIDENCE.LOW"` | `int` | Issue count at confidence=LOW |
| `"CONFIDENCE.MEDIUM"` | `int` | Issue count at confidence=MEDIUM |
| `"CONFIDENCE.HIGH"` | `int` | Issue count at confidence=HIGH |

### 2.2 Shape of `constants.RANKING` and `constants.CRITERIA`

```python
RANKING = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"]           # 4 elements
RANKING_VALUES = {"UNDEFINED": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 10}
CRITERIA = [("SEVERITY", "UNDEFINED"), ("CONFIDENCE", "UNDEFINED")]  # 2 tuples
```

The composite keys are formed as `f"{criteria[0]}.{rank}"`, yielding 2 x 4 = 8 keys:

```
SEVERITY.UNDEFINED, SEVERITY.LOW, SEVERITY.MEDIUM, SEVERITY.HIGH,
CONFIDENCE.UNDEFINED, CONFIDENCE.LOW, CONFIDENCE.MEDIUM, CONFIDENCE.HIGH
```

### 2.3 The `_totals` sentinel

- **Created at construction** with `loc=0`, `nosec=0`, `skipped_tests=0`, and all 8 issue-count keys set to `0`.
- **Overwritten entirely** by `aggregate()`, which replaces `data["_totals"]` with the element-wise sum of every entry in `data` (including the old `_totals` itself — see §6 and §8 for implications).

### 2.4 Per-file entries

Created by `begin(fname)` with only three keys: `loc`, `nosec`, `skipped_tests` (all `0`).
Issue-count keys (`SEVERITY.*`, `CONFIDENCE.*`) are **added later** by `count_issues()`,
which calls `dict.update()` with the output of `_get_issue_counts()`.

This means a per-file dict may lack issue-count keys if `count_issues()` was never called
for that file (e.g. the file raised `SyntaxError` before the AST visitor ran).

---

## 3. Public API

### 3.1 `__init__(self)`

```python
def __init__(self):
```

- **Creates** `self.data` as an empty `dict`.
- **Initialises** `self.data["_totals"]` with `loc=0`, `nosec=0`, `skipped_tests=0`, and the 8 issue-count keys all set to `0`.
- **Does not** initialise `self.current`.

**State modified:** `self.data`

---

### 3.2 `begin(self, fname)`

```python
def begin(self, fname: str) -> None
```

- **Creates** a new per-file entry in `self.data[fname]` with `{"loc": 0, "nosec": 0, "skipped_tests": 0}`.
- **Sets** `self.current` to point to this same dict object (reference aliasing).

**Precondition:** None (any string key is accepted).
**State modified:** `self.data[fname]`, `self.current`

---

### 3.3 `note_nosec(self, num=1)`

```python
def note_nosec(self, num: int = 1) -> None
```

- **Increments** `self.current["nosec"]` by `num`.

**Precondition:** `begin()` must have been called (otherwise `self.current` is undefined → `AttributeError`).
**State modified:** `self.current["nosec"]` (which is the same object as `self.data[<current_file>]["nosec"]` via reference aliasing).

---

### 3.4 `note_skipped_test(self, num=1)`

```python
def note_skipped_test(self, num: int = 1) -> None
```

- **Increments** `self.current["skipped_tests"]` by `num`.

**Precondition:** Same as `note_nosec`.
**State modified:** `self.current["skipped_tests"]`

---

### 3.5 `count_locs(self, lines)`

```python
def count_locs(self, lines: list[bytes]) -> None
```

- **Counts** lines that are neither empty nor start with `b"#"` after stripping whitespace.
- **Adds** the count to `self.current["loc"]`.

**Important detail:** The input `lines` come from `data.splitlines()` where `data` was read
in binary mode (`open(fname, "rb")`). Therefore each line is `bytes`, and the comment prefix
check uses `b"#"` (bytes literal). A Rust implementation must operate on byte slices, not
UTF-8 strings.

**Precondition:** `begin()` must have been called.
**State modified:** `self.current["loc"]`

---

### 3.6 `count_issues(self, scores)`

```python
def count_issues(self, scores: list[dict[str, list[int]]]) -> None
```

- **Delegates** to `_get_issue_counts(scores)` (a static method).
- **Merges** the returned dict into `self.current` via `dict.update()`.

`scores` is a list containing one element — a dict shaped like:

```python
{
    "SEVERITY":   [0, 0, 0, 10],   # indexed by RANKING position (4 elements)
    "CONFIDENCE": [0, 0, 0, 10],
}
```

Each element at index `i` is a weighted score value: `count * RANKING_VALUES[rank]`.

**State modified:** `self.current` (adds/overwrites the 8 issue-count keys)

---

### 3.7 `aggregate(self)`

```python
def aggregate(self) -> None
```

- **Iterates** over all keys in `self.data` (including `"_totals"` itself).
- **Sums** every value using `collections.Counter` addition.
- **Overwrites** `self.data["_totals"]` with the resulting dict cast back to `dict`.

**Critical subtlety:** Because the iteration includes the existing `"_totals"` entry, the
aggregated totals will include the initial `_totals` values. Since those initial values are
all `0`, this is harmless in practice. However, if `aggregate()` were called twice, the
totals would be doubled — this is a latent bug (see §8).

**State modified:** `self.data["_totals"]`

---

### 3.8 `_get_issue_counts(scores)` (static method)

```python
@staticmethod
def _get_issue_counts(scores: list[dict[str, list[int]]]) -> dict[str, int]
```

- For each `score` in `scores`, for each `(criteria, _)` in `CRITERIA`, for each
  `(i, rank)` in `enumerate(RANKING)`:
  - Computes `label = f"{criteria}.{rank}"`.
  - Performs integer division: `count = score[criteria][i] // RANKING_VALUES[rank]`.
  - Accumulates into `issue_counts[label]`.

**Return:** A flat dict like `{"SEVERITY.LOW": 2, "CONFIDENCE.HIGH": 1, ...}`.

**Bug in current code:** The accumulation line `issue_counts[label] += count` is inside the
`if label not in issue_counts` block. This means **only the first score's values are ever
recorded**; subsequent scores for the same label are silently discarded. In the current
codebase this is not triggered because `count_issues()` is always called with a single-element
list `[score]`, so the loop body executes only once per label.

---

## 4. Caller Map

### 4.1 `Metrics()` (constructor)

| Location | Context |
|---|---|
| `bandit/core/manager.py:71` | `BanditManager.__init__()` — one instance per scan run |
| `tests/unit/formatters/test_json.py:64` | Test setup |
| `tests/unit/formatters/test_sarif.py:69` | Test setup |
| `tests/unit/formatters/test_yaml.py:52` | Test setup |
| `tests/functional/test_functional.py:93` | Functional test setup |

### 4.2 `begin(fname)`

| Location | Context |
|---|---|
| `bandit/core/manager.py:306` | `_parse_file()` — called once per file, before LOC counting and AST visiting |

### 4.3 `note_nosec()`

| Location | Context |
|---|---|
| `bandit/core/tester.py:87` | `BanditTester.run_tests()` — when a blanket `# nosec` comment suppresses a finding |

### 4.4 `note_skipped_test()`

| Location | Context |
|---|---|
| `bandit/core/tester.py:93` | `BanditTester.run_tests()` — when a `# nosec BXXX` comment suppresses a specific test |

### 4.5 `count_locs(lines)`

| Location | Context |
|---|---|
| `bandit/core/manager.py:307` | `_parse_file()` — immediately after `begin()`, before AST visiting |

### 4.6 `count_issues(scores)`

| Location | Context |
|---|---|
| `bandit/core/manager.py:324` | `_parse_file()` — after the AST visitor completes, with the file's score list |

### 4.7 `aggregate()`

| Location | Context |
|---|---|
| `bandit/core/manager.py:299` | `run_tests()` — called exactly once, after all files have been processed |

### 4.8 `data` (direct field access)

| Location | Field accessed | Context |
|---|---|---|
| `bandit/formatters/json.py:137` | `manager.metrics.data` (entire dict) | Serialised as `"metrics"` in JSON output |
| `bandit/formatters/yaml.py:108` | `manager.metrics.data` (entire dict) | Serialised as `"metrics"` in YAML output |
| `bandit/formatters/sarif.py:177` | `manager.metrics.data` (entire dict) | Embedded in SARIF run properties |
| `bandit/formatters/html.py:379-380` | `data["_totals"]["loc"]`, `data["_totals"]["nosec"]` | Inserted into HTML template |
| `bandit/formatters/screen.py:98` | `data["_totals"][f"{criteria}.{rank}"]` | Printed in "Run metrics" section |
| `bandit/formatters/screen.py:222` | `data["_totals"]["loc"]` | Printed in "Code scanned" section |
| `bandit/formatters/screen.py:227` | `data["_totals"]["nosec"]` | Printed in "Code scanned" section |
| `bandit/formatters/text.py:72` | `data["_totals"][f"{criteria}.{rank}"]` | Printed in "Run metrics" section |
| `bandit/formatters/text.py:176` | `data["_totals"]["loc"]` | Printed in "Code scanned" section |
| `bandit/formatters/text.py:181` | `data["_totals"]["nosec"]` | Printed in "Code scanned" section |
| `bandit/formatters/text.py:186` | `data["_totals"]["skipped_tests"]` | Printed in "Code scanned" section |
| Various test files | `manager.metrics.data[...]` | Directly mutate `data` for test setup |
| `tests/functional/test_functional.py:98` | `self.b_mgr.metrics.data` | Read the whole dict for assertions |

---

## 5. Mutation Timeline

The lifecycle of a `Metrics` instance from construction to final report:

```
Phase 1: Construction
  __init__()
    → data = {}
    → data["_totals"] = {loc:0, nosec:0, skipped_tests:0,
                         SEVERITY.UNDEFINED:0, ..., CONFIDENCE.HIGH:0}
    → self.current is UNSET (no attribute)

Phase 2: Per-file processing (repeated for each file)
  begin(fname)
    → data[fname] = {loc:0, nosec:0, skipped_tests:0}
    → self.current = data[fname]          (reference alias)

  count_locs(lines)
    → self.current["loc"] += N            (via self.current, mutates data[fname])

  [AST visiting — multiple calls possible per file]
    note_nosec()
      → self.current["nosec"] += 1        (via self.current, mutates data[fname])
    note_skipped_test()
      → self.current["skipped_tests"] += 1 (via self.current, mutates data[fname])

  count_issues([score])
    → self.current.update({               (via self.current, mutates data[fname])
        "SEVERITY.UNDEFINED": N, ...,
        "CONFIDENCE.HIGH": N
      })

Phase 3: Aggregation (exactly once)
  aggregate()
    → counter = sum of all data[*] entries (including old _totals)
    → data["_totals"] = dict(counter)

Phase 4: Reporting (read-only)
  Formatters read data["_totals"] and/or the entire data dict.
  No further mutations occur.
```

### Key ordering guarantees

1. `begin()` is always called before any `note_*`, `count_locs`, or `count_issues` for a given file.
2. `count_locs()` is called before the AST visitor runs (so `loc` is set before `nosec`/`skipped_tests` are incremented).
3. `count_issues()` is called after the AST visitor returns (so issue counts reflect the full file scan).
4. `aggregate()` is called exactly once, after all files are processed.
5. Formatters execute after `aggregate()`.

---

## 6. Concurrency

### Current situation

Bandit processes files **sequentially** in a single thread. The `Metrics` instance is:

- **Created** by `BanditManager.__init__()` on the main thread.
- **Passed by reference** through `BanditNodeVisitor` → `BanditTester`.
- All mutations happen on the **same thread** in a deterministic order.

There is **no locking** anywhere in the `Metrics` class.

### Risks if used concurrently

| Risk | Explanation |
|---|---|
| **`self.current` race** | `self.current` is a single mutable pointer. If two threads call `begin()` concurrently, one thread's `current` will be silently overwritten, and subsequent `note_nosec()` / `count_locs()` calls will mutate the wrong file's data. |
| **`dict.update()` race** | Multiple threads calling `count_issues()` on the same dict is not thread-safe in general. In CPython the GIL protects against segfaults but not logical races. |
| **`aggregate()` timing** | `aggregate()` must be called after all per-file processing completes. If called while another thread is still writing, the totals will be incomplete. |
| **Counter summation** | `collections.Counter.update()` is not atomic. Concurrent iteration over `self.data` during `aggregate()` while another thread adds new keys would cause `RuntimeError: dictionary changed size during iteration`. |

### Recommendations for Rust

- If parallelising file processing, use **per-thread local accumulators** and merge them at the end, or protect `Metrics` with a `Mutex`.
- `self.current` should be replaced with an explicit file-key parameter, or the per-file dict should be returned from a builder method rather than stored as shared mutable state.

---

## 7. Edge Cases

### 7.1 No files scanned

If `files_list` is empty, `run_tests()` will call `aggregate()` immediately. The `Counter` will
iterate only over `data["_totals"]` (the initial zeroed entry) and produce a new `_totals` that
is identical — all zeros. Formatters will display `loc=0, nosec=0`, etc. This is correct
behaviour.

### 7.2 File with zero lines

`count_locs([])` adds `0` to `self.current["loc"]`. The entry will exist with `loc=0`. This is
correct — the file was scanned but had no code.

### 7.3 `nosec` count exceeds `loc`

Nothing in the code prevents `nosec > loc`. A `# nosec` comment on a line that contains only
a comment (which is excluded from `loc`) would increment `nosec` without incrementing `loc`.
The Rust implementation should not enforce `nosec <= loc` as the Python code does not.

### 7.4 `_totals` is never written / `aggregate()` is never called

If `aggregate()` is never called, `data["_totals"]` will contain the initial zeros from
`__init__()`. Formatters that read `_totals` will report zeros for everything. The per-file
data will exist but will not be reflected in `_totals`.

### 7.5 `aggregate()` called twice

The second call will iterate over all entries including the already-aggregated `_totals`, effectively
doubling the totals. This is a latent bug in the Python code (it never happens in practice because
`aggregate()` is called exactly once).

### 7.6 `begin()` called with same filename twice

The second call overwrites `data[fname]`, resetting `loc`, `nosec`, and `skipped_tests` to 0 and
discarding any previously recorded data for that file. The previous per-file entry is lost.

### 7.7 `_get_issue_counts` receives an empty scores list

If `scores` is `[]`, the method returns `{}`. `count_issues` then calls `self.current.update({})`,
which is a no-op. The per-file entry will lack issue-count keys (`SEVERITY.*`, `CONFIDENCE.*`).
When `aggregate()` runs, `Counter` will simply skip those keys for that file.

### 7.8 File raises SyntaxError or other exception during parsing

In `_parse_file()`, if a `SyntaxError` is raised after `begin()` and `count_locs()` but before
`count_issues()`, the per-file entry will have `loc`, `nosec`, `skipped_tests` but **no**
issue-count keys. The file is added to `skipped` and removed from `files_list`, but its
partial metrics entry **remains** in `data` and will be included in `aggregate()`.

---

## 8. Bottlenecks and Performance Concerns

### 8.1 Repeated string formatting

`_get_issue_counts` constructs `f"{criteria}.{rank}"` strings in a triple-nested loop
(scores x criteria x ranking). For `N` files, this produces `N * 1 * 2 * 4 = 8N` format
operations. The same strings are constructed in `__init__()` and in every formatter that
iterates over criteria/ranking.

**Rust recommendation:** Use an enum-based key (e.g. `(Criteria, Ranking)` tuple) internally
and only format strings for serialisation.

### 8.2 Dynamic dict construction

Every per-file entry and `_totals` is a plain `dict`. There is no schema enforcement. Keys
can be missing (see §7.7, §7.8). Formatters access keys by string name with no compile-time
safety.

**Rust recommendation:** Use a `struct` with named fields. This eliminates key typos, enables
compile-time checking, and avoids hash-map overhead.

### 8.3 `collections.Counter` aggregation

`aggregate()` creates a `Counter`, then iterates over every entry in `data` calling
`Counter.update()`. This is O(K * F) where K is the number of keys per entry (~11) and F
is the number of files. For typical codebases this is negligible, but the Python overhead
per operation is high.

**Rust recommendation:** A simple loop summing struct fields will be orders of magnitude faster.

### 8.4 `count_locs` line-by-line processing

`count_locs` calls `sum(proc(line) for line in lines)` where `proc` strips whitespace and
checks for `b"#"` prefix. This is pure Python iteration over potentially large files.

**Rust recommendation:** Process the raw byte buffer directly, counting newline-terminated
segments that are non-empty after stripping and do not start with `#`. Use SIMD or
`memchr` for newline scanning if performance is critical.

### 8.5 `self.current` indirection

`self.current` is a reference alias to the current file's dict. Every `note_nosec()`,
`note_skipped_test()`, and `count_locs()` call goes through this indirection. In Python
this is a simple attribute lookup; in Rust, this pattern would require either an index into
the map or a mutable borrow, which has ownership implications.

### 8.6 GIL contention (theoretical)

Although Bandit is currently single-threaded, if parallelised under Python's GIL, the
per-line processing in `count_locs` and per-node processing in the AST visitor would contend
on the GIL, limiting parallel throughput. In Rust, true parallelism via Rayon or similar
would avoid this entirely.

---

## 9. Python-Specific Dependencies

The following Python behaviours are relied upon and must be explicitly handled in Rust:

### 9.1 Dict mutability and reference aliasing

```python
self.current = self.data[fname]  # self.current IS self.data[fname]
self.current["loc"] += 1         # mutates self.data[fname]["loc"]
```

In Rust, you cannot hold a mutable reference to a `HashMap` value while also holding a
reference to the `HashMap` itself. Options:
- Use an index/key and look up each time.
- Use `Rc<RefCell<FileMetrics>>` (single-threaded) or `Arc<Mutex<FileMetrics>>` (multi-threaded).
- Restructure to pass the file key explicitly to each method.

### 9.2 `dict.update()` semantics

`self.current.update(...)` merges keys, overwriting existing ones. In Rust, this is
`HashMap::extend()` or manual field assignment on a struct.

### 9.3 `collections.Counter` semantics

`Counter.update(dict)` adds values for matching keys and creates new keys as needed.
In Rust, iterate and sum field-by-field on a struct.

### 9.4 Bytes vs strings in `count_locs`

```python
tmp = line.strip()
return bool(tmp and not tmp.startswith(b"#"))
```

- `line` is `bytes` (file opened in `"rb"` mode).
- `.strip()` on bytes strips ASCII whitespace (`b" \t\n\r\x0b\x0c"`).
- `.startswith(b"#")` checks the first byte.

In Rust, use `&[u8]` slices with `trim_ascii()` (or manual whitespace stripping) and check
`first() == Some(&b'#')`.

### 9.5 Integer division (`//`)

```python
count = score[criteria][i] // constants.RANKING_VALUES[rank]
```

Python's `//` is floor division (rounds towards negative infinity). For non-negative integers
(which these always are), this is equivalent to Rust's `/` on unsigned integers. Use `u32` or
`u64` division.

### 9.6 String interning / identity

Dict keys like `"loc"`, `"nosec"`, `"SEVERITY.LOW"` are interned by CPython, making lookups
fast (pointer comparison). Rust `HashMap<String, _>` will do full string comparison. Using
an enum eliminates this concern entirely.

### 9.7 Dynamic attribute creation

`self.current` is not declared in the class body or `__init__`; it is first assigned in
`begin()`. Calling `note_nosec()` before `begin()` raises `AttributeError`. In Rust, model
this as `Option<Key>` (where `Key` is the current file's identifier) and return `Result::Err`
or panic if `None`.

### 9.8 `dict()` constructor from `Counter`

```python
self.data["_totals"] = dict(c)
```

`Counter` is a subclass of `dict`. Converting back to `dict` strips the `Counter`-specific
behaviour (e.g. missing keys returning 0). In Rust, this is simply assigning the summed
struct to the `_totals` slot.

### 9.9 Generator expression in `count_locs`

```python
sum(proc(line) for line in lines)
```

`proc` returns `bool`, and Python's `sum()` treats `True` as `1` and `False` as `0`. In Rust,
use `.filter(predicate).count()` or `.map(|line| predicate(line) as usize).sum()`.

---

## 10. Invariants

The following invariants must hold. A correct Rust implementation must preserve all of them.

### 10.1 Structural invariants

1. **`data["_totals"]` always exists** after construction. It is never removed.
2. **Per-file keys are never `"_totals"`** — no scanned file should have the literal path `_totals`. (This is not enforced; it is an implicit assumption.)
3. **All values in any entry are non-negative integers.** No method ever decrements a counter.
4. **After `aggregate()`**, `data["_totals"]` contains the element-wise sum of all entries in `data` (including the pre-aggregation `_totals`, which is all zeros).

### 10.2 Lifecycle invariants

5. **`begin()` is called exactly once per file**, before any other per-file method.
6. **`count_locs()` is called exactly once per file**, immediately after `begin()`.
7. **`note_nosec()` and `note_skipped_test()` are called zero or more times per file**, only between `begin()` and `count_issues()`.
8. **`count_issues()` is called at most once per file**, after the AST visitor completes.
9. **`aggregate()` is called exactly once**, after all files are processed and before any formatter reads `data`.
10. **After `aggregate()`, no further mutations occur.**

### 10.3 Semantic invariants

11. **`_totals[key] == sum(data[f][key] for f in data if f != "_totals")`** — but only after `aggregate()` has been called. Before aggregation, `_totals` is stale (all zeros from init).
12. **`loc` counts only non-empty, non-comment lines** (bytes-level check: stripped line is non-empty and does not start with `b"#"`).
13. **Issue counts are derived from weighted scores** via integer division by `RANKING_VALUES[rank]`. This means the count represents the number of issues, not the raw score.

### 10.4 Key completeness

14. **`_totals` always has all 11 keys** (`loc`, `nosec`, `skipped_tests`, plus the 8 issue-count keys) after both `__init__` and `aggregate()`.
15. **Per-file entries may lack issue-count keys** if `count_issues()` was never called (e.g. due to a `SyntaxError`). They will always have `loc`, `nosec`, and `skipped_tests` (set by `begin()`).

---

## Appendix A: Recommended Rust Data Model

```rust
/// Counts of issues bucketed by severity or confidence level.
#[derive(Debug, Clone, Default)]
pub struct RankingCounts {
    pub undefined: u64,
    pub low: u64,
    pub medium: u64,
    pub high: u64,
}

/// All metrics for a single file (or the _totals aggregate).
#[derive(Debug, Clone, Default)]
pub struct FileMetrics {
    pub loc: u64,
    pub nosec: u64,
    pub skipped_tests: u64,
    pub severity: RankingCounts,
    pub confidence: RankingCounts,
}

/// The top-level metrics container.
pub struct Metrics {
    /// Per-file metrics, keyed by file path.
    pub files: IndexMap<String, FileMetrics>,
    /// Aggregate totals (computed by `aggregate()`).
    pub totals: FileMetrics,
    /// The key of the currently active file (set by `begin()`).
    current_file: Option<String>,
}
```

This eliminates string-keyed dicts, enforces the schema at compile time, and makes the
`_totals` / per-file separation explicit.

---

## Appendix B: Serialisation Compatibility

Formatters that output the full `metrics.data` dict (JSON, YAML, SARIF) expect the exact
key format `"SEVERITY.HIGH"`, `"CONFIDENCE.LOW"`, etc. The Rust implementation must
serialise using these string keys for output compatibility, even if the internal
representation uses enums.

Expected JSON output shape:

```json
{
  "_totals": {
    "loc": 100,
    "nosec": 2,
    "skipped_tests": 1,
    "SEVERITY.UNDEFINED": 0,
    "SEVERITY.LOW": 3,
    "SEVERITY.MEDIUM": 1,
    "SEVERITY.HIGH": 0,
    "CONFIDENCE.UNDEFINED": 0,
    "CONFIDENCE.LOW": 0,
    "CONFIDENCE.MEDIUM": 1,
    "CONFIDENCE.HIGH": 3
  },
  "./example.py": {
    "loc": 100,
    "nosec": 2,
    "skipped_tests": 1,
    "SEVERITY.UNDEFINED": 0,
    "SEVERITY.LOW": 3,
    "SEVERITY.MEDIUM": 1,
    "SEVERITY.HIGH": 0,
    "CONFIDENCE.UNDEFINED": 0,
    "CONFIDENCE.LOW": 0,
    "CONFIDENCE.MEDIUM": 1,
    "CONFIDENCE.HIGH": 3
  }
}
```
