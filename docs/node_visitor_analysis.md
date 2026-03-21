# Comprehensive Analysis of `bandit/core/node_visitor.py`

> This document is the source of truth for rewriting `bandit.core.node_visitor.BanditNodeVisitor`
> in Rust. It covers every aspect of the class: its role in the pipeline, constructor contract,
> AST traversal model, plugin dispatch, import tracking, nosec handling, score accumulation,
> depth tracking, namespace resolution, coupling inventory, parallelism opportunities, edge cases,
> bottlenecks, and a concrete rewrite strategy.

---

## 1. Role in the Pipeline

`BanditNodeVisitor` is the **central orchestrator** of a single-file security scan. It sits between
file reading/parsing (done by `BanditManager._parse_file`) and result aggregation (done by
`Metrics.aggregate`). Its job is to walk the Python AST of one file, dispatch security plugins
against each node, and accumulate the resulting scores.

### Position in the scan pipeline

```
BanditManager.run_tests()                    # iterates over files
  |
  +-- for each file:
  |     _parse_file(fname, fdata, new_files_list)
  |       |
  |       +-- data = fdata.read()
  |       +-- lines = data.splitlines()
  |       +-- metrics.begin(fname)
  |       +-- metrics.count_locs(lines)
  |       +-- nosec_lines = tokenize + parse nosec comments
  |       +-- score = _execute_ast_visitor(fname, fdata, data, nosec_lines)
  |       |     |
  |       |     +-- res = BanditNodeVisitor(fname, fdata, metaast, testset,
  |       |     |                            debug, nosec_lines, metrics)
  |       |     +-- score = res.process(data)        # <--- THIS IS THE HOT PATH
  |       |     |     |
  |       |     |     +-- f_ast = ast.parse(data)    # Python AST parsing
  |       |     |     +-- self.generic_visit(f_ast)   # recursive tree walk
  |       |     |     |     |
  |       |     |     |     +-- for each child node:
  |       |     |     |           pre_visit(node)     # build context dict
  |       |     |     |           visit(node)         # dispatch plugins via tester
  |       |     |     |           generic_visit(node)  # recurse into children
  |       |     |     |           post_visit(node)     # clean up namespace
  |       |     |     |
  |       |     |     +-- tester.run_tests(context, "File")  # whole-file plugins
  |       |     |     +-- return self.scores
  |       |     |
  |       |     +-- results.extend(res.tester.results)
  |       |     +-- return score
  |       |
  |       +-- self.scores.append(score)
  |       +-- metrics.count_issues([score])
  |
  +-- metrics.aggregate()
```

### Lifecycle summary

1. **Constructed** once per file by `_execute_ast_visitor` (manager.py:355-363)
2. **`process(data)`** is called exactly once, which:
   - Parses the raw bytes into a Python AST via `ast.parse(data)`
   - Walks the entire tree via `generic_visit`
   - Runs whole-file plugins via `tester.run_tests(context, "File")`
   - Returns the accumulated `self.scores` dict
3. **Discarded** after `process` returns; only `tester.results` and the scores survive

The visitor is therefore a **short-lived, single-use object** — created, used, and discarded
per file. This is important for the Rust rewrite: there is no need for the Rust equivalent to
outlive a single file scan.

---

## 2. Constructor Contract

```python
def __init__(self, fname, fdata, metaast, testset, debug, nosec_lines, metrics):
```

### Parameters

| Parameter | Type | Source | Description |
|---|---|---|---|
| `fname` | `str` | `manager._parse_file` | File path being scanned (e.g. `"./example.py"` or `"<stdin>"`) |
| `fdata` | `io.BufferedReader` or `io.BytesIO` | `manager._parse_file` | Open file handle in binary mode (`"rb"`). Seekable. Used by plugins that need raw file data (e.g. `trojansource`). |
| `metaast` | `BanditMetaAst` | `manager.__init__` | Debug-only metadata AST. Receives `add_node` calls only when `debug=True`. Can be ignored in non-debug Rust path. |
| `testset` | `BanditTestSet` | `manager.__init__` | The filtered set of security plugins to run. Passed through to `BanditTester`. |
| `debug` | `bool` | `manager.__init__` | Controls verbose logging and metaast population. |
| `nosec_lines` | `dict[int, set[str] \| None]` | `manager._parse_file` | Map of line number to set of test IDs to skip (empty set = blanket nosec, `None` = no comment on that line). Built by tokenizing the file for `# nosec` comments. |
| `metrics` | `Metrics` | `manager.__init__` | Shared metrics accumulator. Passed through to `BanditTester` for `note_nosec()` / `note_skipped_test()` calls. |

### Invariants

1. `fname` must be a non-empty string.
2. `fdata` must be a seekable binary file-like object (plugins call `.seek(0)` and `.readline()`).
3. `testset` must be fully initialized — `get_tests(checktype)` must work for any valid AST node type name.
4. `nosec_lines` must be a dict. If `ignore_nosec` is `True` in the manager, this will be an empty dict.
5. `metrics` must have had `begin(fname)` called before the visitor is constructed (this happens in `_parse_file` at line 306, before `_execute_ast_visitor` at line 322).

### Constructor side effects

1. Initializes `self.scores` as `{"SEVERITY": [0,0,0,0], "CONFIDENCE": [0,0,0,0]}`.
2. Initializes `self.depth = 0`.
3. Initializes `self.imports = set()` and `self.import_aliases = {}`.
4. Creates a `BanditTester` instance at `self.tester`.
5. Resolves `self.namespace` by calling `b_utils.get_module_qualname_from_path(fname)`. This involves filesystem access (`os.path.split`, `os.path.isfile`) to walk parent directories looking for `__init__.py`. Falls back to `""` on `InvalidModulePath`.

---

## 3. AST Traversal Model

`BanditNodeVisitor` does **not** inherit from `ast.NodeVisitor`. It implements its own traversal
loop in `generic_visit`. This is a critical distinction — Python's `ast.NodeVisitor.generic_visit`
calls `self.visit(child)` which does dynamic dispatch via `getattr`. Bandit's version adds
pre/post hooks, sibling tracking, parent tracking, and depth counting.

### The traversal sequence for a single node

```
generic_visit(parent_node)
  for each field value in ast.iter_fields(parent_node):
    if value is a list:
      for each AST item in the list:
        item._bandit_sibling = next item (or None if last)
        item._bandit_parent = parent_node
        if pre_visit(item):        # (1) build context, increment depth
          visit(item)              # (2) dispatch to visit_* or run_tests
          generic_visit(item)      # (3) recurse into children
          post_visit(item)         # (4) decrement depth, pop namespace
    elif value is a single AST node:
      value._bandit_sibling = None
      value._bandit_parent = parent_node
      if pre_visit(value):
        visit(value)
        generic_visit(value)
        post_visit(value)
```

### Key observations

1. **Parent/sibling injection**: Before visiting any node, Bandit injects `_bandit_parent` and
   `_bandit_sibling` as dynamic attributes on the AST node. These are used by:
   - `visit_Str` / `visit_Bytes`: Checks `node._bandit_parent` to detect docstrings
   - `b_utils.linerange`: Uses `_bandit_sibling` for multiline string line number fixup
   - `b_utils.concat_string`: Walks up `_bandit_parent` chain for `ast.BinOp`

2. **Pre-visit always returns True**: The `pre_visit` method always returns `True` (line 216).
   There is no mechanism to skip a subtree. Every node in the AST is visited.

3. **Visit dispatch is manual**: `visit(node)` uses `getattr(self, "visit_" + name, None)` to
   find a handler. If no handler exists, it falls through to `self.tester.run_tests(self.context, name)`.
   This means **every AST node type triggers either a named visitor or a generic plugin dispatch**.

4. **Depth-first, field-order traversal**: The traversal follows `ast.iter_fields` order, which
   is the declaration order of fields in the AST grammar. This is deterministic.

---

## 4. Plugin Dispatch

### Registration flow

```
@test.test_id("B102")           # attaches func._test_id = "B102"
@test.checks("Call")            # attaches func._checks = ["Call"]
def exec_used(context):         # the plugin function
    ...
```

1. **At import time**: Plugins are discovered via stevedore entry points (`bandit.plugins` namespace).
   Each plugin function is decorated with `@test.checks(node_type)` and `@test.test_id(id)`.
   The `@checks` decorator validates node type names against `ast.AST` subclasses (or the special
   `"File"` pseudo-type).

2. **At BanditTestSet construction**: `_load_tests` iterates over all filtered plugins and builds
   `self.tests: dict[str, list[Callable]]` — a map from AST node type name to list of plugin functions.

3. **At visit time**: `BanditTester.run_tests(context, checktype)` looks up `self.testset.get_tests(checktype)`
   to get the list of plugins for that node type, then calls each one.

### Dispatch sequence (per node)

```
visit(node)
  name = node.__class__.__name__    # e.g. "Call", "Import", "FunctionDef"
  method = "visit_" + name          # e.g. "visit_Call"
  visitor = getattr(self, method, None)

  if visitor exists:
    visitor(node)
    # The visitor method itself calls:
    #   self.context[...] = ...     # enrich context
    #   self.update_scores(self.tester.run_tests(self.context, name))
  else:
    # No named visitor — run plugins directly
    self.update_scores(self.tester.run_tests(self.context, name))
```

### Node types with named visitors

| Visitor method | AST node type | What it adds to context | Plugin dispatch type |
|---|---|---|---|
| `visit_ClassDef` | `ClassDef` | Updates namespace | **No plugin dispatch** (namespace-only) |
| `visit_FunctionDef` | `FunctionDef` | `function`, `qualname`, `name`, updates namespace | `"FunctionDef"` |
| `visit_Call` | `Call` | `call`, `qualname`, `name` | `"Call"` |
| `visit_Import` | `Import` | Updates `imports`, `import_aliases`, `module` | `"Import"` |
| `visit_ImportFrom` | `ImportFrom` | Updates `imports`, `import_aliases`, `module`, `name` | `"ImportFrom"` |
| `visit_Constant` | `Constant` | Delegates to `visit_Str` or `visit_Bytes` | via delegate |
| `visit_Str` | (via Constant) | `str`, `linerange` | `"Str"` (skips docstrings) |
| `visit_Bytes` | (via Constant) | `bytes`, `linerange` | `"Bytes"` (skips docstrings) |

### Node types without named visitors (fall-through dispatch)

Any AST node type not listed above (e.g. `Assert`, `If`, `While`, `For`, `Try`, `With`,
`Assign`, `AugAssign`, `Delete`, `Global`, etc.) falls through to the `else` branch in `visit()`,
which calls `self.tester.run_tests(self.context, name)` with the raw node type name. This is how
plugins like `assert_used` (registered for `"Assert"`) get dispatched.

### The special `"File"` check type

After `generic_visit` completes, `process()` runs one final dispatch:
```python
self.tester.run_tests(self.context, "File")
```
This runs plugins like `trojansource` that inspect the whole file rather than individual AST nodes.
The context for this call has `file_data`, `filename`, `lineno=0`, `linerange=[0,1]`, `col_offset=0`.

### What plugins receive

Each plugin function receives a `Context` object (wrapping a shallow-copied dict) with these fields:

| Key | Set by | Available for |
|---|---|---|
| `imports` | `pre_visit` | All node types |
| `import_aliases` | `pre_visit` | All node types |
| `lineno` | `pre_visit` | Nodes with `lineno` attr |
| `col_offset` | `pre_visit` | Nodes with `col_offset` attr |
| `end_col_offset` | `pre_visit` | Nodes with `end_col_offset` attr |
| `node` | `pre_visit` | All node types |
| `linerange` | `pre_visit` | All node types |
| `filename` | `pre_visit` | All node types |
| `file_data` | `pre_visit` | All node types |
| `function` | `visit_FunctionDef` | `FunctionDef` only |
| `qualname` | `visit_FunctionDef`, `visit_Call` | `FunctionDef`, `Call` |
| `name` | `visit_FunctionDef`, `visit_Call`, `visit_ImportFrom` | `FunctionDef`, `Call`, `ImportFrom` |
| `call` | `visit_Call` | `Call` only |
| `module` | `visit_Import`, `visit_ImportFrom` | `Import`, `ImportFrom` |
| `str` | `visit_Str` | `Str` only |
| `bytes` | `visit_Bytes` | `Bytes` only |

### What plugins return

A plugin returns either `None` (no finding) or an `Issue` object with:
- `severity`: one of `"UNDEFINED"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`
- `confidence`: same ranking
- `cwe`: a `Cwe` object
- `text`: human-readable description
- `lineno`: optional override
- `test_id`: populated by tester from `test._test_id`

### Configurable plugins

Some plugins accept config via `@test.takes_config("config_name")`:
```python
@test.takes_config("shell_injection")
@test.checks("Call")
@test.test_id("B602")
def subprocess_popen_with_shell_equals_true(context, config):
    ...
```

The tester detects `hasattr(test, "_config")` and passes `test._config` as the second argument.
Config is loaded from the bandit config file or generated by a `gen_config()` function in the
plugin module.

---

## 5. Import Tracking

### State

```python
self.imports: set[str]           # set of fully qualified module names
self.import_aliases: dict[str, str]  # alias -> fully qualified name
```

### How imports are accumulated

| Node type | Effect on `self.imports` | Effect on `self.import_aliases` |
|---|---|---|
| `import X` | Adds `"X"` | If `import X as Y`: adds `{"Y": "X"}` |
| `import X.Y` | Adds `"X.Y"` | If `import X.Y as Z`: adds `{"Z": "X.Y"}` |
| `from X import Y` | Adds `"X.Y"` | Adds `{"Y": "X.Y"}` (even without `as`) |
| `from X import Y as Z` | Adds `"X.Y"` | Adds `{"Z": "X.Y"}` |
| `from . import Y` (relative, `node.module is None`) | Falls through to `visit_Import` logic | Same as `visit_Import` |

### Why import tracking matters

Plugins need to know the fully qualified name of what's being called. For example:
```python
import subprocess as sp
sp.Popen(cmd, shell=True)
```

Without import aliases, the `visit_Call` handler would see `sp.Popen`. With the alias map
`{"sp": "subprocess"}`, `b_utils.get_call_name` resolves this to `"subprocess.Popen"`, which
matches the plugin's blacklist.

### Shared references

`self.imports` and `self.import_aliases` are placed into the context dict at `pre_visit` time:
```python
self.context["imports"] = self.imports
self.context["import_aliases"] = self.import_aliases
```

These are **reference aliases** — the context dict holds the same `set` and `dict` objects as
`self`. Mutations in `visit_Import`/`visit_ImportFrom` are visible to subsequent plugin calls
within the same file. The `copy.copy(raw_context)` in `BanditTester.run_tests` creates a
shallow copy, so the inner set/dict objects are still shared. This is intentional — plugins
should see all imports accumulated so far.

---

## 6. Nosec Handling

### Data structure

`nosec_lines: dict[int, set[str]]` maps line numbers to sets of test IDs to skip:
- **Key absent**: No nosec comment on this line
- **Key present, empty set**: Blanket `# nosec` — skip all findings on this line
- **Key present, non-empty set**: `# nosec B602,B603` — skip only those specific test IDs

### Where nosec is checked

Nosec suppression happens inside `BanditTester.run_tests`, **after** a plugin returns a non-None
result (tester.py:56-94):

```python
result = test(context)
if result is not None:
    nosec_tests_to_skip = self._get_nosecs_from_contexts(temp_context, test_result=result)
    ...
    if nosec_tests_to_skip is not None:
        if not nosec_tests_to_skip:
            # Blanket nosec: skip everything, count it
            self.metrics.note_nosec()
            continue
        if result.test_id in nosec_tests_to_skip:
            # Specific nosec: skip this test, count it
            self.metrics.note_skipped_test()
            continue
    # No nosec: record the result
    self.results.append(result)
```

### Nosec resolution

`_get_nosecs_from_contexts` combines two sources:
1. **`test_result.lineno`**: The line where the issue was found (direct lookup)
2. **`context["linerange"]`**: All lines in the node's range (broader lookup via `utils.get_nosec`)

If either source yields a nosec set, they are unioned. This handles cases where a nosec comment
is on a different line within the same statement.

### Important: Nosec is NOT checked during traversal

The visitor itself does not check nosec. It unconditionally visits every node and dispatches
every plugin. Suppression happens entirely in the tester, after the plugin has already executed
and returned a result. This means:
- Plugin execution cost is paid even for suppressed lines
- The nosec check is a post-filter, not a pre-filter
- A Rust rewrite could potentially short-circuit this by checking nosec before dispatch

---

## 7. Score Accumulation

### Score structure

```python
self.scores = {
    "SEVERITY": [0, 0, 0, 0],      # indexed by RANKING position
    "CONFIDENCE": [0, 0, 0, 0],     # [UNDEFINED, LOW, MEDIUM, HIGH]
}
```

### How scores are updated

`update_scores` is called after every `tester.run_tests` call:

```python
def update_scores(self, scores):
    for score_type in self.scores:
        self.scores[score_type] = list(
            map(operator.add, self.scores[score_type], scores[score_type])
        )
```

The tester returns a scores dict with the same shape. For each issue found, the tester adds
the weighted value (`RANKING_VALUES[severity]`) to the appropriate index:

```python
sev = constants.RANKING.index(result.severity)      # e.g. 3 for "HIGH"
val = constants.RANKING_VALUES[result.severity]       # e.g. 10 for "HIGH"
scores["SEVERITY"][sev] += val                        # scores["SEVERITY"][3] += 10
```

### Score flow

```
Per-node scores (from tester.run_tests)
  → update_scores accumulates into self.scores
    → process() returns self.scores
      → manager stores in self.scores list
        → manager passes [score] to metrics.count_issues
```

### Performance note

`update_scores` creates a new list on every call via `list(map(...))`. For a file with N nodes,
this creates 2N temporary lists. In Rust, this would be a simple in-place addition of two
fixed-size arrays.

---

## 8. The `process()` Method

```python
def process(self, data):
    f_ast = ast.parse(data)             # (1) Parse bytes to AST
    self.generic_visit(f_ast)           # (2) Walk the tree
    # Run whole-file plugins:
    self.context = {                    # (3) Build file-level context
        "file_data": self.fdata,
        "filename": self.fname,
        "lineno": 0,
        "linerange": [0, 1],
        "col_offset": 0,
    }
    self.update_scores(                 # (4) Dispatch "File" plugins
        self.tester.run_tests(self.context, "File")
    )
    return self.scores                  # (5) Return accumulated scores
```

### What `process` does beyond `generic_visit`

1. **AST parsing**: `ast.parse(data)` takes raw bytes (the file content). Python handles encoding
   detection (BOM, coding declarations). This is the most expensive single operation in the
   pipeline.

2. **File-level plugins**: After the tree walk, `process` runs plugins registered for `"File"`.
   These see the whole file data, not individual nodes. Currently only `trojansource` uses this.

3. **Return value**: The scores dict is returned to the manager, which appends it to
   `self.scores` and passes it to `metrics.count_issues([score])`.

---

## 9. Depth Tracking

```python
# In __init__:
self.depth = 0

# In pre_visit:
self.depth += 1

# In post_visit:
self.depth -= 1
```

### What depth is used for

1. **Debug logging**: `pre_visit` logs the depth in debug messages (line 212-213).
2. **MetaAST**: When `debug=True`, `self.metaast.add_node(node, "", self.depth)` records the
   depth for visualization.

### Not used for

- Depth is **not** used for any security analysis or plugin dispatch.
- Depth is **not** used to limit recursion or skip subtrees.

For a non-debug Rust rewrite, depth tracking can be omitted entirely.

---

## 10. Namespace Resolution

### Initial namespace

```python
try:
    self.namespace = b_utils.get_module_qualname_from_path(fname)
except b_utils.InvalidModulePath:
    self.namespace = ""
```

`get_module_qualname_from_path` walks up the directory tree from `fname` looking for `__init__.py`
files to construct a dotted module path. For example:
- `./bandit/core/manager.py` → `"bandit.core.manager"`
- `./example.py` → `"example"`
- `<stdin>` → raises `InvalidModulePath` → `""`

### Namespace mutations during traversal

| Event | Mutation |
|---|---|
| `visit_ClassDef(node)` | `self.namespace = namespace_path_join(self.namespace, node.name)` |
| `visit_FunctionDef(node)` | `self.namespace = namespace_path_join(self.namespace, name)` |
| `post_visit(node)` where `isinstance(node, (FunctionDef, ClassDef))` | `self.namespace = namespace_path_split(self.namespace)[0]` |

This creates a stack-like behavior: entering a class/function appends to the namespace,
leaving it pops the last component. This ensures that `qualname` in `visit_FunctionDef`
reflects the full `module.class.method` path.

### What namespace is used for

- **`visit_FunctionDef`**: Constructs `qualname = self.namespace + "." + get_func_name(node)`,
  which is placed in the context for plugins to match against.
- **`visit_ClassDef`**: Only updates namespace for descendants; does not dispatch plugins itself.

---

## 11. Coupling Inventory

These are the Python-specific dependencies that would need explicit handling in a Rust rewrite:

### 11.1 `ast.NodeVisitor` inheritance — NOT USED

`BanditNodeVisitor` does **not** inherit from `ast.NodeVisitor`. It implements its own traversal.
This is actually helpful for a Rust rewrite — there's no base class contract to satisfy.

### 11.2 Dynamic dispatch via `getattr`

```python
visitor = getattr(self, "visit_" + name, None)
```

The `visit()` method uses string-based dynamic dispatch to find visitor methods. In Rust, this
would be a `match` statement on the node type name string, or a `HashMap<String, fn>`.

### 11.3 Decorator-based plugin registration

```python
@test.checks("Call")
@test.test_id("B102")
def exec_used(context):
    ...
```

Plugins are Python functions with attributes (`_checks`, `_test_id`, `_config`) attached by
decorators. They are discovered at runtime by stevedore via entry points. **Plugins must remain
as Python callables** — they use Python AST nodes, Python string operations, and arbitrary
Python logic. A Rust rewrite cannot reimplement plugins in Rust without rewriting all ~40 plugins.

### 11.4 Python AST node types

The entire traversal operates on `ast.AST` nodes — Python objects with dynamic attributes.
Key dependencies:
- `ast.parse(data)`: Parsing bytes into an AST
- `ast.iter_fields(node)`: Getting child nodes
- `node.__class__.__name__`: Determining node type
- `node.lineno`, `node.col_offset`, `node.end_lineno`, `node.end_col_offset`: Location info
- `node.args`, `node.func`, `node.names`, `node.module`, `node.name`, `node.value`: Type-specific fields
- `node._bandit_parent`, `node._bandit_sibling`: Injected attributes

### 11.5 `copy.copy(raw_context)` in tester

The tester shallow-copies the context dict before passing it to each plugin. This prevents
plugins from interfering with each other's context, but the inner objects (imports, import_aliases,
AST nodes) are still shared references.

### 11.6 `Context` class wrapping

The raw context dict is wrapped in a `Context` object that provides properties like
`call_function_name`, `call_args`, `call_keywords`, etc. These properties access the raw AST
node and perform Python-specific operations (attribute access on AST nodes, isinstance checks).

### 11.7 `operator.add` and `map` in `update_scores`

```python
self.scores[score_type] = list(map(operator.add, self.scores[score_type], scores[score_type]))
```

Element-wise addition of two lists. Trivial to replace with array addition in Rust.

### 11.8 String-based namespace operations

```python
b_utils.namespace_path_join(base, name)  → f"{base}.{name}"
b_utils.namespace_path_split(path)       → tuple(path.rsplit(".", 1))
```

Simple string operations, trivially replicable in Rust.

### 11.9 Filesystem access for namespace resolution

```python
b_utils.get_module_qualname_from_path(fname)
```

Walks parent directories looking for `__init__.py`. Uses `os.path.split`, `os.path.isfile`.

---

## 12. Parallelism Opportunity

### Current state: Strictly sequential

`BanditManager.run_tests()` iterates over files in a simple `for` loop (manager.py:277).
Each file is processed completely before the next one starts.

### Shared mutable state analysis

| State | Owned by | Shared? | Mutable? | Parallelism risk |
|---|---|---|---|---|
| `BanditNodeVisitor` | Per-file (created and discarded) | No | Yes | **None** — each file gets its own visitor |
| `BanditTester` | Per-visitor (created in constructor) | No | Yes | **None** — each file gets its own tester |
| `self.tester.results` | Per-tester | No | Yes (appended) | **None** — results are collected after process() |
| `Metrics` | `BanditManager` | **Yes** — shared via reference | **Yes** — `note_nosec`, `note_skipped_test` | **RISK** — concurrent writes to same metrics instance |
| `BanditMetaAst` | `BanditManager` | **Yes** — shared via reference | **Yes** — `add_node` | **RISK** — but only used in debug mode |
| `manager.results` | `BanditManager` | **Yes** | **Yes** — `extend` | **RISK** — concurrent list extension |
| `manager.scores` | `BanditManager` | **Yes** | **Yes** — `append` | **RISK** — concurrent list append |
| `manager.skipped` | `BanditManager` | **Yes** | **Yes** — `append` | **RISK** — concurrent list append |
| `manager.files_list` | `BanditManager` | **Yes** | **Yes** — `remove` | **RISK** — concurrent modification |

### What would need to change for parallel file processing

1. **Metrics**: Replace shared `Metrics` with per-file score accumulation, then merge after
   all files complete. The Rust `Metrics` already uses native structs that could be per-thread.
   `note_nosec` and `note_skipped_test` could be per-file counters merged at the end.

2. **Results collection**: Each file produces a list of `Issue` objects. These could be collected
   in a per-file `Vec` and concatenated after all files complete.

3. **BanditNodeVisitor**: Already per-file and stateless across files. No changes needed.

4. **BanditTester**: Already per-visitor. No changes needed.

5. **GIL consideration**: If plugins remain as Python callables, the GIL prevents true
   parallelism for CPU-bound plugin execution. However, if the inner visit loop is in Rust
   and releases the GIL for pure-Rust operations (context building, namespace tracking,
   import alias resolution), then file I/O and AST parsing could overlap with plugin execution
   on other threads via `py.allow_threads(|| ...)`.

### Conclusion

Parallelism across files is architecturally feasible. The main barriers are:
1. **Shared mutable state**: Solvable by accumulating per-file and merging
2. **GIL**: The bottleneck. Plugins are Python code that holds the GIL. True speedup requires
   either (a) multi-process parallelism, or (b) moving enough work into Rust to make GIL-free
   sections meaningful.

---

## 13. Edge Cases

### 13.1 Empty files

- `ast.parse(b"")` succeeds and returns a `Module` node with an empty body.
- `generic_visit` of an empty module iterates zero fields → no nodes visited.
- `process` still runs the `"File"` check type.
- `metrics.count_locs([])` records `loc = 0`.
- Result: valid, zero-score output.

### 13.2 Files that fail to parse

- `ast.parse(data)` raises `SyntaxError`.
- Caught by `_parse_file` (manager.py:327). File is added to `skipped` with reason
  `"syntax error while parsing AST from file"`.
- `metrics.count_issues` is **never called** for this file (it's after the try block).
- The file's `loc` and `nosec` counts from `metrics.begin/count_locs` **persist** in metrics
  (they were recorded before parsing).

### 13.3 Files with only comments

- `ast.parse(b"# just comments\n# nothing here\n")` succeeds (empty module body).
- `metrics.count_locs` counts 0 lines (comments are excluded).
- No AST nodes to visit → no plugin dispatch.
- Result: valid, zero-score output with `loc = 0`.

### 13.4 Deeply nested ASTs

- Python's `ast.parse` has a default recursion limit (usually tied to `sys.getrecursionlimit`).
- `generic_visit` is recursive — deeply nested ASTs (100+ levels) could hit Python's stack limit.
- In practice, Python source files rarely exceed 20-30 levels of nesting.
- A Rust rewrite could use iterative traversal with an explicit stack to avoid this limitation.

### 13.5 Wildcard imports (`from X import *`)

- `visit_ImportFrom`: `node.names` contains a single `alias` with `name="*"` and `asname=None`.
- `self.imports.add(module + "." + "*")` adds e.g. `"os.*"`.
- `self.import_aliases["*"] = module + "." + "*"` adds a wildcard alias.
- This is partially correct — the alias resolution won't resolve individual names from
  wildcard imports. This is a known limitation documented in a TODO in the code.

### 13.6 `from . import Y` (relative imports with `node.module is None`)

- `visit_ImportFrom` detects `module is None` and delegates to `visit_Import(node)`.
- `visit_Import` iterates `node.names` and adds them without a module prefix.

### 13.7 Nosec on a line with no issues

- The nosec comment is still parsed and stored in `nosec_lines`.
- If a test produces `result is None` (no issue found) but the line has a nosec comment with
  a specific test ID, the tester logs a warning: `"nosec encountered (BXXX), but no failed test"`.
- No metrics are affected.

### 13.8 `visit_Constant` node type mapping

- Python 3.8+ unified `Str`, `Bytes`, `Num`, `NameConstant`, `Ellipsis` into `Constant`.
- `visit_Constant` checks `isinstance(node.value, str)` → delegates to `visit_Str`.
- `visit_Constant` checks `isinstance(node.value, bytes)` → delegates to `visit_Bytes`.
- Other Constant types (int, float, bool, None, Ellipsis) are **not** delegated — they fall
  through and get generic plugin dispatch via the `else` branch of `visit()`.
- Wait — actually no. `visit_Constant` is the visitor method, so `visit()` calls it. After
  `visit_Constant` returns, control goes back to `generic_visit` → `post_visit`. If
  `visit_Constant` doesn't call `tester.run_tests` for non-str/non-bytes constants, those
  constants get **no plugin dispatch at all** (neither via the named visitor nor the fallthrough).

### 13.9 `visit_Str` and `visit_Bytes` docstring suppression

- If `node._bandit_parent` is an `ast.Expr`, the string/bytes is treated as a docstring and
  plugin dispatch is **skipped**.
- This prevents false positives on docstrings that contain suspicious patterns.

---

## 14. Bottlenecks

### 14.1 `ast.parse(data)` — AST parsing

**Estimated share: 40-60% of per-file time.**

This is the single most expensive operation. Python's parser processes the entire file, builds
an AST tree of Python objects, and allocates memory for every node. This is pure CPython C code
and cannot be accelerated from Python.

A Rust-native parser (e.g. `rustpython-parser`, `ruff_python_parser`) could potentially be
faster, but would produce Rust AST nodes that are incompatible with Python plugins expecting
`ast.AST` objects.

### 14.2 Plugin dispatch overhead — `BanditTester.run_tests`

**Estimated share: 20-30% of per-file time.**

For each node, `run_tests`:
1. Looks up `self.testset.get_tests(checktype)` — dict lookup, fast
2. For each matching plugin:
   a. `copy.copy(raw_context)` — shallow copy of a dict with ~10 keys
   b. `Context(temp_context)` — object construction
   c. `test(context)` or `test(context, config)` — Python function call
   d. Nosec checking — dict lookups and set operations
   e. Score accumulation — index lookup and integer addition

The overhead is dominated by Python function call overhead and object construction, not by
the actual security logic.

### 14.3 Context object construction — `pre_visit`

**Estimated share: 10-15% of per-file time.**

`pre_visit` runs for **every** node in the AST. It:
1. Creates a fresh dict: `self.context = {}`
2. Populates 8+ keys
3. Calls `b_utils.linerange(node)` — which may recursively compute line ranges
4. Does `hasattr` checks for optional node attributes

For a file with 500 AST nodes, this means 500 dict allocations and 4000+ key insertions.

### 14.4 `update_scores` — list creation

**Estimated share: 2-5% of per-file time.**

```python
self.scores[score_type] = list(map(operator.add, self.scores[score_type], scores[score_type]))
```

Creates 2 new lists per call. For 500 nodes, that's 1000 temporary lists. In Rust, this is
a trivial in-place `[i64; 4]` addition.

### 14.5 Parent/sibling injection — `generic_visit`

**Estimated share: 5-10% of per-file time.**

Setting `_bandit_parent` and `_bandit_sibling` on AST nodes involves Python attribute assignment
on C-level objects (AST nodes are C structs in CPython). This is moderately expensive due to
the descriptor protocol and `__dict__` manipulation.

### 14.6 `get_module_qualname_from_path` — filesystem access

**Estimated share: <1% of per-file time (amortized).**

Called once per file in the constructor. Involves `os.path.split` and `os.path.isfile` calls
walking up the directory tree. Fast in practice but involves syscalls.

### Summary: Where time is actually spent

```
ast.parse(data)                          ████████████████████  40-60%
Plugin dispatch (tester.run_tests)       ██████████            20-30%
Context construction (pre_visit)         █████                 10-15%
Parent/sibling injection (generic_visit) ███                   5-10%
Score accumulation (update_scores)       █                     2-5%
Namespace resolution, imports            ░                     <2%
```

---

## 15. Rewrite Strategy

### Question 1: Can the plugin system be preserved as-is?

**Recommendation: YES — preserve plugins as Python callables called from Rust via PyO3.**

Rationale:
- There are ~40 plugin functions spread across ~30 files. Each one uses Python `ast` nodes,
  Python string operations, and Python control flow. Rewriting them all in Rust would be a
  massive effort with high regression risk.
- Plugins are the **extensibility point** of bandit — third-party plugins exist and must
  continue to work.
- The plugin execution itself is not the bottleneck. The overhead is in the dispatch
  infrastructure (context building, dict copying, nosec checking), not in the plugin logic.
- PyO3 can call Python functions efficiently. The context dict can be built in Rust and
  passed as a `Py<PyDict>` to the Python plugin.

**Implementation**: Keep `BanditTester` and `Context` as Python classes. Rust calls
`tester.run_tests(context, checktype)` via PyO3 for each node. The Rust side handles
traversal, context building, namespace tracking, and score accumulation.

### Question 2: Should Python's `ast` module be used or a Rust-native parser?

**Recommendation: Use Python's `ast.parse` and keep the tree as Python objects.**

Rationale:
- Plugins directly access `ast.AST` node attributes (`node.func`, `node.args`,
  `node.keywords`, `node.value`, etc.). If a Rust parser produces Rust AST nodes, every
  plugin would need a translation layer or rewrite.
- `ast.parse` handles encoding detection, `coding:` declarations, and produces the exact
  same node types that plugins expect.
- The cost of `ast.parse` is unavoidable if plugins need Python AST nodes. Using a Rust
  parser would mean parsing twice (once in Rust for traversal, once in Python for plugins)
  or building a complex interop layer.
- `ast.parse` is implemented in C and is already reasonably fast. The speedup from a Rust
  parser would be modest (maybe 2x) and not worth the compatibility risk.

**Implementation**: Call `ast.parse(data)` from Rust via PyO3 (`py.import("ast")?.call_method1("parse", (data,))?`).
The returned `Module` node is a Python object that Rust traverses via `iter_fields`.

### Question 3: What is the minimal Rust surface for the biggest performance gain?

**Recommendation: Rewrite the inner visit loop (`generic_visit` + `pre_visit` + `visit` +
`post_visit` + `update_scores`) in Rust. Keep everything else in Python.**

This targets the 30-40% of time spent on traversal infrastructure:

| Component | Current (Python) | After (Rust) | Savings |
|---|---|---|---|
| `generic_visit` loop | Python `for` loop with `isinstance` checks | Rust match + iteration | 5-10% |
| `pre_visit` context building | Python dict allocation + key insertion | Rust struct or pre-allocated dict | 10-15% |
| `visit` dispatch | `getattr` string lookup | Rust `match` on node type | 2-3% |
| `update_scores` | `list(map(operator.add, ...))` | `[i64; 4]` in-place add | 2-5% |
| Parent/sibling injection | Python attribute assignment | Rust `HashMap<usize, (usize, usize)>` tracking | 5-10% |
| Namespace tracking | Python string concat/split | Rust `String` push/pop | <1% |
| Import tracking | Python `set.add` / `dict.__setitem__` | Keep as Python (shared with plugins) | 0% |

**Expected speedup**: 1.3-1.5x on the overall per-file processing time. This is modest
because `ast.parse` (40-60%) and plugin execution (20-30%) remain in Python.

**What the Rust visit loop would look like**:

```rust
#[pyclass]
struct RustNodeVisitor {
    scores: [[i64; 4]; 2],          // SEVERITY + CONFIDENCE
    depth: u32,
    namespace: String,
    fname: String,
}

#[pymethods]
impl RustNodeVisitor {
    fn process(&mut self, py: Python, data: &[u8], tester: &PyAny, ...) -> PyResult<PyObject> {
        let ast = py.import("ast")?;
        let tree = ast.call_method1("parse", (data,))?;
        self.generic_visit(py, &tree, tester)?;
        // File-level dispatch
        let ctx = self.build_file_context(py)?;
        let scores = tester.call_method1("run_tests", (ctx, "File"))?;
        self.update_scores(py, &scores)?;
        Ok(self.scores_to_py(py)?)
    }

    fn generic_visit(&mut self, py: Python, node: &PyAny, tester: &PyAny) -> PyResult<()> {
        let ast = py.import("ast")?;
        let fields = ast.call_method1("iter_fields", (node,))?;
        for field in fields.iter()? {
            let (_, value) = field?.extract::<(String, PyObject)>()?;
            // Check if list or single AST node, recurse...
        }
        Ok(())
    }
}
```

### Question 4: Is parallelism across files achievable?

**Recommendation: YES, but with significant caveats. Pursue multi-process parallelism first,
then consider GIL-releasing Rust if the inner loop is rewritten.**

#### Option A: Multi-process parallelism (easiest, biggest win)

Use `multiprocessing.Pool` or `concurrent.futures.ProcessPoolExecutor` to scan files in
parallel across multiple Python processes. Each process gets its own GIL, AST parser, and
plugin set.

**Changes required**:
1. `BanditManager.run_tests()`: Replace the `for` loop with a process pool
2. Each worker: creates its own `BanditNodeVisitor` + `BanditTester`, processes one file,
   returns `(scores, results, metrics_delta)` as serializable data
3. Manager: merges results, scores, and metrics from all workers

**Expected speedup**: Near-linear with core count for I/O-bound workloads. On an 8-core
machine scanning 1000 files, expect 4-6x speedup.

**Risks**: Plugin state (config, extension manager) must be pickle-serializable or
re-initialized per process. The `extension_loader.MANAGER` singleton would need to be
reconstructed in each worker process.

#### Option B: GIL-releasing Rust inner loop (harder, modest win)

If the inner visit loop is rewritten in Rust, the GIL can be released during:
- Namespace resolution (pure string operations)
- Score accumulation (pure integer operations)
- Depth tracking (pure integer operations)

But the GIL must be re-acquired for:
- `ast.iter_fields(node)` — accessing Python AST objects
- `tester.run_tests(context, checktype)` — calling Python plugins
- Building the context dict — creating Python dict objects

Since the GIL-requiring operations dominate, the GIL-free sections would be too small to
enable meaningful thread-level parallelism.

#### Option C: Full Rust pipeline (hardest, biggest long-term win)

Replace `ast.parse` with a Rust-native parser, traverse in Rust, and only call Python plugins
via PyO3. This would allow:
- Parsing multiple files in parallel (no GIL needed for Rust parsing)
- Releasing the GIL during traversal
- Only acquiring the GIL when calling Python plugins

**This is the long-term vision but requires**:
1. A Rust Python parser that produces nodes compatible with Python plugin expectations
   (or an adapter layer)
2. Reimplementing `Context`, `utils.linerange`, `utils.get_call_name`, etc. in Rust
3. Significant testing to ensure plugin compatibility

### Recommended phased approach

```
Phase 1 (this PR): Analysis document (this file)
Phase 2: Rewrite inner visit loop in Rust (generic_visit, pre_visit, visit, post_visit)
         Keep ast.parse and plugin dispatch in Python
         Expected: 1.3-1.5x speedup on per-file processing
Phase 3: Add multi-process parallelism at the manager level
         Expected: 4-6x additional speedup (multiplicative with Phase 2)
Phase 4: (Optional) Replace ast.parse with Rust-native parser
         Expected: 1.5-2x additional speedup on parsing
         Risk: Plugin compatibility
```

---

## Appendix A: Complete Method Reference

### `__init__(self, fname, fdata, metaast, testset, debug, nosec_lines, metrics)`
Constructor. See §2.

### `visit_ClassDef(self, node)`
Appends `node.name` to `self.namespace`. Does NOT dispatch plugins.

### `visit_FunctionDef(self, node)`
Sets `context["function"]`, `context["qualname"]`, `context["name"]`.
Appends function name to namespace.
Dispatches plugins for `"FunctionDef"`.

### `visit_Call(self, node)`
Sets `context["call"]`, `context["qualname"]`, `context["name"]`.
Dispatches plugins for `"Call"`.

### `visit_Import(self, node)`
Updates `self.imports` and `self.import_aliases`.
Sets `context["module"]`.
Dispatches plugins for `"Import"`.

### `visit_ImportFrom(self, node)`
Delegates to `visit_Import` if `node.module is None`.
Otherwise updates imports/aliases with module prefix.
Sets `context["module"]`, `context["name"]`.
Dispatches plugins for `"ImportFrom"`.

### `visit_Constant(self, node)`
Delegates to `visit_Str` if `node.value` is `str`.
Delegates to `visit_Bytes` if `node.value` is `bytes`.
Does nothing for other constant types (int, float, bool, None, Ellipsis).

### `visit_Str(self, node)`
Sets `context["str"]`. Skips docstrings (parent is `ast.Expr`).
Dispatches plugins for `"Str"`.

### `visit_Bytes(self, node)`
Sets `context["bytes"]`. Skips docstrings (parent is `ast.Expr`).
Dispatches plugins for `"Bytes"`.

### `pre_visit(self, node)`
Builds fresh context dict with imports, aliases, location info, node, linerange, filename, file_data.
Increments depth. Always returns `True`.

### `visit(self, node)`
Dispatches to named visitor if one exists, otherwise falls through to `tester.run_tests`.

### `post_visit(self, node)`
Decrements depth. Pops namespace for `FunctionDef`/`ClassDef` nodes.

### `generic_visit(self, node)`
Recursive traversal of all child nodes via `ast.iter_fields`.
Injects `_bandit_parent` and `_bandit_sibling` on each child.

### `update_scores(self, scores)`
Element-wise addition of scores from `tester.run_tests` into `self.scores`.

### `process(self, data)`
Entry point. Parses AST, walks tree, runs file-level plugins, returns scores.

---

## Appendix B: AST Node Types and Plugin Coverage

### Node types with >0 registered plugins (from default bandit test set)

| AST Node Type | Plugin Count | Example Plugins |
|---|---|---|
| `Call` | ~15 | B102 (exec), B201 (flask_debug), B602-B607 (shell injection), B301-B303 (pickle) |
| `Import` | ~3 | B401-B412 (blacklist imports) |
| `ImportFrom` | ~3 | B401-B412 (blacklist imports) |
| `FunctionDef` | 0 | (no direct plugins, but namespace tracking) |
| `Str` | ~3 | B105 (hardcoded password string), B108 (hardcoded tmp) |
| `Bytes` | ~1 | B105 (hardcoded password bytes) |
| `Assert` | 1 | B101 (assert_used) |
| `ExceptHandler` | 2 | B110 (try_except_pass), B112 (try_except_continue) |
| `File` | 1 | B613 (trojansource) |

### Node types visited but with 0 plugins

Most AST node types (`If`, `While`, `For`, `With`, `Assign`, `Return`, `Yield`, `BoolOp`,
`BinOp`, `UnaryOp`, `Lambda`, `ListComp`, `SetComp`, `DictComp`, `GeneratorExp`, etc.) are
visited by `generic_visit` but have no registered plugins. The `visit()` fallthrough calls
`tester.run_tests(self.context, name)` which returns a zero-score dict.

**Optimization opportunity**: In Rust, skip the `tester.run_tests` call entirely if the
testset has no plugins registered for the node type. This avoids the Python function call
overhead for the majority of AST nodes. The check is: `if self.testset.get_tests(name)` is
empty (or the Rust side caches which node types have plugins).

---

## Appendix C: Data Flow Diagram

```
                          ┌──────────────────────────────┐
                          │     BanditManager            │
                          │                              │
                          │  files_list ──┐              │
                          │  metrics ─────┼──────────┐   │
                          │  results ─────┼────────┐ │   │
                          │  scores ──────┼──────┐ │ │   │
                          │  b_ts ────────┼────┐ │ │ │   │
                          │  b_ma ────────┼──┐ │ │ │ │   │
                          └───────────────┼──┼─┼─┼─┼─┼───┘
                                          │  │ │ │ │ │
                   _parse_file(fname)     │  │ │ │ │ │
                          │               │  │ │ │ │ │
                          ▼               │  │ │ │ │ │
              ┌───────────────────────┐   │  │ │ │ │ │
              │  BanditNodeVisitor    │◄──┼──┼─┼─┼─┘ │
              │                       │   │  │ │ │   │
              │  fname ◄──────────────┼───┘  │ │ │   │
              │  metaast ◄────────────┼──────┘ │ │   │
              │  testset ◄────────────┼────────┘ │   │
              │  metrics ◄────────────┼──────────┼───┘
              │  nosec_lines          │          │
              │  imports: set         │          │
              │  import_aliases: dict │          │
              │  namespace: str       │          │
              │  scores: dict         │──────────┘
              │  depth: int           │     (returned via process())
              │                       │
              │  tester ──────────────┼──┐
              └───────────────────────┘  │
                                         │
              ┌──────────────────────────┘
              │
              ▼
              ┌───────────────────────┐
              │  BanditTester         │
              │                       │
              │  testset ─────────────┼──► BanditTestSet.get_tests(checktype)
              │  nosec_lines          │         │
              │  metrics ─────────────┼──► note_nosec() / note_skipped_test()
              │  results: list[Issue] │         │
              │                       │         ▼
              │  run_tests(ctx, type) │    ┌────────────────┐
              │    │                  │    │  Plugin func    │
              │    ├─ get_tests(type) │    │  (Python)       │
              │    ├─ copy context    │    │                 │
              │    ├─ Context(ctx)    │    │  context ──►    │
              │    ├─ call plugin ────┼──► │  → Issue | None │
              │    ├─ check nosec     │    └────────────────┘
              │    └─ accumulate score│
              └───────────────────────┘
```

---

## 16. Test Coverage

### 16.1 Test command and results

```
$ stestr run
Ran: 273 tests in 3.39 sec. — Passed: 273
```

All 273 tests pass on the current codebase (branch `feat/node-visitor-rust`, parent `main`).

### 16.2 Coverage summary

```
$ python -m pytest tests/ --cov=bandit.core.node_visitor --cov-report=term-missing --cov-branch

Name                          Stmts   Miss Branch BrPart  Cover   Missing
-------------------------------------------------------------------------
bandit/core/node_visitor.py     143      6     50      6    94%   40-44, 185->exit, 195-196, 224, 244->243, 251->243, 259->240
```

**143 statements, 137 covered (96% statement). 50 branches, 44 covered (88% branch). Combined: 94%.**

### 16.3 Uncovered lines analysis

| Lines | Code | Why uncovered |
|---|---|---|
| **40-44** | `except b_utils.InvalidModulePath: LOG.warning(...); self.namespace = ""` | No test provides a `fname` that triggers `InvalidModulePath`. All functional tests use real file paths under `examples/` which resolve correctly. |
| **185→exit** | `visit_Bytes`: the `if not isinstance(node._bandit_parent, ast.Expr)` branch where it IS an `ast.Expr` (docstring bytes) | No example file contains a bytes literal docstring (`b"..."` as a standalone expression). |
| **195-196** | `if self.debug: LOG.debug(ast.dump(node)); self.metaast.add_node(...)` | No test runs with `debug=True`. All functional tests use `debug=False` (the manager default). |
| **224** | `if self.debug: LOG.debug(...)` inside `visit()` | Same — no test runs with `debug=True`. |
| **244→243** | `generic_visit` inner loop: branch where `isinstance(item, ast.AST)` is `False` | This branch fires when a list field contains non-AST items (e.g. `ast.arguments.defaults` can contain non-AST values in some edge cases). Most list fields do contain only AST nodes. |
| **251→243** | `generic_visit`: `if self.pre_visit(item)` returning `False` | `pre_visit` always returns `True` (line 216), so this branch is dead code. Never exercised. |
| **259→240** | `generic_visit`: `if self.pre_visit(value)` returning `False` (single-value branch) | Same — `pre_visit` always returns `True`. Dead code. |

### 16.4 Test inventory

There are **no direct unit tests** for `BanditNodeVisitor`. All coverage comes from **functional tests** that drive the full pipeline through `BanditManager.run_tests()` → `_parse_file` → `_execute_ast_visitor` → `BanditNodeVisitor.process()`.

#### Functional tests (tests/functional/test_functional.py)

All 67 functional tests exercise `BanditNodeVisitor` implicitly via the full pipeline. The table below categorises them by which node_visitor code paths they cover:

| Test | Example file | AST node types exercised | Tests nosec? | Tests import tracking? | Tests score accumulation? |
|---|---|---|---|---|---|
| `test_skip` | `skip.py` | `Call` | **Yes** — blanket `#nosec` and `#noqa` | No (no imports) | Yes |
| `test_ignore_skip` | `skip.py` (with `ignore_nosec=True`) | `Call` | **Yes** — verifies nosec is ignored | No | Yes |
| `test_nosec` | `nosec.py` | `Call`, `Import`, `ImportFrom` | **Yes** — blanket `#nosec`, specific `#nosec B602`, `#nosec B607,B602`, by-name nosec | Yes (subprocess, cryptography imports) | Yes |
| `test_multiline_sql_statements` | `sql_multiline_statements.py` | `Call`, `Import`, `FunctionDef`, `Str` | **Yes** — `#nosec` and `#nosec B608` on multiline strings | Yes (`import sqlalchemy`) | **Yes** — also tests `check_metrics` with exact nosec/skipped counts |
| `test_metric_gathering` | `skip.py`, `imports.py` | `Call`, `Import` | **Yes** — verifies nosec count in metrics | Yes (`imports.py` tests import-based detection) | **Yes** — exact metric values verified |
| `test_imports_aliases` | `imports-aliases.py` | `Call`, `Import`, `ImportFrom` | No | **Yes** — `import X as Y`, `from X import Y as Z` | Yes |
| `test_imports_from` | `imports-from.py` | `Import`, `ImportFrom` | No | **Yes** — `from X import Y`, relative imports (`from . import`, `from .. import`) | Yes |
| `test_imports_function` | `imports-function.py` | `Call`, `Import` | No | **Yes** — `__import__()` | Yes |
| `test_imports` | `imports.py` | `Import` | No | **Yes** — dangerous module imports | Yes |
| `test_imports_using_importlib` | `imports-with-importlib.py` | `Call`, `Import` | No | **Yes** — `importlib.import_module()` | Yes |
| `test_exec` | `exec.py` | `Call` | No | No | Yes |
| `test_eval` | `eval.py` | `Call` | No | No | Yes |
| `test_asserts` | `assert.py` | `Assert` | No | No | Yes (also tests config-based skip) |
| `test_subprocess_shell` | `subprocess_shell.py` | `Call`, `Import` | No | Yes (subprocess) | Yes |
| `test_flask_debug_true` | `flask_debug.py` | `Call`, `Import` | No | Yes (flask) | Yes |
| `test_hardcoded_passwords` | `hardcoded-passwords.py` | `Str`, `Call`, `Assign` | No | No | Yes |
| `test_hardcoded_tmp` | `hardcoded-tmp.py` | `Str` | No | No | Yes |
| `test_try_except_continue` | `try_except_continue.py` | `ExceptHandler` | No | No | Yes (with config toggling) |
| `test_try_except_pass` | `try_except_pass.py` | `ExceptHandler` | No | No | Yes (with config toggling) |
| `test_nonsense` | `nonsense.py` | **None** (SyntaxError) | No | No | No — tests parse failure path |
| `test_okay` | `okay.py` | Various (clean file) | No | No | Yes — verifies zero scores |
| `test_subdirectory_okay` | `init-py-test/subdirectory-okay.py` | Various | No | No | Yes — exercises namespace resolution via `__init__.py` |
| `test_multiline_code` | `multiline_statement.py` | `Call` | No | No | Yes — verifies line numbers and line ranges |
| `test_trojansource` | `trojansource.py` | **`File`** check type | No | No | Yes |
| `test_trojansource_latin1` | `trojansource_latin1.py` | **`File`** check type | No | No | Yes |
| `test_baseline_filter` | `flask_debug.py` | `Call` | No | Yes | Yes — verifies baseline filtering post-visit |
| `test_crypto_md5` | `crypto-md5.py` | `Call`, `Import` | No | Yes (hashlib) | Yes |
| `test_ciphers` | `ciphers.py` | `Call`, `Import` | No | Yes (Crypto) | Yes |
| `test_pickle` | `pickle_deserialize.py` | `Call`, `Import` | No | Yes (pickle) | Yes |
| `test_xml` (6 sub-tests) | `xml_*.py` | `Call`, `Import` | No | Yes (xml modules) | Yes |
| `test_ssl_insecure_version` | `ssl-insecure-version.py` | `Call`, `Import` | No | Yes (ssl) | Yes |
| `test_binding` | `binding.py` | `Call` | No | No | Yes |
| `test_os_chmod` | `os-chmod.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_os_exec` | `os-exec.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_os_popen` | `os-popen.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_os_spawn` | `os-spawn.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_os_startfile` | `os-startfile.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_os_system` | `os_system.py` | `Call`, `Import` | No | Yes (os) | Yes |
| `test_popen_wrappers` | `popen_wrappers.py` | `Call`, `Import` | No | Yes | Yes |
| `test_random_module` | `random_module.py` | `Call`, `Import` | No | Yes (random) | Yes |
| `test_requests_ssl_verify_disabled` | `requests-ssl-verify-disabled.py` | `Call`, `Import` | No | Yes (requests) | Yes |
| `test_requests_without_timeout` | `requests-missing-timeout.py` | `Call`, `Import` | No | Yes (requests) | Yes |
| `test_weak_cryptographic_key` | `weak_cryptographic_key_sizes.py` | `Call`, `Import` | No | Yes | Yes |
| `test_wildcard_injection` | `wildcard-injection.py` | `Call`, `Import` | No | Yes | Yes |
| `test_yaml` | `yaml_load.py` | `Call`, `Import` | No | Yes (yaml) | Yes |
| `test_jinja2_templating` | `jinja2_templating.py` | `Call`, `Import` | No | Yes (jinja2) | Yes |
| `test_mako_templating` | `mako_templating.py` | `Call`, `Import` | No | Yes (mako) | Yes |
| `test_django_sql_injection` | `django_sql_injection_extra.py` | `Call`, `Import` | No | Yes | Yes |
| `test_django_sql_injection_raw` | `django_sql_injection_raw.py` | `Call`, `Import` | No | Yes | Yes |
| `test_django_xss_secure` | `mark_safe_secure.py` | `Call`, `Import` | No | Yes | Yes |
| `test_django_xss_insecure` | `mark_safe_insecure.py` | `Call`, `Import` | No | Yes | Yes |
| `test_blacklist_pycrypto` | `pycrypto.py` | `Import` | No | Yes | Yes |
| `test_no_blacklist_pycryptodome` | `pycryptodome.py` | `Import` | No | Yes | Yes |
| `test_blacklist_pyghmi` | `pyghmi.py` | `Import` | No | Yes | Yes |
| `test_snmp_security_check` | `snmp.py` | `Call`, `Import` | No | Yes | Yes |
| `test_host_key_verification` | `no_host_key_verification.py` | `Call`, `Import` | No | Yes (paramiko) | Yes |
| `test_paramiko_injection` | `paramiko_injection.py` | `Call`, `Import` | No | Yes | Yes |
| `test_partial_path` | `partial_path_process.py` | `Call`, `Import` | No | Yes | Yes |
| `test_tarfile_unsafe_members` | `tarfile_unsafe_members.py` | `Call`, `Import` | No | Yes | Yes |
| `test_pytorch_load` | `pytorch.py` | `Call`, `Import` | No | Yes | Yes |
| `test_markupsafe_markup_xss` | `markupsafe_markup_xss.py` | `Call`, `Import` | No | Yes | Yes |
| `test_huggingface_unsafe_download` | `huggingface.py` | `Call`, `Import` | No | Yes | Yes |
| `test_unverified_context` | `unverified_context.py` | `Call`, `Import` | No | Yes (ssl) | Yes |
| `test_hashlib_new_insecure_functions` | `hashlib_new_insecure_functions.py` | `Call`, `Import` | No | Yes (hashlib) | Yes |

#### Unit tests that indirectly relate to node_visitor components

| Test file | What it tests | Relation to node_visitor |
|---|---|---|
| `tests/unit/core/test_context.py` | `Context` class properties and methods | Tests the wrapper that plugins receive from `run_tests`; does NOT exercise `pre_visit` context building |
| `tests/unit/core/test_manager.py` (`test_run_tests_keyboardinterrupt`) | Manager error handling during `run_tests` | Exercises `_execute_ast_visitor` → `BanditNodeVisitor` but mocks `count_issues` |
| `tests/unit/core/test_manager.py` (`test_run_tests_ioerror`) | Manager handling of missing files | Does NOT exercise `BanditNodeVisitor` (file open fails before visitor creation) |
| `tests/unit/core/test_meta_ast.py` | `BanditMetaAst.add_node` and `__str__` | Tests the metaast that `pre_visit` writes to when `debug=True`, but metaast is tested in isolation |
| `tests/unit/core/test_test_set.py` | `BanditTestSet` plugin loading | Tests the testset passed to visitor constructor |
| `tests/unit/core/test_blacklisting.py` | Blacklist plugin dispatch | Tests the blacklist function called by tester during visit |

### 16.5 Behaviours tested end-to-end only (no isolated unit test)

These behaviours are exercised only through the full pipeline in functional tests. If the Rust rewrite introduces a subtle bug, these tests may not pinpoint the exact failure location:

1. **`visit_Call` context enrichment** — `context["call"]`, `context["qualname"]`, `context["name"]` are set correctly. Tested implicitly by every functional test that detects a function call issue.
2. **`visit_FunctionDef` namespace tracking** — entering/leaving a function appends/pops the namespace. Tested implicitly by `test_multiline_sql_statements` (which has nested functions) and `test_subdirectory_okay`.
3. **`visit_ClassDef` namespace tracking** — entering/leaving a class appends/pops the namespace. Only implicitly exercised by example files that contain classes.
4. **`visit_Import` / `visit_ImportFrom` alias accumulation** — tested by `test_imports_aliases`, `test_imports_from`, and every test with import-based detection, but only at the score level (not verifying `self.imports` or `self.import_aliases` directly).
5. **`visit_Str` docstring suppression** — `isinstance(node._bandit_parent, ast.Expr)` check. Tested implicitly (docstrings in example files don't trigger false positives), but no test explicitly verifies suppression.
6. **`pre_visit` context dict construction** — all 8+ keys set per node. Tested indirectly via plugin dispatch correctness, but never verified in isolation.
7. **`generic_visit` parent/sibling injection** — `_bandit_parent` and `_bandit_sibling` attributes. Tested indirectly (plugins and `linerange` depend on them), but never directly asserted.
8. **`update_scores` accumulation** — element-wise addition. Tested by every functional test that checks expected scores, but never in isolation.
9. **`process()` return value** — the scores dict. Tested implicitly via `check_example` which reads `self.b_mgr.scores`.
10. **Score-to-metrics pipeline** — `process()` returns scores → manager passes to `metrics.count_issues`. Tested by `test_metric_gathering` and `test_multiline_sql_statements` (via `check_metrics`).

### 16.6 Behaviours that are entirely untested

These are the **highest-risk areas** for the Rust rewrite — any regression here would be silent:

1. **`InvalidModulePath` fallback** (lines 40-44) — No test provides a file path that fails `get_module_qualname_from_path`. The `self.namespace = ""` fallback is never exercised. Risk: if the Rust version handles this differently, no test would catch it.

2. **`debug=True` code paths** (lines 195-196, 224) — No test runs with `debug=True`. The `metaast.add_node` and `LOG.debug(ast.dump(node))` paths are completely untested. Risk: low (debug-only), but the Rust rewrite should still support a debug mode.

3. **`visit_Bytes` docstring suppression** (line 185→exit) — No test has a bytes literal as a standalone expression (docstring). The `isinstance(node._bandit_parent, ast.Expr)` check for bytes nodes is untested. Risk: medium — a Rust rewrite that doesn't suppress bytes docstrings could produce false positives.

4. **`visit_Constant` with non-str/non-bytes values** — No test verifies behaviour for `Constant` nodes containing `int`, `float`, `bool`, `None`, or `Ellipsis`. `visit_Constant` silently does nothing for these types. Risk: low (no plugins target these).

5. **`visit_ImportFrom` with `node.module is None`** — Relative imports like `from . import X`. The `test_imports_from` test uses `imports-from.py` which includes `from . import sys` and `from .. import sys`, providing partial coverage, but the score-level assertion doesn't directly verify the `visit_Import` delegation path.

6. **Wildcard imports** (`from X import *`) — No test verifies that `self.imports.add(module + "." + "*")` and `self.import_aliases["*"]` are set correctly. The wildcard case is implicitly handled but never asserted.

7. **Deeply nested AST recursion** — No test exercises `generic_visit` on a deeply nested AST (e.g. 50+ levels of nesting). Risk: a Rust iterative traversal must handle depth correctly.

8. **Empty file** — No test calls `process()` on `b""` or a file with only whitespace/comments (though `test_okay` comes close with a vulnerability-free file).

9. **Nosec on a line with no matching issues** — No test verifies the tester's warning log when a `# nosec B602` comment appears on a line where B602 doesn't actually trigger.

10. **Multiple `visit_Import` calls accumulating state** — No test directly verifies that `self.imports` and `self.import_aliases` grow correctly across multiple import statements within a single file. This is implicitly tested by files with multiple imports, but only via score correctness.

11. **`_bandit_sibling` correctness** — No test verifies that `_bandit_sibling` is set correctly (pointing to the next item in a list, or `None` for the last item). This attribute is used by `b_utils.linerange` for multiline fixup.

12. **Namespace popping in `post_visit`** — No test directly verifies that `namespace_path_split` correctly pops the last component when leaving a `ClassDef` or `FunctionDef`. Tested implicitly by correct `qualname` resolution in subsequent nodes.

---

## 17. Acceptance Criteria

The Rust implementation of `BanditNodeVisitor` must satisfy all of the following testable assertions.
These are organised into categories with unique IDs for traceability.

### AC-SCORE: Score parity

| ID | Assertion |
|---|---|
| AC-SCORE-1 | For every file in `examples/`, the Rust visitor must produce an identical `scores` dict (`{"SEVERITY": [a,b,c,d], "CONFIDENCE": [e,f,g,h]}`) to the Python visitor. |
| AC-SCORE-2 | For every file in `bandit/` (the bandit source itself), the Rust visitor must produce identical scores to the Python visitor. |
| AC-SCORE-3 | Given a file with zero issues, the Rust visitor must return `{"SEVERITY": [0,0,0,0], "CONFIDENCE": [0,0,0,0]}`. |
| AC-SCORE-4 | Given a file with issues at all four severity levels, each `SEVERITY[i]` must equal the sum of `RANKING_VALUES[level]` for all issues at that level. Same for `CONFIDENCE`. |
| AC-SCORE-5 | `update_scores` must be commutative and associative — the order of plugin dispatch within a node type must not affect the final scores. |

### AC-NOSEC: Nosec suppression correctness

| ID | Assertion |
|---|---|
| AC-NOSEC-1 | A blanket `# nosec` comment must suppress all findings on that line and increment `metrics.nosec` by 1 per suppressed result. |
| AC-NOSEC-2 | A specific `# nosec B602` must suppress only B602 findings and increment `metrics.skipped_tests` by 1. Other findings on the same line must NOT be suppressed. |
| AC-NOSEC-3 | A multi-ID `# nosec B602,B607` must suppress both B602 and B607 findings. |
| AC-NOSEC-4 | A `# nosec` on a multiline statement must suppress findings across the entire statement's line range (verified on `examples/nosec.py` lines 5-6 and 7-8). |
| AC-NOSEC-5 | When `ignore_nosec=True` (empty `nosec_lines` dict), all nosec comments must be ignored and all findings reported. Verified by running `examples/skip.py` with and without `ignore_nosec`. |
| AC-NOSEC-6 | Nosec by test name (`# nosec subprocess_popen_with_shell_equals_true`) must suppress the named test. |
| AC-NOSEC-7 | The Rust visitor must produce identical nosec and skipped_tests metric counts as the Python visitor for `examples/sql_multiline_statements.py` (expected: `nosec=7`, `skipped_tests=8`). |
| AC-NOSEC-8 | The Rust visitor must produce identical nosec metric counts as the Python visitor for `examples/skip.py` (expected: `nosec=2`, `loc=7`). |

### AC-IMPORT: Import tracking correctness

| ID | Assertion |
|---|---|
| AC-IMPORT-1 | `import X` must add `"X"` to `self.imports`. |
| AC-IMPORT-2 | `import X as Y` must add `"X"` to `self.imports` AND `{"Y": "X"}` to `self.import_aliases`. |
| AC-IMPORT-3 | `from X import Y` must add `"X.Y"` to `self.imports` AND `{"Y": "X.Y"}` to `self.import_aliases`. |
| AC-IMPORT-4 | `from X import Y as Z` must add `"X.Y"` to `self.imports` AND `{"Z": "X.Y"}` to `self.import_aliases`. |
| AC-IMPORT-5 | `from . import Y` (relative import, `module is None`) must delegate to `visit_Import` logic — `"Y"` added to `self.imports`. |
| AC-IMPORT-6 | Import aliases must be usable by `visit_Call` to resolve qualified names. Verified by `examples/imports-aliases.py`: `import hashlib as h; h.md5('1')` must resolve to `hashlib.md5` and trigger B324. |
| AC-IMPORT-7 | Multiple imports in the same file must accumulate — `self.imports` and `self.import_aliases` must contain entries from all import statements visited so far. |

### AC-TRAVERSE: AST traversal correctness

| ID | Assertion |
|---|---|
| AC-TRAVERSE-1 | Every AST node in the file must be visited exactly once (depth-first, field-order). |
| AC-TRAVERSE-2 | `_bandit_parent` must be set on every visited node to its immediate parent in the AST. |
| AC-TRAVERSE-3 | `_bandit_sibling` must be set to the next item in a list field, or `None` if last. |
| AC-TRAVERSE-4 | `visit_Str` must NOT dispatch plugins for string literals that are docstrings (parent is `ast.Expr`). |
| AC-TRAVERSE-5 | `visit_Bytes` must NOT dispatch plugins for bytes literals that are docstrings (parent is `ast.Expr`). |
| AC-TRAVERSE-6 | `visit_Constant` must delegate to `visit_Str` for `str` values and `visit_Bytes` for `bytes` values. Other constant types must NOT trigger Str/Bytes dispatch. |
| AC-TRAVERSE-7 | Node types without named visitors (e.g. `Assert`, `ExceptHandler`) must still trigger `tester.run_tests` with the correct node type name. |
| AC-TRAVERSE-8 | After `generic_visit` completes, `process()` must run `tester.run_tests(context, "File")` to dispatch file-level plugins. |

### AC-NAMESPACE: Namespace resolution correctness

| ID | Assertion |
|---|---|
| AC-NAMESPACE-1 | `self.namespace` must be initialised from the file path using `get_module_qualname_from_path`. For `examples/assert.py`, namespace should derive from the path. |
| AC-NAMESPACE-2 | Entering a `ClassDef` must append `node.name` to the namespace. |
| AC-NAMESPACE-3 | Entering a `FunctionDef` must append the function name to the namespace. |
| AC-NAMESPACE-4 | Leaving a `ClassDef` or `FunctionDef` (in `post_visit`) must pop the last component from the namespace. |
| AC-NAMESPACE-5 | For nested structures (class containing a method), `qualname` in `visit_FunctionDef` must be `module.ClassName.method_name`. |
| AC-NAMESPACE-6 | If `get_module_qualname_from_path` raises `InvalidModulePath`, `self.namespace` must default to `""`. |

### AC-CONTEXT: Context object correctness

| ID | Assertion |
|---|---|
| AC-CONTEXT-1 | `pre_visit` must set `imports`, `import_aliases`, `node`, `linerange`, `filename`, `file_data` for every node. |
| AC-CONTEXT-2 | `pre_visit` must set `lineno` if the node has a `lineno` attribute. |
| AC-CONTEXT-3 | `pre_visit` must set `col_offset` and `end_col_offset` if the node has those attributes. |
| AC-CONTEXT-4 | `visit_Call` must set `call`, `qualname`, and `name` in the context. |
| AC-CONTEXT-5 | `visit_FunctionDef` must set `function`, `qualname`, and `name` in the context. |
| AC-CONTEXT-6 | `visit_Import` and `visit_ImportFrom` must set `module` in the context. `visit_ImportFrom` must also set `name`. |
| AC-CONTEXT-7 | `visit_Str` must set `str` in the context. `visit_Bytes` must set `bytes` in the context. |

### AC-METRICS: Metrics integration correctness

| ID | Assertion |
|---|---|
| AC-METRICS-1 | The Rust visitor must call `metrics.note_nosec()` the same number of times as the Python visitor for any given file. |
| AC-METRICS-2 | The Rust visitor must call `metrics.note_skipped_test()` the same number of times as the Python visitor for any given file. |
| AC-METRICS-3 | After `process()` returns, `metrics.count_issues([scores])` must receive the same scores from the Rust visitor as from the Python visitor. |
| AC-METRICS-4 | For `examples/skip.py`, post-aggregation metrics must show `nosec=2`, `loc=7`, `SEVERITY.LOW=5`, `CONFIDENCE.HIGH=5`. |
| AC-METRICS-5 | For `examples/imports.py`, post-aggregation metrics must show `nosec=0`, `loc=4`, `SEVERITY.LOW=2`, `CONFIDENCE.HIGH=2`. |

### AC-RESULT: Issue result parity

| ID | Assertion |
|---|---|
| AC-RESULT-1 | For every file in `examples/`, the Rust visitor must produce the same list of `Issue` objects (same `test_id`, `severity`, `confidence`, `lineno`, `linerange`, `text`, `fname`). |
| AC-RESULT-2 | Issue ordering must match — plugins are dispatched in testset order, and issues must be appended to `tester.results` in the same sequence. |
| AC-RESULT-3 | The `test` attribute on each `Issue` (set by the tester to `test.__name__`) must match between Python and Rust implementations. |
| AC-RESULT-4 | The `test_id` attribute on each `Issue` must match. |

### AC-EDGE: Edge case handling

| ID | Assertion |
|---|---|
| AC-EDGE-1 | An empty file (`b""`) must parse without error, produce zero scores, and still run `"File"` plugins. |
| AC-EDGE-2 | A file with only comments must parse without error and produce zero scores. |
| AC-EDGE-3 | A file that fails `ast.parse` (syntax error) must be handled by the caller (manager), not crash the visitor. |
| AC-EDGE-4 | A file with wildcard imports (`from os import *`) must add `"os.*"` to imports and `{"*": "os.*"}` to import_aliases. |
| AC-EDGE-5 | A file with deeply nested AST (30+ levels) must complete without stack overflow. |
| AC-EDGE-6 | A file with `visit_ClassDef` immediately followed by `visit_FunctionDef` must correctly track namespace (push class, push function, pop function, pop class). |

### AC-COMPAT: Drop-in compatibility

| ID | Assertion |
|---|---|
| AC-COMPAT-1 | The Rust visitor must expose the same constructor signature: `__init__(self, fname, fdata, metaast, testset, debug, nosec_lines, metrics)`. |
| AC-COMPAT-2 | `process(data)` must accept `bytes` and return a `dict` with the same shape as the Python version. |
| AC-COMPAT-3 | `self.tester.results` must be accessible from Python after `process()` returns, containing the same `Issue` objects. |
| AC-COMPAT-4 | The Rust visitor must work with the existing Python `BanditTester`, `BanditTestSet`, `Context`, and all existing Python plugins without modification. |
| AC-COMPAT-5 | `manager._execute_ast_visitor` must be able to use the Rust visitor as a drop-in replacement without any changes to manager.py. |
| AC-COMPAT-6 | All 273 existing tests must pass when the Rust visitor replaces the Python visitor. |

### AC-REGRESSION: Full parity test

| ID | Assertion |
|---|---|
| AC-REGRESSION-1 | A parametrised test must run both Python and Rust visitors on every file in `examples/` and assert identical `(scores, results, metrics)` tuples. |
| AC-REGRESSION-2 | A parametrised test must run both visitors on every `.py` file in `bandit/` and assert identical output. |
| AC-REGRESSION-3 | Performance must not regress — the Rust visitor must process files at least as fast as the Python visitor (wall time per file). |
