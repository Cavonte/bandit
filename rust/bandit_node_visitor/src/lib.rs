use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet, PyTuple};

/// Rust implementation of BanditNodeVisitor.
///
/// Drop-in replacement for bandit.core.node_visitor.BanditNodeVisitor.
/// Handles AST traversal, context building, namespace tracking, import tracking,
/// parent/sibling injection, and score accumulation in Rust.
/// Plugin dispatch remains in Python via BanditTester.run_tests().
#[pyclass]
struct BanditNodeVisitor {
    /// Accumulated scores: [SEVERITY[4], CONFIDENCE[4]]
    scores: [[i64; 4]; 2],
    /// Current AST recursion depth
    depth: i64,
    /// Current namespace path (e.g. "module.class.method")
    namespace: String,
    /// File path being scanned
    fname: PyObject,
    /// File data handle (binary reader)
    fdata: PyObject,
    /// Debug-only metadata AST
    metaast: PyObject,
    /// Whether debug mode is enabled
    debug: bool,
    /// The BanditTester instance (Python object)
    tester: PyObject,
    /// Import set (Python set, shared with context)
    imports: PyObject,
    /// Import aliases dict (Python dict, shared with context)
    import_aliases: PyObject,
    /// Current context dict (rebuilt per node in pre_visit)
    context: PyObject,
    /// Metrics instance
    metrics: PyObject,
}

#[pymethods]
impl BanditNodeVisitor {
    #[new]
    fn new(
        py: Python<'_>,
        fname: PyObject,
        fdata: PyObject,
        metaast: PyObject,
        testset: PyObject,
        debug: bool,
        nosec_lines: PyObject,
        metrics: PyObject,
    ) -> PyResult<Self> {
        // Create imports set and import_aliases dict
        let imports: PyObject = PySet::empty_bound(py)?.unbind().into();
        let import_aliases: PyObject = PyDict::new_bound(py).unbind().into();

        // Create BanditTester instance
        let tester_mod = py.import_bound("bandit.core.tester")?;
        let tester_cls = tester_mod.getattr("BanditTester")?;
        let tester = tester_cls
            .call1((&testset, debug, &nosec_lines, &metrics))?
            .unbind();

        // Resolve namespace via get_module_qualname_from_path
        let utils_mod = py.import_bound("bandit.core.utils")?;
        let namespace = match utils_mod
            .getattr("get_module_qualname_from_path")?
            .call1((&fname,))
        {
            Ok(result) => result.extract::<String>()?,
            Err(_) => {
                // InvalidModulePath - log warning and use empty string
                let logging = py.import_bound("logging")?;
                let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
                logger.call_method1(
                    "warning",
                    ("Unable to find qualified name for module: %s", &fname),
                )?;
                String::new()
            }
        };

        // Log the namespace (matches Python: always logs via LOG.debug)
        {
            let logging = py.import_bound("logging")?;
            let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
            logger.call_method1("debug", ("Module qualified name: %s", namespace.as_str()))?;
        }

        let context: PyObject = PyDict::new_bound(py).unbind().into();

        Ok(BanditNodeVisitor {
            scores: [[0i64; 4]; 2],
            depth: 0,
            namespace,
            fname,
            fdata,
            metaast,
            debug,
            tester,
            imports,
            import_aliases,
            context,
            metrics,
        })
    }

    /// Access the tester (Python BanditTester instance)
    #[getter]
    fn tester(&self, py: Python<'_>) -> PyObject {
        self.tester.clone_ref(py)
    }

    /// Access the scores as a Python dict
    #[getter]
    fn scores(&self, py: Python<'_>) -> PyResult<PyObject> {
        self.scores_to_py(py)
    }

    /// Access imports set
    #[getter]
    fn imports(&self, py: Python<'_>) -> PyObject {
        self.imports.clone_ref(py)
    }

    /// Access import_aliases dict
    #[getter]
    fn import_aliases(&self, py: Python<'_>) -> PyObject {
        self.import_aliases.clone_ref(py)
    }

    /// Access the namespace
    #[getter]
    fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Access depth
    #[getter]
    fn depth(&self) -> i64 {
        self.depth
    }

    /// Access metrics
    #[getter]
    fn metrics(&self, py: Python<'_>) -> PyObject {
        self.metrics.clone_ref(py)
    }

    /// Main entry point. Parses AST and walks the tree.
    fn process(&mut self, py: Python<'_>, data: PyObject) -> PyResult<PyObject> {
        // 1. Parse bytes to AST: f_ast = ast.parse(data)
        let ast_mod = py.import_bound("ast")?;
        let f_ast = ast_mod.call_method1("parse", (&data,))?;

        // 2. Walk the tree
        self.generic_visit(py, &f_ast)?;

        // 3. Build file-level context for "File" plugins
        let file_ctx = PyDict::new_bound(py);
        file_ctx.set_item("file_data", &self.fdata)?;
        file_ctx.set_item("filename", &self.fname)?;
        file_ctx.set_item("lineno", 0)?;
        let linerange = PyList::new_bound(py, &[0i64, 1i64]);
        file_ctx.set_item("linerange", &linerange)?;
        file_ctx.set_item("col_offset", 0)?;
        self.context = file_ctx.unbind().into();

        // 4. Dispatch "File" plugins
        let tester = self.tester.bind(py);
        let scores_obj = tester.call_method1("run_tests", (&self.context, "File"))?;
        self.update_scores_from_py(&scores_obj)?;

        // 5. Return scores
        self.scores_to_py(py)
    }

    /// Recursive AST traversal. Injects parent/sibling and calls pre/visit/post.
    fn generic_visit(
        &mut self,
        py: Python<'_>,
        node: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let ast_mod = py.import_bound("ast")?;
        let ast_ast = ast_mod.getattr("AST")?;
        let iter_fields = ast_mod.getattr("iter_fields")?;

        let fields = iter_fields.call1((node,))?;

        for field_result in fields.iter()? {
            let field = field_result?;
            // field is a tuple (name, value)
            let tuple: &Bound<'_, PyTuple> = field.downcast()?;
            let value = tuple.get_item(1)?;

            if let Ok(list) = value.downcast::<PyList>() {
                let max_idx = list.len().saturating_sub(1);
                for idx in 0..list.len() {
                    let item = list.get_item(idx)?;
                    if item.is_instance(&ast_ast)? {
                        // Set _bandit_sibling
                        if idx < max_idx {
                            let sibling = list.get_item(idx + 1)?;
                            item.setattr("_bandit_sibling", sibling)?;
                        } else {
                            item.setattr("_bandit_sibling", py.None())?;
                        }
                        // Set _bandit_parent
                        item.setattr("_bandit_parent", node)?;

                        // pre_visit -> visit -> generic_visit -> post_visit
                        self.pre_visit(py, &item)?;
                        self.visit(py, &item)?;
                        self.generic_visit(py, &item)?;
                        self.post_visit(py, &item)?;
                    }
                }
            } else if value.is_instance(&ast_ast)? {
                value.setattr("_bandit_sibling", py.None())?;
                value.setattr("_bandit_parent", node)?;

                self.pre_visit(py, &value)?;
                self.visit(py, &value)?;
                self.generic_visit(py, &value)?;
                self.post_visit(py, &value)?;
            }
        }

        Ok(())
    }
}

impl BanditNodeVisitor {
    /// Build context dict before visiting a node.
    fn pre_visit(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let ctx = PyDict::new_bound(py);

        // Set imports and import_aliases (shared references)
        ctx.set_item("imports", &self.imports)?;
        ctx.set_item("import_aliases", &self.import_aliases)?;

        // Debug logging and metaast
        if self.debug {
            let ast_mod = py.import_bound("ast")?;
            let logging = py.import_bound("logging")?;
            let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
            let dump = ast_mod.call_method1("dump", (node,))?;
            logger.call_method1("debug", (dump,))?;
            self.metaast
                .call_method1(py, "add_node", (node, "", self.depth))?;
        }

        // Set lineno, col_offset, end_col_offset if present
        // Python uses hasattr() which is true even if the value is None
        if let Ok(lineno) = node.getattr("lineno") {
            ctx.set_item("lineno", &lineno)?;
        }
        if let Ok(col_offset) = node.getattr("col_offset") {
            ctx.set_item("col_offset", &col_offset)?;
        }
        if let Ok(end_col_offset) = node.getattr("end_col_offset") {
            ctx.set_item("end_col_offset", &end_col_offset)?;
        }

        // Set node, linerange, filename, file_data
        ctx.set_item("node", node)?;

        let utils_mod = py.import_bound("bandit.core.utils")?;
        let linerange = utils_mod.call_method1("linerange", (node,))?;
        ctx.set_item("linerange", linerange)?;

        ctx.set_item("filename", &self.fname)?;
        ctx.set_item("file_data", &self.fdata)?;

        // Python: LOG.debug("entering: %s %s [%s]", hex(id(node)), type(node), self.depth)
        let logging = py.import_bound("logging")?;
        let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
        let node_id = node.as_ptr() as usize;
        let node_type = node.getattr("__class__")?;
        logger.call_method1("debug", (format!("entering: 0x{:x} {} [{}]", node_id, node_type, self.depth),))?;

        self.depth += 1;

        // Python: LOG.debug(self.context)
        logger.call_method1("debug", (&ctx,))?;

        self.context = ctx.unbind().into();

        Ok(())
    }

    /// Dispatch to named visitor or fall through to tester.run_tests.
    /// Python: method = "visit_" + name; visitor = getattr(self, method, None)
    fn visit(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let cls = node.getattr("__class__")?;
        let name: String = cls.getattr("__name__")?.extract()?;

        // Check if we have a named visitor for this node type
        let has_visitor = matches!(
            name.as_str(),
            "ClassDef" | "FunctionDef" | "Call" | "Import" | "ImportFrom" | "Constant"
        );

        if has_visitor {
            // Python: if self.debug: LOG.debug("%s called (%s)", method, ast.dump(node))
            if self.debug {
                let ast_mod = py.import_bound("ast")?;
                let logging = py.import_bound("logging")?;
                let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
                let dump = ast_mod.call_method1("dump", (node,))?;
                let method_name = format!("visit_{}", name);
                logger.call_method1("debug", (format!("{} called ({})", method_name, dump),))?;
            }

            match name.as_str() {
                "ClassDef" => self.visit_classdef(node),
                "FunctionDef" => self.visit_functiondef(py, node),
                "Call" => self.visit_call(py, node),
                "Import" => self.visit_import(py, node),
                "ImportFrom" => self.visit_importfrom(py, node),
                "Constant" => self.visit_constant(py, node),
                _ => unreachable!(),
            }
        } else {
            // No named visitor - dispatch to tester directly
            let tester = self.tester.bind(py);
            let scores =
                tester.call_method1("run_tests", (&self.context, name.as_str()))?;
            self.update_scores_from_py(&scores)?;
            Ok(())
        }
    }

    /// Post-visit: decrement depth and pop namespace for FunctionDef/ClassDef.
    fn post_visit(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        self.depth -= 1;

        let logging = py.import_bound("logging")?;
        let logger = logging.call_method1("getLogger", ("bandit.core.node_visitor",))?;
        let node_id = node.as_ptr() as usize;
        logger.call_method1("debug", (format!("{}\texiting : 0x{:x}", self.depth, node_id),))?;

        let ast_mod = py.import_bound("ast")?;
        let funcdef = ast_mod.getattr("FunctionDef")?;
        let classdef = ast_mod.getattr("ClassDef")?;

        if node.is_instance(&funcdef)?
            || node.is_instance(&classdef)?
        {
            if let Some(pos) = self.namespace.rfind('.') {
                self.namespace.truncate(pos);
            } else {
                self.namespace.clear();
            }
        }

        Ok(())
    }

    /// visit_ClassDef: only update namespace (no plugin dispatch).
    /// Uses namespace_path_join semantics: always "{base}.{name}"
    fn visit_classdef(&mut self, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let node_name: String = node.getattr("name")?.extract()?;
        // Python: self.namespace = b_utils.namespace_path_join(self.namespace, node.name)
        // namespace_path_join = f"{base}.{name}" — always prepends dot
        self.namespace = format!("{}.{}", self.namespace, node_name);
        Ok(())
    }

    /// visit_FunctionDef: enrich context, update namespace, dispatch plugins.
    fn visit_functiondef(
        &mut self,
        py: Python<'_>,
        node: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;

        ctx_dict.set_item("function", node)?;

        // Python: qualname = self.namespace + "." + b_utils.get_func_name(node)
        // get_func_name just returns node.name
        let func_name: String = node.getattr("name")?.extract()?;
        let qualname = format!("{}.{}", self.namespace, func_name);
        // Python: name = qualname.split(".")[-1]
        let name = qualname.split('.').last().unwrap_or("");

        ctx_dict.set_item("qualname", qualname.as_str())?;
        ctx_dict.set_item("name", name)?;

        // Python: self.namespace = b_utils.namespace_path_join(self.namespace, name)
        // namespace_path_join = f"{base}.{name}"
        self.namespace = format!("{}.{}", self.namespace, name);

        // Dispatch FunctionDef plugins
        let tester = self.tester.bind(py);
        let scores = tester.call_method1("run_tests", (&self.context, "FunctionDef"))?;
        self.update_scores_from_py(&scores)?;

        Ok(())
    }

    /// visit_Call: enrich context with call info, dispatch plugins.
    fn visit_call(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;

        ctx_dict.set_item("call", node)?;

        // qualname = b_utils.get_call_name(node, self.import_aliases)
        let utils_mod = py.import_bound("bandit.core.utils")?;
        let qualname_obj =
            utils_mod.call_method1("get_call_name", (node, &self.import_aliases))?;
        let qualname: String = qualname_obj.extract()?;
        // Python: name = qualname.split(".")[-1]
        let name = qualname.split('.').last().unwrap_or("");

        ctx_dict.set_item("qualname", qualname.as_str())?;
        ctx_dict.set_item("name", name)?;

        // Dispatch Call plugins
        let tester = self.tester.bind(py);
        let scores = tester.call_method1("run_tests", (&self.context, "Call"))?;
        self.update_scores_from_py(&scores)?;

        Ok(())
    }

    /// visit_Import: update imports/aliases, enrich context, dispatch plugins.
    fn visit_import(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;
        let imports = self.imports.bind(py);
        let import_aliases = self.import_aliases.bind(py);
        let imports_set: &Bound<'_, PySet> = imports.downcast()?;
        let aliases_dict: &Bound<'_, PyDict> = import_aliases.downcast()?;

        let names = node.getattr("names")?;
        for nodename_result in names.iter()? {
            let nodename = nodename_result?;
            let module_name: String = nodename.getattr("name")?.extract()?;
            let asname = nodename.getattr("asname")?;

            if !asname.is_none() {
                let alias: String = asname.extract()?;
                aliases_dict.set_item(alias.as_str(), module_name.as_str())?;
            }

            imports_set.add(module_name.as_str())?;
            ctx_dict.set_item("module", module_name.as_str())?;
        }

        // Dispatch Import plugins
        let tester = self.tester.bind(py);
        let scores = tester.call_method1("run_tests", (&self.context, "Import"))?;
        self.update_scores_from_py(&scores)?;

        Ok(())
    }

    /// visit_ImportFrom: update imports/aliases with module prefix, dispatch plugins.
    fn visit_importfrom(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let module_attr = node.getattr("module")?;

        // If module is None (relative import like `from . import X`), delegate to visit_Import
        if module_attr.is_none() {
            return self.visit_import(py, node);
        }

        let module: String = module_attr.extract()?;

        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;
        let imports = self.imports.bind(py);
        let import_aliases = self.import_aliases.bind(py);
        let imports_set: &Bound<'_, PySet> = imports.downcast()?;
        let aliases_dict: &Bound<'_, PyDict> = import_aliases.downcast()?;

        let names = node.getattr("names")?;
        for nodename_result in names.iter()? {
            let nodename = nodename_result?;
            let name: String = nodename.getattr("name")?.extract()?;
            let asname = nodename.getattr("asname")?;
            let fq_name = format!("{}.{}", module, name);

            if !asname.is_none() {
                let alias: String = asname.extract()?;
                aliases_dict.set_item(alias.as_str(), fq_name.as_str())?;
            } else {
                // Even without alias, map name -> module.name
                aliases_dict.set_item(name.as_str(), fq_name.as_str())?;
            }

            imports_set.add(fq_name.as_str())?;
            ctx_dict.set_item("module", module.as_str())?;
            ctx_dict.set_item("name", name.as_str())?;
        }

        // Dispatch ImportFrom plugins
        let tester = self.tester.bind(py);
        let scores = tester.call_method1("run_tests", (&self.context, "ImportFrom"))?;
        self.update_scores_from_py(&scores)?;

        Ok(())
    }

    /// visit_Constant: delegate to visit_Str or visit_Bytes based on value type.
    fn visit_constant(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = node.getattr("value")?;

        if value.is_instance_of::<pyo3::types::PyString>() {
            self.visit_str(py, node)?;
        } else if value.is_instance_of::<pyo3::types::PyBytes>() {
            self.visit_bytes(py, node)?;
        }

        Ok(())
    }

    /// visit_Str: set context["str"], skip docstrings, dispatch "Str" plugins.
    fn visit_str(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;

        let value = node.getattr("value")?;
        ctx_dict.set_item("str", &value)?;

        // Check if parent is ast.Expr (docstring) - skip dispatch if so
        let parent = node.getattr("_bandit_parent")?;
        let ast_mod = py.import_bound("ast")?;
        let expr_type = ast_mod.getattr("Expr")?;

        if !parent.is_instance(&expr_type)? {
            let utils_mod = py.import_bound("bandit.core.utils")?;
            let linerange = utils_mod.call_method1("linerange", (&parent,))?;
            ctx_dict.set_item("linerange", linerange)?;

            let tester = self.tester.bind(py);
            let scores = tester.call_method1("run_tests", (&self.context, "Str"))?;
            self.update_scores_from_py(&scores)?;
        }

        Ok(())
    }

    /// visit_Bytes: set context["bytes"], skip docstrings, dispatch "Bytes" plugins.
    fn visit_bytes(&mut self, py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<()> {
        let ctx = self.context.bind(py);
        let ctx_dict: &Bound<'_, PyDict> = ctx.downcast()?;

        let value = node.getattr("value")?;
        ctx_dict.set_item("bytes", &value)?;

        // Check if parent is ast.Expr (docstring) - skip dispatch if so
        let parent = node.getattr("_bandit_parent")?;
        let ast_mod = py.import_bound("ast")?;
        let expr_type = ast_mod.getattr("Expr")?;

        if !parent.is_instance(&expr_type)? {
            let utils_mod = py.import_bound("bandit.core.utils")?;
            let linerange = utils_mod.call_method1("linerange", (&parent,))?;
            ctx_dict.set_item("linerange", linerange)?;

            let tester = self.tester.bind(py);
            let scores = tester.call_method1("run_tests", (&self.context, "Bytes"))?;
            self.update_scores_from_py(&scores)?;
        }

        Ok(())
    }

    /// Extract scores from Python dict and add to internal scores array.
    fn update_scores_from_py(&mut self, scores_obj: &Bound<'_, PyAny>) -> PyResult<()> {
        let scores_dict: &Bound<'_, PyDict> = scores_obj.downcast()?;

        if let Some(sev) = scores_dict.get_item("SEVERITY")? {
            let sev_list: &Bound<'_, PyList> = sev.downcast()?;
            for i in 0..4 {
                let val: i64 = sev_list.get_item(i)?.extract()?;
                self.scores[0][i] += val;
            }
        }

        if let Some(conf) = scores_dict.get_item("CONFIDENCE")? {
            let conf_list: &Bound<'_, PyList> = conf.downcast()?;
            for i in 0..4 {
                let val: i64 = conf_list.get_item(i)?.extract()?;
                self.scores[1][i] += val;
            }
        }

        Ok(())
    }

    /// Convert internal scores array to Python dict.
    fn scores_to_py(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);

        let sev = PyList::new_bound(py, &self.scores[0]);
        let conf = PyList::new_bound(py, &self.scores[1]);

        dict.set_item("SEVERITY", sev)?;
        dict.set_item("CONFIDENCE", conf)?;

        Ok(dict.unbind().into())
    }
}

/// Python module initialization
#[pymodule]
fn bandit_node_visitor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BanditNodeVisitor>()?;
    Ok(())
}
