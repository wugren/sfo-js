use std::cell::RefCell;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use boa_engine::{js_string, Context, JsArgs, JsError, JsNativeError, JsObject, JsResult, JsValue, Module, NativeFunction, Source};
use boa_engine::builtins::promise::PromiseState;
use boa_engine::class::Class;
use boa_engine::module::{resolve_module_specifier, ModuleLoader, Referrer};
use boa_engine::parser::source::ReadChar;
use boa_engine::property::{Attribute, PropertyKey};
use rustc_hash::FxHashMap;
use crate::errors::{into_js_err, js_err, JSErrorCode, JSResult};
use crate::gc::GcRefCell;
use crate::JsString;

struct SfoModuleLoader {
    roots: Mutex<Vec<PathBuf>>,
    module_map: GcRefCell<FxHashMap<PathBuf, Module>>,
    commonjs_module_map: GcRefCell<FxHashMap<PathBuf, (Module, JsValue)>>,
}

impl SfoModuleLoader {
    pub fn new(roots: Vec<PathBuf>) -> JSResult<Self> {
        if !roots.is_empty() {
            if cfg!(target_family = "wasm") {
                return Err(js_err!(JSErrorCode::JsFailed, "cannot resolve a relative path in WASM targets"));
            }
        }
        Ok(Self {
            roots: Mutex::new(vec![]),
            module_map: GcRefCell::new(FxHashMap::default()),
            commonjs_module_map: GcRefCell::new(FxHashMap::default()),
        })
    }

    #[inline]
    pub fn insert(&self, path: PathBuf, module: Module) {
        self.module_map.borrow_mut().insert(path, module);
    }

    #[inline]
    pub fn get(&self, path: &Path) -> Option<Module> {
        self.module_map.borrow().get(path).cloned()
    }

    #[inline]
    pub fn insert_commonjs(&self, path: PathBuf, module: Module, module_obj: JsValue) {
        self.commonjs_module_map.borrow_mut().insert(path, (module, module_obj));
    }

    #[inline]
    pub fn get_commonjs(&self, path: &Path) -> Option<(Module, JsValue)> {
        self.commonjs_module_map.borrow().get(path).cloned()
    }

    pub fn add_module_path(&self, module_path: &Path) -> JSResult<()> {
        self.roots.lock().unwrap().push(module_path.canonicalize()
            .map_err(into_js_err!(JSErrorCode::InvalidPath, "Invalid path {:?}", module_path))?);
        Ok(())
    }

    pub fn commonjs_resolve_module(&self, module_name: &str) -> JsResult<PathBuf> {
        let roots = {
            self.roots.lock().unwrap().clone()
        };
        for root in roots.iter() {
            let mut path = root.join(module_name);
            if path.exists() && path.is_dir() {
                let index = path.join("index.js");
                if index.exists() && index.is_file() {
                    if let Some(parent) = index.parent() {
                        if parent != root {
                            let _ = self.add_module_path(parent);
                        }
                    }
                    return Ok(index);
                }
            }
            if path.exists() && path.is_file() {
                if let Some(parent) = path.parent() {
                    if parent != root {
                        let _ = self.add_module_path(parent);
                    }
                }
                return Ok(path);
            }
            let mut js_path = path.to_path_buf();
            js_path.add_extension("js");
            if js_path.exists() && js_path.is_file() {
                if let Some(parent) = js_path.parent() {
                    if parent != root {
                        let _ = self.add_module_path(parent);
                    }
                }
                return Ok(js_path);
            }
            path.add_extension("mjs");
            if path.exists() && path.is_file() {
                if let Some(parent) = path.parent() {
                    if parent != root {
                        let _ = self.add_module_path(parent);
                    }
                }
                return Ok(path);
            }
        }
        Err(JsError::from_native(JsNativeError::typ().with_message(format!("module {} not found", module_name))))
    }
}

impl ModuleLoader for SfoModuleLoader {
    async fn load_imported_module(self: Rc<Self>, referrer: Referrer, specifier: JsString, context: &RefCell<&mut Context>) -> JsResult<Module> {
        let roots = {
            self.roots.lock().unwrap().clone()
        };
        for root in roots.iter() {
            let short_path = specifier.to_std_string_escaped();
            let path = resolve_module_specifier(
                Some(root),
                &specifier,
                referrer.path(),
                &mut context.borrow_mut(),
            )?;
            if let Some(module) = self.get(&path) {
                return Ok(module);
            }

            let mut path = path.to_path_buf();
            let source = match Source::from_filepath(&path) {
                Ok(source) => source,
                Err(_) => {
                    if !path.ends_with(".js") {
                        path.add_extension("js");
                        match Source::from_filepath(&path) {
                            Ok(source) => source,
                            Err(_) => continue,
                        }
                    } else {
                        continue;
                    }
                }
            };
            let module = Module::parse(source, None, &mut context.borrow_mut()).map_err(|err| {
                JsNativeError::syntax()
                    .with_message(format!("could not parse module `{short_path}`"))
                    .with_cause(err)
            })?;
            self.insert(path.clone(), module.clone());
            if let Some(parent) = path.parent() {
                if parent != root {
                    let _ = self.add_module_path(parent);
                }
            }
            return Ok(module);
        }

        Err(
            JsError::from_native(JsNativeError::typ()
                .with_message(format!("could not find module `{:?}`", specifier))))
    }
}

pub struct JsEngine {
    loader: Rc<SfoModuleLoader>,
    context: Context,
    module: Option<Module>,
}

unsafe impl Send for JsEngine {}
unsafe impl Sync for JsEngine {}

impl JsEngine {
    pub fn new() -> JSResult<Self> {
        let loader = Rc::new(SfoModuleLoader::new(vec![])?);
        let mut context = Context::builder()
            .module_loader(loader.clone())
            .can_block(true)
            .build()
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        boa_runtime::register(
            (
                boa_runtime::extensions::ConsoleExtension::default(),
                boa_runtime::extensions::FetchExtension(
                    boa_runtime::fetch::BlockingReqwestFetcher::default()
                ),
            ),
            None,
            &mut context,
        ).map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        context.register_global_callable("require".into(), 0, NativeFunction::from_fn_ptr(require))
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        // Adding custom object that mimics 'module.exports'
        let moduleobj = JsObject::default(context.intrinsics());
        moduleobj.set(js_string!("exports"), js_string!(" "), false, &mut context)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        context.register_global_property(
            js_string!("module"),
            JsValue::from(moduleobj),
            Attribute::default(),
        ).map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        Ok(JsEngine {
            loader,
            context,
            module: None,
        })
    }

    pub fn add_module_path(&mut self, module_path: &Path) -> JSResult<()> {
        self.loader.add_module_path(module_path)
    }

    pub fn register_global_property<K, V>(
        &mut self,
        key: K,
        value: V,
        attribute: Attribute,
    ) -> JSResult<()>
    where
        K: Into<PropertyKey>,
        V: Into<JsValue>, {
        self.context.register_global_property(key, value, attribute)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_callable(
        &mut self,
        name: String,
        length: usize,
        body: NativeFunction,
    ) -> JSResult<()> {
        self.context.register_global_callable(JsString::from(name), length, body)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_builtin_callable(
        &mut self,
        name: String,
        length: usize,
        body: NativeFunction,
    ) -> JSResult<()> {
        self.context.register_global_builtin_callable(JsString::from(name), length, body)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_class<C: Class>(&mut self) -> JSResult<()> {
        self.context.register_global_class::<C>()
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn eval_file(&mut self, path: &Path) -> JSResult<()> {
        let path = path.canonicalize()
            .map_err(into_js_err!(JSErrorCode::InvalidPath, "Invalid path {:?}", path))?;
        if let Some(parent) = path.parent() {
            self.add_module_path(parent)?;
        } else {
            self.add_module_path(std::env::current_dir()
                .map_err(into_js_err!(JSErrorCode::InvalidPath))?.as_path())?;
        }
        let source = Source::from_filepath(path.as_path())
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
        self.eval(source)
    }

    pub fn eval_string(&mut self, code: &str) -> JSResult<()> {
        let source = Source::from_bytes(code.as_bytes());
        self.eval(source)
    }

    fn eval<'path, R: ReadChar>(&mut self, source: Source<'path, R>) -> JSResult<()> {
        if self.module.is_some() {
            return Err(js_err!(JSErrorCode::JsFailed, "Already loaded a module"));
        }

        let module = Module::parse(source, None, &mut self.context)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        let promise_result = module.load(&mut self.context)
            .then(
                Some(
                    NativeFunction::from_copy_closure_with_captures(
                        |_, _, module, context| {
                            // After loading, link all modules by resolving the imports
                            // and exports on the full module graph, initializing module
                            // environments. This returns a plain `Err` since all modules
                            // must link at the same time.
                            module.link(context)?;
                            Ok(JsValue::undefined())
                        },
                        module.clone(),
                    )
                        .to_js_function(self.context.realm()),
                ),
                None,
                &mut self.context,
            )
            .then(
                Some(
                    NativeFunction::from_copy_closure_with_captures(
                        // Finally, evaluate the root module.
                        // This returns a `JsPromise` since a module could have
                        // top-level await statements, which defers module execution to the
                        // job queue.
                        |_, _, module, context| {
                            let result = module.evaluate(context);
                            Ok(result.into())
                        },
                        module.clone(),
                    )
                        .to_js_function(self.context.realm()),
                ),
                None,
                &mut self.context,
            );

        self.context.run_jobs()
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;

        match promise_result.state() {
            PromiseState::Pending => return Err(js_err!(JSErrorCode::JsFailed, "module didn't execute!")),
            PromiseState::Fulfilled(v) => {
                assert_eq!(v, JsValue::undefined());
            }
            PromiseState::Rejected(err) => {
                log::error!("module {:?} execution failed: {:?}", module.path(), err.to_string(&mut self.context));
                let err = JsError::from_opaque(err).into_erased(&mut self.context);
                return Err(js_err!(JSErrorCode::JsFailed, "{err}"));
            }
        }

        self.module = Some(module);

        Ok(())
    }

    pub fn call(&mut self, name: &str, args: Vec<JsValue>) -> JSResult<JsValue> {
        if self.module.is_none() {
            return Err(js_err!(JSErrorCode::JsFailed, "module didn't execute!"));
        }

        let fun = self.module.as_mut().unwrap().get_value(JsString::from(name), &mut self.context)
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "can't find {name} failed: {}", e))?;

        if let Some(fun) = fun.as_callable() {
            let result = fun.call(&JsValue::null(), args.as_slice(), &mut self.context)
                .map_err(|e| js_err!(JSErrorCode::JsFailed, "call {name} failed: {}", e))?;
            Ok(result)
        } else {
            Err(js_err!(JSErrorCode::JsFailed, "can't call {name}"))
        }
    }
}

pub struct AsyncJsEngine {
    inner: Arc<Mutex<JsEngine>>,
}

impl AsyncJsEngine {
    pub async fn new() -> JSResult<Self> {
        let inner = tokio::task::spawn_blocking(|| JsEngine::new())
            .await
            .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))??;
        Ok(AsyncJsEngine {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn add_module_path(&self, module_path: &Path) -> JSResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.add_module_path(module_path)
    }

    pub fn register_global_property<K, V>(
        &self,
        key: K,
        value: V,
        attribute: Attribute,
    ) -> JSResult<()>
    where
        K: Into<PropertyKey>,
        V: Into<JsValue>, {
        self.inner.lock().unwrap().register_global_property(key, value, attribute)
    }

    pub fn register_global_callable(
        &self,
        name: impl Into<String>,
        length: usize,
        body: NativeFunction,
    ) -> JSResult<()> {
        self.inner.lock().unwrap().register_global_callable(name.into(), length, body)
    }

    pub fn register_global_builtin_callable(
        &self,
        name: String,
        length: usize,
        body: NativeFunction,
    ) -> JSResult<()> {
        self.inner.lock().unwrap().register_global_builtin_callable(name, length, body)
    }

    pub fn register_global_class<C: Class>(&self) -> JSResult<()> {
        self.inner.lock().unwrap().register_global_class::<C>()
    }

    pub async fn eval_string(&self, code: impl Into<String>) -> JSResult<()> {
        let inner = self.inner.clone();
        let code = code.into();
        tokio::task::spawn_blocking(move || {
            let mut inner = inner.lock().unwrap();
            inner.eval_string(code.as_str())
        }).await.map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?
    }

    pub async fn eval_file(&self, path: impl AsRef<Path>) -> JSResult<()> {
        let inner = self.inner.clone();
        let path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut inner = inner.lock().unwrap();
            inner.eval_file(path.as_path())
        }).await.map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?
    }

    pub async fn call(&self, name: impl Into<String>, args: Vec<serde_json::Value>) -> JSResult<Option<serde_json::Value>> {
        let inner = self.inner.clone();
        let name = name.into();
        tokio::task::spawn_blocking(move || {
            let mut inner = inner.lock().unwrap();
            let mut new_args = Vec::with_capacity(args.len());
            for v in args.iter() {
                new_args.push(JsValue::from_json(v, &mut inner.context)
                    .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?);
            }
            let result = inner.call(name.as_str(), new_args)?;
            let result = result.to_json(&mut inner.context)
                .map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?;
            Ok(result)
        }).await.map_err(|e| js_err!(JSErrorCode::JsFailed, "{e}"))?
    }
}

fn require(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let arg = args.get_or_undefined(0);

    // BUG: Dev branch seems to be passing string arguments along with quotes
    let libfile = arg.to_string(ctx)?.to_std_string_escaped();
    let module_loader = ctx.downcast_module_loader::<SfoModuleLoader>().unwrap();
    let libfile = module_loader.commonjs_resolve_module(libfile.as_str())?;

    if let Some((_, module_obj)) = module_loader.get_commonjs(libfile.as_path()) {
        let exports = module_obj.as_object().unwrap().get(js_string!("exports"), ctx)?;
        return Ok(exports)
    }

    let buffer = read_to_string(libfile.clone())
        .map_err(|e| JsNativeError::typ().with_message(e.to_string()))?;

    let wrapper_code = format!(
        r#"export function cjs_module(exports, requireInner, module, __filename, __dirname) {{ {}
        }}"#,
        buffer
    );

    let module = Module::parse(Source::from_reader(wrapper_code.as_bytes(), Some(libfile.as_path())), None, ctx)?;
    let promise_result = module.load(ctx)
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    |_, _, module, context| {
                        // After loading, link all modules by resolving the imports
                        // and exports on the full module graph, initializing module
                        // environments. This returns a plain `Err` since all modules
                        // must link at the same time.
                        module.link(context)?;
                        Ok(JsValue::undefined())
                    },
                    module.clone(),
                )
                    .to_js_function(ctx.realm()),
            ),
            None,
            ctx,
        )
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    // Finally, evaluate the root module.
                    // This returns a `JsPromise` since a module could have
                    // top-level await statements, which defers module execution to the
                    // job queue.
                    |_, _, module, context| Ok(module.evaluate(context).into()),
                    module.clone(),
                )
                    .to_js_function(ctx.realm()),
            ),
            None,
            ctx,
        );
    ctx.run_jobs()?;

    match promise_result.state() {
        PromiseState::Pending => return Err(JsError::from_native(JsNativeError::typ().with_message("module didn't execute!"))),
        PromiseState::Fulfilled(v) => {
            assert_eq!(v, JsValue::undefined());
        }
        PromiseState::Rejected(err) => {
            let stacks = ctx.stack_trace();
            for stack in stacks {
                println!("{:?}", stack);
            }

            let err = JsError::from_opaque(err).try_native(ctx).unwrap();
            return Err(JsError::from_native(err));
        }
    }

    // let wrapper_func = ctx.eval(Source::from_bytes(&wrapper_code))?;

    // Adding custom object that mimics 'module.exports'
    let module_obj = JsObject::default(ctx.intrinsics());
    let exports_obj = JsObject::default(ctx.intrinsics());
    module_obj.set(js_string!("exports"), exports_obj.clone(), false, ctx)?;
    module_loader.insert_commonjs(libfile.clone(), module.clone(), JsValue::from(module_obj.clone()));

    let require = NativeFunction::from_fn_ptr(require).to_js_function(ctx.realm());
    let filename = libfile.to_string_lossy().to_string();
    let dirname = libfile.parent().unwrap().to_string_lossy().to_string();

    let commonjs_module = module.get_value(JsString::from("cjs_module"), ctx)?;
    if let Some(args) = commonjs_module.as_callable() {
        let result = args.call(
            &JsValue::null(),
            &[
                JsValue::from(exports_obj.clone()),
                JsValue::from(require),
                JsValue::from(module_obj.clone()),
                JsValue::from(JsString::from(filename)),
                JsValue::from(JsString::from(dirname)),
            ],
            ctx
        );
        if result.is_err() {
            let err = result.as_ref().err().unwrap();
            log::error!("{}", err);
            return result;
        }
        let exports = module_obj.get(js_string!("exports"), ctx)?;
        Ok(exports)
    } else {
        unreachable!()
    }


    // let wrapper_func = ctx.eval(Source::from_bytes(&wrapper_code))?;
    //
    // // Adding custom object that mimics 'module.exports'
    // let module_obj = JsObject::default(ctx.intrinsics());
    // let exports_obj = JsObject::default(ctx.intrinsics());
    // exports_obj.set(js_string!("__esModule"), JsValue::new(true), false, ctx)?;
    // module_obj.set(js_string!("exports"), exports_obj.clone(), false, ctx)?;
    //
    // let require = NativeFunction::from_fn_ptr(require).to_js_function(ctx.realm());
    // let filename = libfile.to_string_lossy().to_string();
    // let dirname = libfile.parent().unwrap().to_string_lossy().to_string();
    //
    // if let Some(args) = wrapper_func.as_callable() {
    //     args.call(
    //         &JsValue::null(),
    //         &[
    //             JsValue::from(exports_obj.clone()),
    //             JsValue::from(module_obj),
    //             JsValue::from(JsString::from(filename)),
    //             JsValue::from(JsString::from(dirname)),
    //         ],
    //         ctx
    //     )?;
    //     Ok(JsValue::from(exports_obj))
    // } else {
    //     unreachable!()
    // }
}
