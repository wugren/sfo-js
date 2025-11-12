#[cfg(test)]
mod test_engine {
    use sfo_js::{js_value, JsEngine};

    #[test]
    fn test_code() {
        let js = r#"
        function add(a, b) {
            return a + b;
        }
        let ret = add(1, 2);
        console.log(ret);
        ret
        "#;

        let engine = JsEngine::new();
        assert!(engine.is_ok());
        let mut engine = engine.unwrap();
        let ret = engine.eval_string(js);
        assert!(ret.is_ok());
    }


    #[test]
    fn test_arg() {
        let js = r#"
        export function args(p1, p2) {
            let arg_str = process.argv.join(" ");
            return arg_str + " " + p1 + " " + p2;
        }
        "#;

        let engine = JsEngine::new();
        assert!(engine.is_ok());
        let mut engine = engine.unwrap();
        let ret = engine.eval_string_with_args(js, "argv1 argv2");
        assert!(ret.is_ok());
        let ret = engine.call("args", vec![js_value!("test"), js_value!("test2")]);
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap().as_string().unwrap(), "argv1 argv2 test test2");
    }
}
