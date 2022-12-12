//! Implement a configuration source based on command-line arguments.

use config::{ConfigError, Source, Value};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// Alias for the Result type from config.
type Result<T> = std::result::Result<T, ConfigError>;

/// A CmdLine holds a set of command-line arguments that augment a
/// configuration.
///
/// These arguments are formatted in toml, and concatenated into a
/// single toml object.  With arguments of the form "key=bareword",
/// the bareword is quoted for convenience.
#[derive(Debug, Clone)]
pub struct CmdLine {
    /// String for decorating Values.
    //
    // TODO(nickm): not yet used.
    #[allow(dead_code)]
    name: String,
    /// List of toml lines as given on the command line.
    contents: Vec<String>,
}

impl Default for CmdLine {
    fn default() -> Self {
        Self::new()
    }
}

impl CmdLine {
    /// Make a new empty command-line
    pub fn new() -> Self {
        CmdLine {
            name: "command line".to_string(),
            contents: Vec::new(),
        }
    }
    /// Add a single line of toml to the configuration.
    pub fn push_toml_line(&mut self, line: String) {
        self.contents.push(line);
    }
    /// Try to adjust the contents of a toml deserialization error so
    /// that instead it refers to a single command-line argument.
    fn convert_toml_error(&self, s: &str, pos: Option<(usize, usize)>) -> String {
        /// Regex to match an error message from the toml crate.
        static RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(.*?) at line [0-9]+ column [0-9]+$").expect("Can't compile regex")
        });
        let cap = RE.captures(s);
        let msg = match cap {
            Some(c) => c.get(1).expect("mismatch regex: no capture group").as_str(),
            None => s,
        };

        let location = match pos {
            Some((line, _col)) if line < self.contents.len() => {
                format!(" in {:?}", self.contents[line])
            }
            _ => " on command line".to_string(),
        };

        format!("{}{}", msg, location)
    }

    /// Compose elements of this cmdline into a single toml string.
    fn build_toml(&self) -> String {
        let mut toml_s = String::new();
        for line in &self.contents {
            toml_s.push_str(tweak_toml_bareword(line).as_ref().unwrap_or(line));
            toml_s.push('\n');
        }
        toml_s
    }
}

impl Source for CmdLine {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<HashMap<String, Value>> {
        let toml_s = self.build_toml();
        let toml_v: toml::Value = match toml::from_str(&toml_s) {
            Err(e) => {
                return Err(ConfigError::Message(
                    self.convert_toml_error(&e.to_string(), e.line_col()),
                ))
            }
            Ok(v) => v,
        };

        toml_v
            .try_into()
            .map_err(|e| ConfigError::Foreign(Box::new(e)))
    }
}

/// If `s` is a string of the form "keyword=bareword", return a new string
/// where `bareword` is quoted. Otherwise return None.
///
/// This isn't a smart transformation outside the context of 'config',
/// since many serde formats don't do so good a job when they get a
/// string when they wanted a number or whatever.  But 'config' is
/// pretty happy to convert strings to other stuff.
fn tweak_toml_bareword(s: &str) -> Option<String> {
    /// Regex to match a keyword=bareword item.
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?x:
               ^
                [ \t]*
                # first capture group: dotted barewords
                ((?:[a-zA-Z0-9_\-]+\.)*
                 [a-zA-Z0-9_\-]+)
                [ \t]*=[ \t]*
                # second group: one bareword without hyphens
                ([a-zA-Z0-9_]+)
                [ \t]*
                $)"#,
        )
        .expect("Built-in regex compilation failed")
    });

    RE.captures(s).map(|c| format!("{}=\"{}\"", &c[1], &c[2]))
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    #[test]
    fn bareword_expansion() {
        assert_eq!(tweak_toml_bareword("dsfklj"), None);
        assert_eq!(tweak_toml_bareword("=99"), None);
        assert_eq!(tweak_toml_bareword("=[1,2,3]"), None);
        assert_eq!(tweak_toml_bareword("a=b-c"), None);

        assert_eq!(tweak_toml_bareword("a=bc"), Some("a=\"bc\"".into()));
        assert_eq!(tweak_toml_bareword("a=b_c"), Some("a=\"b_c\"".into()));
        assert_eq!(
            tweak_toml_bareword("hello.there.now=a_greeting"),
            Some("hello.there.now=\"a_greeting\"".into())
        );
    }

    #[test]
    fn conv_toml_error() {
        let mut cl = CmdLine::new();
        cl.push_toml_line("Hello=world".to_string());
        cl.push_toml_line("Hola=mundo".to_string());
        cl.push_toml_line("Bonjour=monde".to_string());

        assert_eq!(
            &cl.convert_toml_error("Nice greeting at line 1 column 1", Some((0, 1))),
            "Nice greeting in \"Hello=world\""
        );

        assert_eq!(
            &cl.convert_toml_error("Nice greeting at line 1 column 1", Some((7, 1))),
            "Nice greeting on command line"
        );

        assert_eq!(
            &cl.convert_toml_error("Nice greeting with a thing", Some((0, 1))),
            "Nice greeting with a thing in \"Hello=world\""
        );
    }

    #[test]
    fn clone_into_box() {
        let mut cl = CmdLine::new();
        cl.push_toml_line("Molo=Lizwe".to_owned());
        let cl2 = cl.clone_into_box();

        let v = cl2.collect().unwrap();
        assert_eq!(v["Molo"], "Lizwe".into());
    }

    #[test]
    fn parse_good() {
        let mut cl = CmdLine::default();
        cl.push_toml_line("a=3".to_string());
        cl.push_toml_line("bcd=hello".to_string());
        cl.push_toml_line("ef=\"gh i\"".to_string());
        cl.push_toml_line("w=[1,2,3]".to_string());

        let v = cl.collect().unwrap();
        assert_eq!(v["a"], "3".into());
        assert_eq!(v["bcd"], "hello".into());
        assert_eq!(v["ef"], "gh i".into());
        assert_eq!(v["w"], vec![1, 2, 3].into());
    }

    #[test]
    fn parse_bad() {
        let mut cl = CmdLine::default();
        cl.push_toml_line("x=1 1 1 1 1".to_owned());
        let v = cl.collect();
        assert!(v.is_err());
    }
}
