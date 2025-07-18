//! Implement a configuration source based on command-line arguments.

use regex::Regex;
use std::sync::LazyLock;

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
    fn convert_toml_error(
        &self,
        toml_str: &str,
        error_message: &str,
        span: &Option<std::ops::Range<usize>>,
    ) -> String {
        // Function to translate a string index to a 0-offset line number.
        let linepos = |idx| toml_str.bytes().take(idx).filter(|b| *b == b'\n').count();

        // Find the source position as a line within toml_str, and convert that
        // to an index into self.contents.
        let source_line = span
            .as_ref()
            .and_then(|range| {
                let startline = linepos(range.start);
                let endline = linepos(range.end);
                (startline == endline).then_some(startline)
            })
            .and_then(|pos| self.contents.get(pos));

        match (source_line, span.as_ref()) {
            (Some(source), _) => {
                format!("Couldn't parse command line: {error_message} in {source:?}")
            }
            (None, Some(range)) if toml_str.get(range.clone()).is_some() => format!(
                "Couldn't parse command line: {error_message} within {:?}",
                &toml_str[range.clone()]
            ),
            _ => format!("Couldn't parse command line: {error_message}"),
        }
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

impl figment::Provider for CmdLine {
    fn metadata(&self) -> figment::Metadata {
        figment::Metadata::named("command line")
    }

    fn data(&self) -> figment::Result<figment::value::Map<figment::Profile, figment::value::Dict>> {
        let toml_str = self.build_toml();
        let toml: toml::Value = toml::from_str(&toml_str).map_err(|toml_err| {
            self.convert_toml_error(&toml_str, toml_err.message(), &toml_err.span())
        })?;

        figment::providers::Serialized::defaults(toml).data()
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
    static RE: LazyLock<Regex> = LazyLock::new(|| {
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
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use figment::Provider as _;

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
        let toml_s = cl.build_toml();

        assert_eq!(
            &cl.convert_toml_error(&toml_s, "Nice greeting", &Some(0..13)),
            "Couldn't parse command line: Nice greeting in \"Hello=world\""
        );

        assert_eq!(
            &cl.convert_toml_error(&toml_s, "Nice greeting", &Some(99..333)),
            "Couldn't parse command line: Nice greeting"
        );

        assert_eq!(
            &cl.convert_toml_error(&toml_s, "Nice greeting with a thing", &Some(0..13)),
            "Couldn't parse command line: Nice greeting with a thing in \"Hello=world\""
        );
    }

    #[test]
    fn parse_good() {
        let mut cl = CmdLine::default();
        cl.push_toml_line("a=3".to_string());
        cl.push_toml_line("bcd=hello".to_string());
        cl.push_toml_line("ef=\"gh i\"".to_string());
        cl.push_toml_line("w=[1,2,3]".to_string());

        let v = cl
            .data()
            .unwrap()
            .remove(&figment::Profile::Default)
            .unwrap();

        assert_eq!(v["a"], "3".into());
        assert_eq!(v["bcd"], "hello".into());
        assert_eq!(v["ef"], "gh i".into());
        assert_eq!(v["w"], vec![1, 2, 3].into());
    }

    #[test]
    fn parse_bad() {
        let mut cl = CmdLine::default();
        cl.push_toml_line("x=1 1 1 1 1".to_owned());
        let v = cl.data();
        assert!(v.is_err());
    }
}
