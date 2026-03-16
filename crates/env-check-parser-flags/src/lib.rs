//! Parser flag model used by source discovery and configuration.

use anyhow::{Context, bail};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Parser {
    Node,
    Python,
    Go,
}

impl Parser {
    fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
            Self::Go => "go",
        }
    }
}

fn parse_parser_name(value: &str) -> Option<Parser> {
    match value.trim().to_lowercase().as_str() {
        "node" | "nodejs" | "node.js" => Some(Parser::Node),
        "python" | "py" => Some(Parser::Python),
        "go" | "golang" => Some(Parser::Go),
        _ => None,
    }
}

fn available_parsers() -> Vec<Parser> {
    let mut parsers = Vec::new();

    if cfg!(feature = "parser-node") {
        parsers.push(Parser::Node);
    }
    if cfg!(feature = "parser-python") {
        parsers.push(Parser::Python);
    }
    if cfg!(feature = "parser-go") {
        parsers.push(Parser::Go);
    }

    parsers
}

fn parser_ids_set_from(names: &[String]) -> anyhow::Result<BTreeSet<Parser>> {
    let mut out = BTreeSet::new();
    for raw in names {
        let parsed =
            parse_parser_name(raw).with_context(|| format!("unsupported parser '{raw}'"))?;
        out.insert(parsed);
    }
    Ok(out)
}

#[cfg(test)]
fn supported_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = available_parsers()
        .into_iter()
        .map(Parser::as_str)
        .collect();
    names.sort_unstable();
    names
}

#[derive(Debug, Clone, Default)]
pub struct ParserFilters {
    node: bool,
    python: bool,
    go: bool,
}

impl ParserFilters {
    /// Build filters from available crate-level parser features.
    pub fn all() -> Self {
        Self {
            node: cfg!(feature = "parser-node"),
            python: cfg!(feature = "parser-python"),
            go: cfg!(feature = "parser-go"),
        }
    }

    /// Compute active parser flags from config `sources.enabled` / `sources.disabled`.
    pub fn from_config(enabled: &[String], disabled: &[String]) -> anyhow::Result<Self> {
        let mut enabled_set =
            parser_ids_set_from(enabled).context("invalid parser in sources.enabled")?;
        let disabled_set =
            parser_ids_set_from(disabled).context("invalid parser in sources.disabled")?;

        let available: BTreeSet<Parser> = available_parsers().into_iter().collect();
        let overlap: Vec<_> = enabled_set.intersection(&disabled_set).collect();
        if !overlap.is_empty() {
            let overlapping: Vec<_> = overlap.iter().map(|p| p.as_str()).collect();
            bail!(
                "parsers appear in both sources.enabled and sources.disabled: {}",
                overlapping.join(", ")
            );
        }

        if enabled_set.is_empty() {
            for parser in available.iter() {
                enabled_set.insert(*parser);
            }
            for parser in disabled_set.iter() {
                enabled_set.remove(parser);
            }
        } else {
            for parser in enabled_set.iter() {
                if !available.contains(parser) {
                    bail!(
                        "sources.enabled includes '{}' but parser crate is unavailable in this build",
                        parser.as_str()
                    );
                }
            }
            for parser in disabled_set {
                enabled_set.remove(&parser);
            }
        }

        Ok(Self {
            node: enabled_set.contains(&Parser::Node),
            python: enabled_set.contains(&Parser::Python),
            go: enabled_set.contains(&Parser::Go),
        })
    }

    pub fn node_enabled(&self) -> bool {
        self.node
    }

    pub fn python_enabled(&self) -> bool {
        self.python
    }

    pub fn go_enabled(&self) -> bool {
        self.go
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_parser_aliases() {
        assert!(matches!(parse_parser_name("nodejs"), Some(Parser::Node)));
        assert!(matches!(parse_parser_name("NODE"), Some(Parser::Node)));
        assert!(matches!(parse_parser_name("py"), Some(Parser::Python)));
        assert!(matches!(parse_parser_name("GOLANG"), Some(Parser::Go)));
    }

    #[test]
    fn parse_filters_supports_overlap_error() {
        let err = parser_ids_set_from(&[String::from("node"), String::from("bad")]).unwrap_err();
        assert!(err.to_string().contains("unsupported parser 'bad'"));
    }

    #[test]
    fn from_config_rejects_overlap_and_bad_inputs() {
        let supported = supported_names();
        assert!(!supported.is_empty());

        let err =
            ParserFilters::from_config(&[String::from("node")], &[String::from("bad-parser")])
                .unwrap_err();
        assert!(format!("{err:#}").contains("unsupported parser 'bad-parser'"));

        let err = ParserFilters::from_config(&[String::from("node")], &[String::from("node")])
            .unwrap_err();
        assert!(format!("{err:#}").contains("parsers appear in both"));
    }
}
