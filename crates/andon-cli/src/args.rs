//! A tiny flag parser.
//!
//! Hand-rolled for the reason `andon-spike` and `andon-registry-lint` give for
//! theirs: this workspace's supply-chain gate is `cargo deny check licenses bans
//! sources`, and an argument parser is a transitive dependency tree admitted
//! into a binary whose pitch is that its supply chain is auditable. Six
//! subcommands and a dozen flags do not pay for that.
//!
//! Switches are declared rather than inferred. `--json` with no declaration
//! would swallow the next argument as its value, so a caller writing
//! `andon measure --json --repo .` would silently measure a repository called
//! `--repo`. Declaring the switch set makes that a parse error instead.

/// Parsed command-line arguments for one subcommand.
#[derive(Debug, Default)]
pub struct Flags {
    values: Vec<(String, String)>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Flags {
    /// Parse `args`, treating every name in `switch_names` as a value-less flag.
    pub fn parse(
        args: impl Iterator<Item = String>,
        switch_names: &[&str],
    ) -> Result<Self, String> {
        let mut flags = Flags::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if switch_names.contains(&name) {
                    flags.switches.push(name.to_string());
                } else if let Some((name, value)) = name.split_once('=') {
                    flags.values.push((name.to_string(), value.to_string()));
                } else {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("--{name} needs a value"))?;
                    flags.values.push((name.to_string(), value));
                }
            } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
                // `-h` is the only short form, and it is an alias rather than a
                // family: a CLI that accepts `-r` for `--repo` invites a caller
                // to guess, and a guess that resolves to the wrong flag is worse
                // than a refusal.
                if short == "h" {
                    flags.switches.push("help".to_string());
                } else {
                    return Err(format!("unknown flag '-{short}'"));
                }
            } else {
                flags.positional.push(arg);
            }
        }
        Ok(flags)
    }

    /// The last value given for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether a switch was given.
    pub fn on(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Positional arguments, in the order given.
    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// The first positional argument, if any.
    pub fn first(&self) -> Option<&str> {
        self.positional.first().map(String::as_str)
    }

    /// A path value, or `default` when the flag was not given.
    pub fn path(&self, name: &str, default: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(self.get(name).unwrap_or(default))
    }

    /// Refuse any value flag this subcommand does not declare.
    ///
    /// A mistyped `--registryy` that is silently ignored is a caller running
    /// under a configuration they believe is in force and is not — the same
    /// argument `Policy` makes for `deny_unknown_fields`.
    pub fn reject_unknown(&self, known: &[&str]) -> Result<(), String> {
        for (key, _) in &self.values {
            if !known.contains(&key.as_str()) {
                return Err(format!("unknown option '--{key}'"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], switches: &[&str]) -> Result<Flags, String> {
        Flags::parse(args.iter().map(|s| s.to_string()), switches)
    }

    #[test]
    fn a_declared_switch_does_not_eat_the_next_argument() {
        // The failure this exists to prevent: `--json` consuming `--repo` as its
        // value and the tool measuring a repository named `--repo`.
        let flags = parse(&["--json", "--repo", "/tmp/x"], &["json"]).expect("parses");
        assert!(flags.on("json"));
        assert_eq!(flags.get("repo"), Some("/tmp/x"));
    }

    #[test]
    fn an_equals_form_is_the_same_as_a_separated_one() {
        let a = parse(&["--base=HEAD~1"], &[]).expect("parses");
        let b = parse(&["--base", "HEAD~1"], &[]).expect("parses");
        assert_eq!(a.get("base"), b.get("base"));
    }

    #[test]
    fn a_value_flag_with_no_value_is_a_refusal() {
        assert!(parse(&["--base"], &[]).is_err());
    }

    #[test]
    fn an_unknown_option_is_refused_rather_than_ignored() {
        let flags = parse(&["--registryy", "x"], &[]).expect("parses");
        assert!(flags.reject_unknown(&["registry"]).is_err());
    }

    #[test]
    fn an_unknown_short_flag_is_refused() {
        assert!(parse(&["-r"], &[]).is_err());
    }
}
