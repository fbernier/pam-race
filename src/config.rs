//! Module arguments, parsed.

use std::fmt;
use std::time::Duration;

use crate::types::{AbsPath, ServiceName};

const DEFAULT_HELPER: &str = match option_env!("PAM_RACE_HELPER") {
    Some(p) => p,
    None => "/usr/lib/pam-race/pam-race-helper",
};
/// Covers fprintd claiming a slow sensor (measured ~0.3–0.4 s on a Goodix
/// MOC reader) while still bounding the delay before a prompt.
pub const DEFAULT_SETTLE: Duration = Duration::from_millis(600);
pub const MAX_SETTLE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Config {
    pub debug: bool,
    /// How long prompts may wait for every helper to speak first.
    pub settle: Duration,
    pub helper: AbsPath,
    /// PAM configuration directory for the sub-stacks (default: libpam's).
    pub confdir: Option<AbsPath>,
    /// Non-empty, in configuration order.
    pub services: Vec<ServiceName>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    NotUtf8,
    BadService(String),
    DuplicateService(String),
    BadSettle(String),
    NotAbsolute(&'static str),
    UnknownOption(String),
    NoServices,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NotUtf8 => write!(f, "argument is not UTF-8"),
            ConfigError::BadService(s) => write!(f, "invalid service name {s:?}"),
            ConfigError::DuplicateService(s) => write!(f, "service {s:?} given twice"),
            ConfigError::BadSettle(s) => write!(f, "invalid settle value {s:?}"),
            ConfigError::NotAbsolute(o) => write!(f, "{o}= needs an absolute path"),
            ConfigError::UnknownOption(o) => write!(f, "unknown option {o:?}"),
            ConfigError::NoServices => write!(f, "no services given"),
        }
    }
}

impl Config {
    /// `[debug] [settle=MS] [helper=PATH] [confdir=DIR] SERVICE...`
    pub fn parse<'a>(args: impl IntoIterator<Item = &'a [u8]>) -> Result<Config, ConfigError> {
        let mut cfg = Config {
            debug: false,
            settle: DEFAULT_SETTLE,
            helper: AbsPath::parse(DEFAULT_HELPER.as_bytes())
                .expect("default helper path is absolute"),
            confdir: None,
            services: Vec::new(),
        };
        for arg in args {
            let s = std::str::from_utf8(arg).map_err(|_| ConfigError::NotUtf8)?;
            match s.split_once('=') {
                None if s == "debug" => cfg.debug = true,
                None => {
                    let service =
                        ServiceName::parse(arg).ok_or_else(|| ConfigError::BadService(s.into()))?;
                    if cfg.services.contains(&service) {
                        return Err(ConfigError::DuplicateService(s.into()));
                    }
                    cfg.services.push(service);
                }
                Some(("settle", v)) => {
                    let ms: u64 = v.parse().map_err(|_| ConfigError::BadSettle(v.into()))?;
                    cfg.settle = Duration::from_millis(ms).min(MAX_SETTLE);
                }
                Some(("helper", v)) => {
                    cfg.helper =
                        AbsPath::parse(v.as_bytes()).ok_or(ConfigError::NotAbsolute("helper"))?
                }
                Some(("confdir", v)) => {
                    cfg.confdir = Some(
                        AbsPath::parse(v.as_bytes()).ok_or(ConfigError::NotAbsolute("confdir"))?,
                    )
                }
                Some((k, _)) => return Err(ConfigError::UnknownOption(k.into())),
            }
        }
        if cfg.services.is_empty() {
            return Err(ConfigError::NoServices);
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, ConfigError> {
        Config::parse(args.iter().map(|s| s.as_bytes()))
    }

    #[test]
    fn service_names_cannot_escape_the_config_dir() {
        for bad in ["../shadow", "a/b", ".hidden", "a b", "a\0b"] {
            assert_eq!(
                parse(&[bad]).unwrap_err(),
                ConfigError::BadService(bad.into())
            );
        }
        assert!(parse(&["system-auth", "sudo-fprint", "x_y.z+1"]).is_ok());
    }

    #[test]
    fn options_and_services() {
        assert_eq!(parse(&["debug"]).unwrap_err(), ConfigError::NoServices);
        assert_eq!(
            parse(&["helper=rel", "a"]).unwrap_err(),
            ConfigError::NotAbsolute("helper")
        );
        assert_eq!(
            parse(&["bogus=1", "a"]).unwrap_err(),
            ConfigError::UnknownOption("bogus".into())
        );
        assert_eq!(
            parse(&["a", "b", "a"]).unwrap_err(),
            ConfigError::DuplicateService("a".into()),
            "a service cannot race itself"
        );
        let c = parse(&["settle=999999", "a", "debug", "b"]).unwrap();
        assert_eq!(c.settle, MAX_SETTLE);
        assert!(c.debug);
        let names: Vec<String> = c.services.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["a", "b"]);
    }
}
