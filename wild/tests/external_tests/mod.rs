#[cfg(feature = "mold_tests")]
mod mold_tests;

use crate::Filter;
use crate::Result;
use libtest_mimic::Trial;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::OnceLock;

pub(super) fn collect_tests(tests: &mut Vec<Trial>, filter: &Filter) -> Result {
    #[cfg(feature = "mold_tests")]
    {
        mold_tests::collect_tests(tests, filter)?;
    }

    let _ = (tests, filter);

    Ok(())
}

#[derive(Clone, Debug)]
enum ExternalLinker {
    Wild,
    ThirdParty { name: String, path: PathBuf },
}

impl ExternalLinker {
    fn is_wild(&self) -> bool {
        matches!(self, ExternalLinker::Wild)
    }

    fn name(&self) -> &str {
        match self {
            ExternalLinker::Wild => "wild",
            ExternalLinker::ThirdParty { name, .. } => name.as_str(),
        }
    }
}

fn get_external_linker() -> &'static ExternalLinker {
    static VALUE: OnceLock<ExternalLinker> = OnceLock::new();
    VALUE.get_or_init(|| {
        let Ok(val) = env::var("WILD_EXTERNAL_LINKER") else {
            return ExternalLinker::Wild;
        };
        let val = val.trim();
        if val.is_empty() || val.eq_ignore_ascii_case("wild") {
            return ExternalLinker::Wild;
        }

        let (name, search_names): (&str, &[&str]) = match val.to_ascii_lowercase().as_str() {
            "ld" | "bfd" => ("ld", &["ld.bfd", "ld"]),
            "lld" => ("lld", &["ld.lld"]),
            "mold" => ("mold", &["mold"]),
            "gold" => ("gold", &["ld.gold", "gold"]),
            _ => {
                let p = PathBuf::from(&val);
                if p.exists() {
                    return ExternalLinker::ThirdParty {
                        name: val.to_string(),
                        path: std::fs::canonicalize(&p)
                            .expect("failed to canonicalize WILD_EXTERNAL_LINKER path"),
                    };
                }

                let path = which::which(val).unwrap_or_else(|_| {
                    panic!("WILD_EXTERNAL_LINKER={val}: not found as a file and not on PATH")
                });

                return ExternalLinker::ThirdParty {
                    name: val.to_string(),
                    path,
                };
            }
        };

        let path = search_names
            .iter()
            .find_map(|n| which::which(n).ok())
            .unwrap_or_else(|| {
                panic!(
                    "WILD_EXTERNAL_LINKER={val}: could not find any of [{}] on PATH",
                    search_names.join(", ")
                )
            });

        ExternalLinker::ThirdParty {
            name: name.to_string(),
            path,
        }
    })
}

fn get_fakes_dir() -> &'static Path {
    static DIR: OnceLock<FakesDir> = OnceLock::new();
    DIR.get_or_init(|| FakesDir::new(get_external_linker()))
        .path()
}

enum FakesDir {
    Static(PathBuf),
    Temp(tempfile::TempDir),
}

impl FakesDir {
    fn new(linker: &ExternalLinker) -> Self {
        match linker {
            ExternalLinker::Wild => {
                let current_dir = env::current_dir().expect("failed to get current directory");
                let fakes = current_dir.parent().unwrap().join("fakes-debug");
                assert!(
                    fakes.exists(),
                    "fakes-debug directory not found at {}",
                    fakes.display()
                );
                FakesDir::Static(fakes)
            }
            ExternalLinker::ThirdParty { path, name } => {
                let tmp = tempfile::tempdir()
                    .expect("failed to create temp directory for external linker fakes");
                let tmp_path = tmp.path();

                for link_name in &["mold", "ld", "ld.lld"] {
                    let link = tmp_path.join(link_name);
                    std::os::unix::fs::symlink(path, &link).unwrap_or_else(|e| {
                        panic!(
                            "failed to create symlink {} -> {}: {e}",
                            link.display(),
                            path.display()
                        )
                    });
                }

                eprintln!(
                    "external_tests: using linker '{name}' ({}) via fakes dir {}",
                    path.display(),
                    tmp_path.display()
                );

                FakesDir::Temp(tmp)
            }
        }
    }

    fn path(&self) -> &Path {
        match self {
            FakesDir::Static(p) => p.as_path(),
            FakesDir::Temp(t) => t.path(),
        }
    }
}

#[allow(unused)]
fn should_not_ignore_tests(external_test: &str) -> bool {
    let wild_ignore_skip: Option<Vec<String>> =
        std::env::var("WILD_IGNORE_SKIP").ok().map(|test_suites| {
            test_suites
                .split(',')
                .map(|suite| suite.trim().to_string())
                .filter(|suite| !suite.is_empty())
                .collect()
        });

    wild_ignore_skip.is_some_and(|tests| {
        tests.contains(&external_test.to_string()) || tests.contains(&"all".to_string())
    })
}

#[allow(unused)]
fn using_third_party_linker() -> bool {
    !get_external_linker().is_wild()
}

#[allow(unused)]
fn external_linker_name() -> &'static str {
    get_external_linker().name()
}

#[allow(unused)]
fn run_external_test(external_test: &Path, extra_env: &[(&str, &str)]) -> Result<Output> {
    let fakes_dir = get_fakes_dir();

    let mut command = Command::new("bash");
    command
        .current_dir(fakes_dir)
        .arg("-c")
        .arg(format!("{} 2>&1", external_test.display()));

    for (key, value) in extra_env {
        command.env(key, value);
    }

    command.output().map_err(Into::into)
}
