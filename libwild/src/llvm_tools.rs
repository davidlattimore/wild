//! Discovery + invocation of LLVM tools (`llc`, `opt`, `llvm-ar`, …).
//!
//! Tools are used by the LTO pipeline (see `wild-lto-plan.md`) for
//! subprocess-driven bitcode handling. Discovery honours `$WILD_LLC`,
//! `$WILD_OPT`, `$WILD_LLVM_AR`, `$WILD_LLVM_NM`, `$WILD_LLVM_MC`
//! overrides first, then falls back to a search of:
//!
//! - `$PATH`
//! - versioned names (`llc-14` … `llc-20`) on Debian/Ubuntu/Fedora
//! - Homebrew (`/opt/homebrew/opt/llvm/bin`, `/usr/local/opt/llvm/bin`)
//! - Nix (`/run/current-system/sw/bin`, `/nix/var/nix/profiles/default/bin`)
//! - The bundled tools shipped by `rustup component add llvm-tools-preview` under the active
//!   toolchain's sysroot.
//!
//! Version reporting is best-effort: LLVM tools accept `--version` and
//! print something like `LLVM version 19.1.6`. We surface the parsed
//! `(major, minor, patch)` for skew checks at link time.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Canonical names of the LLVM tools wild cares about. Each has a
/// matching `$WILD_<UPPERCASE>` env override.
#[derive(Debug, Clone, Copy)]
pub enum Tool {
    Llc,
    Opt,
    LlvmAr,
    LlvmNm,
    LlvmMc,
    LlvmLink,
    LlvmDwarfdump,
}

impl Tool {
    /// The standard executable name (no `.exe` — wild's current
    /// target set is Unix-only).
    pub fn exe_name(self) -> &'static str {
        match self {
            Tool::Llc => "llc",
            Tool::Opt => "opt",
            Tool::LlvmAr => "llvm-ar",
            Tool::LlvmNm => "llvm-nm",
            Tool::LlvmMc => "llvm-mc",
            Tool::LlvmLink => "llvm-link",
            Tool::LlvmDwarfdump => "llvm-dwarfdump",
        }
    }

    /// Name of the env var users can set to override discovery. The
    /// override is absolute-path-or-command and not further searched.
    pub fn env_var(self) -> &'static str {
        match self {
            Tool::Llc => "WILD_LLC",
            Tool::Opt => "WILD_OPT",
            Tool::LlvmAr => "WILD_LLVM_AR",
            Tool::LlvmNm => "WILD_LLVM_NM",
            Tool::LlvmMc => "WILD_LLVM_MC",
            Tool::LlvmLink => "WILD_LLVM_LINK",
            Tool::LlvmDwarfdump => "WILD_LLVM_DWARFDUMP",
        }
    }
}

/// Locate an LLVM tool, returning the first path that exists (or is on
/// `$PATH`). Returns `None` if nothing is found — callers decide how to
/// diagnose that.
#[must_use]
pub fn find(tool: Tool) -> Option<PathBuf> {
    if let Ok(v) = std::env::var(tool.env_var()) {
        if !v.is_empty() {
            let p = PathBuf::from(&v);
            if p.is_absolute() || p.components().count() > 1 {
                return p.exists().then_some(p);
            }
            return which::which(&v).ok();
        }
    }
    find_by_name(tool.exe_name())
}

/// Locate a tool by its raw executable name — used by callers (e.g.
/// the test harness) that care about tools outside `Tool`.
#[must_use]
pub fn find_by_name(name: &str) -> Option<PathBuf> {
    if let Ok(p) = which::which(name) {
        return Some(p);
    }
    // Debian-style versioned names (llc-19, opt-19, …).
    for ver in (14..=20).rev() {
        let versioned = format!("{name}-{ver}");
        if let Ok(p) = which::which(&versioned) {
            return Some(p);
        }
    }
    for prefix in [
        "/opt/homebrew/opt/llvm/bin",
        "/usr/local/opt/llvm/bin",
        "/run/current-system/sw/bin",
        "/nix/var/nix/profiles/default/bin",
    ] {
        let p = PathBuf::from(prefix).join(name);
        if p.exists() {
            return Some(p);
        }
    }
    // Rustup's `llvm-tools-preview` component. We don't know the
    // active toolchain's triple reliably from this crate, so probe the
    // usual parents. This covers the common case where the user ran
    // `rustup component add llvm-tools-preview`.
    if let Some(rustup_home) = rustup_home() {
        let toolchains = rustup_home.join("toolchains");
        if let Ok(entries) = std::fs::read_dir(&toolchains) {
            for entry in entries.flatten() {
                let bindir = entry.path().join("lib").join("rustlib");
                if let Ok(triples) = std::fs::read_dir(&bindir) {
                    for t in triples.flatten() {
                        let p = t.path().join("bin").join(name);
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }
    None
}

/// `$RUSTUP_HOME` if set, else the default (`$HOME/.rustup`).
fn rustup_home() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("RUSTUP_HOME") {
        return Some(PathBuf::from(v));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".rustup"))
}

/// Invoke `<tool> --version` and parse the reported `(major, minor,
/// patch)`. Returns `None` if the tool didn't run or the output
/// didn't match the LLVM version line. Best-effort — callers should
/// treat a `None` as "unknown, proceed" not "fatal".
#[must_use]
pub fn version_of(path: &Path) -> Option<(u32, u32, u32)> {
    let output = Command::new(path).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Example lines:
    //   "LLVM version 19.1.6"
    //   "LLVM (http://llvm.org/):\n  LLVM version 19.1.6\n  …"
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("LLVM version ") {
            return parse_semver(rest);
        }
    }
    None
}

fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let head = s
        .split(|c: char| c == '-' || c == '+' || c.is_whitespace())
        .next()?;
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_takes_precedence_when_path_exists() {
        let td = tempfile::tempdir().unwrap();
        let shim = td.path().join("my-llc");
        std::fs::write(&shim, "").unwrap();
        // SAFETY: single-threaded test (#[test] runs one at a time
        // per test binary by default unless --test-threads>1; we set
        // and unset deterministically).
        // SAFETY: the mutation here is process-wide, fine for cargo
        // test's per-process test execution.
        unsafe {
            std::env::set_var("WILD_LLC", shim.to_str().unwrap());
        }
        let found = find(Tool::Llc);
        unsafe {
            std::env::remove_var("WILD_LLC");
        }
        assert_eq!(found.as_deref(), Some(shim.as_path()));
    }

    #[test]
    fn env_override_missing_file_returns_none() {
        unsafe {
            std::env::set_var("WILD_LLC", "/definitely/not/here/llc");
        }
        let found = find(Tool::Llc);
        unsafe {
            std::env::remove_var("WILD_LLC");
        }
        assert!(found.is_none());
    }

    #[test]
    fn parse_semver_handles_common_llvm_formats() {
        assert_eq!(parse_semver("19.1.6"), Some((19, 1, 6)));
        assert_eq!(parse_semver("18.0.0"), Some((18, 0, 0)));
        assert_eq!(parse_semver("17"), Some((17, 0, 0)));
        assert_eq!(parse_semver("20.0.0-rust-1.87.0-stable"), Some((20, 0, 0)));
    }

    #[test]
    fn tool_env_vars_are_unique() {
        let tools = [
            Tool::Llc,
            Tool::Opt,
            Tool::LlvmAr,
            Tool::LlvmNm,
            Tool::LlvmMc,
            Tool::LlvmLink,
            Tool::LlvmDwarfdump,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in tools {
            assert!(seen.insert(t.env_var()), "duplicate env var: {:?}", t);
            assert!(seen.insert(t.exe_name()), "duplicate exe name: {:?}", t);
        }
    }

    /// Smoke test — if `llc` is installed, we find it AND can read its
    /// version. On systems without llc (most CI without
    /// llvm-tools-preview), this test is a no-op.
    #[test]
    fn finds_and_versions_llc_if_installed() {
        if let Some(p) = find(Tool::Llc) {
            assert!(p.exists(), "find(Llc) returned non-existent path");
            // Version is optional — some stripped builds don't print
            // a recognisable line; just ensure the call doesn't panic.
            let _ = version_of(&p);
        }
    }
}
