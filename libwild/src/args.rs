//! A handwritten parser for our arguments.
//!
//! We don't currently use a 3rd party library like clap for a few reasons. Firstly, we need to
//! support flags like `--push-state` and `--pop-state`. These need to push and pop a state stack
//! when they're parsed. Some of the other flags then need to manipulate the state of the top of the
//! stack. Positional arguments like input files and libraries to link, then need to have the
//! current state of the stack attached to that file.
//!
//! Secondly, long arguments need to also be accepted with a single '-' in addition to the more
//! common double-dash.
//!
//! Basically, we need to be able to parse arguments in the same way as the other linkers on the
//! platform that we're targeting.

use std::num::NonZeroUsize;

use jobserver::Acquired;
use rayon::ThreadPoolBuilder;
use crate::error::Result;

pub mod elf;
pub use elf::*;

use crate::timing_phase;

#[derive(Debug)]
pub struct Args<T = TargetArgs> {
    // ── Format-specific ──────────────────────────────────────────────────────
    pub target_args: T,
}

impl<T> std::ops::Deref for Args<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.target_args
    }
}

impl<T> std::ops::DerefMut for Args<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.target_args
    }
}

impl<T> Args<T> {
    pub fn new(target_args: T) -> Self {
        Self { target_args }
    }

    /// Sets up the thread pool, using the explicit number of threads if specified,
    /// or falling back to the jobserver protocol if available.
    ///
    /// <https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html>
    pub fn activate_thread_pool(mut self) -> Result<ActivatedArgs<T>> {
        timing_phase!("Activate thread pool");

        let mut tokens = Vec::new();
        self.available_threads = self.num_threads.unwrap_or_else(|| {
            if let Some(client) = &self.jobserver_client {
                while let Ok(Some(acquired)) = client.try_acquire() {
                    tokens.push(acquired);
                }
                tracing::trace!(count = tokens.len(), "Acquired jobserver tokens");
                // Our parent "holds" one jobserver token, add it.
                NonZeroUsize::new((tokens.len() + 1).max(1)).unwrap()
            } else {
                std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap())
            }
        });

        // The pool might be already initialized, suppress the error intentionally.
        let _ = ThreadPoolBuilder::new()
            .num_threads(self.available_threads.get())
            .build_global();

        Ok(ActivatedArgs {
            args: self,
            _jobserver_tokens: tokens,
        })
    }
}

/// Represents a command-line argument that specifies the number of threads to use,
/// triggering activation of the thread pool.
pub struct ActivatedArgs<T = TargetArgs> {
    pub args: Args<T>,
    _jobserver_tokens: Vec<Acquired>,
}
pub enum TargetArgs {
    Elf(elf::ElfArgs),
}

impl std::fmt::Debug for TargetArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetArgs::Elf(e) => e.fmt(f),
        }
    }
}
