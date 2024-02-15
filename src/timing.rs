//! Code for reporting how long each phase of linking takes when the --time argument is supplied.

use std::time::Instant;

pub(crate) struct Timing {
    active: bool,
    start: Instant,
    last: Instant,
}

impl Timing {
    pub(crate) fn new(active: bool) -> Timing {
        let start = Instant::now();
        Self {
            active,
            last: start,
            start,
        }
    }

    pub(crate) fn complete(&mut self, phase: &str) {
        if !self.active {
            return;
        }
        let now = Instant::now();
        println!(
            "{phase}: {:0.2} ms",
            now.duration_since(self.last).as_secs_f64() * 1000.0
        );
        self.last = now;
    }
}

impl Drop for Timing {
    fn drop(&mut self) {
        if self.active {
            self.complete("Free resources");
            println!(
                "Total: {:0.2} ms",
                self.start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}
