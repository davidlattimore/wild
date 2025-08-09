use crate::args::CounterKind;

pub(crate) struct CounterList {}

impl CounterList {
    pub(crate) fn from_kinds(_opts: &[CounterKind]) -> Self {
        CounterList {}
    }

    pub(crate) fn start(&self) {
        let _ = self;
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn disable_and_read(&self) -> Vec<u64> {
        let _ = self;
        Vec::new()
    }
}
