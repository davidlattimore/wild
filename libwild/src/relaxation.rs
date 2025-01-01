#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}
