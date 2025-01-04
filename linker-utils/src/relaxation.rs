#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}
