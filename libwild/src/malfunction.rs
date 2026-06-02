//! Contains code that allows us to cause the linker to malfunction in certain ways. This is used to
//! test our tests and to test linker-diff.

pub const ENV_NAME: &str = "WILD_MALFUNCTION";

#[inline(always)]
pub(crate) fn malfunction_point(name: &str) -> bool {
    cfg!(debug_assertions) && std::env::var(ENV_NAME).is_ok_and(|v| v == name)
}

#[macro_export]
macro_rules! malfunction_point_ret {
    ($name:expr, $val:expr) => {
        if $crate::malfunction::malfunction_point($name) {
            return $val;
        }
    };
}
