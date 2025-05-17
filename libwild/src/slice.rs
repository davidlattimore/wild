/// Removes `prefix` elements from `data` and returns them.
#[track_caller]
pub(crate) fn slice_take_prefix_mut<'t, T>(data: &mut &'t mut [T], prefix: usize) -> &'t mut [T] {
    data.split_off_mut(..prefix)
        .unwrap_or_else(|| {
            panic!(
                "Attempted to slice {prefix} elements when only {len} available",
                len = data.len()
            )
        })
}

pub(crate) fn try_slice_take_prefix_mut<'t, T>(
    data: &mut &'t mut [T],
    prefix: usize,
) -> Option<&'t mut [T]> {
    data.split_off_mut(..prefix)
}

pub(crate) fn take_first_mut<'t, T>(data: &mut &'t mut [T]) -> Option<&'t mut T> {
    data.split_off_first_mut()
}
