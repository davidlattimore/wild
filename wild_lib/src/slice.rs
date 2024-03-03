/// Removes `prefix` elements from `data` and returns them. Once `take_mut` on core::slice is
/// stable, we can use that instead.
#[track_caller]
pub(crate) fn slice_take_prefix_mut<'t, T>(data: &mut &'t mut [T], prefix: usize) -> &'t mut [T] {
    let len = data.len();
    if prefix > len {
        panic!("Attempted to slice {prefix} elements when only {len} available");
    }
    let owned_data = core::mem::take(data);
    let (prefix, rest) = owned_data.split_at_mut(prefix);
    *data = rest;
    prefix
}

pub(crate) fn take_first_mut<'t, T>(data: &mut &'t mut [T]) -> Option<&'t mut T> {
    if data.is_empty() {
        None
    } else {
        let owned_data = core::mem::take(data);
        let (prefix, rest) = owned_data.split_at_mut(1);
        *data = rest;
        Some(&mut prefix[0])
    }
}
