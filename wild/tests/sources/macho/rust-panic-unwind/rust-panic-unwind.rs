//#Ignore:__eh_frame SUBTRACTOR relocations need correct FDE computation

fn main() {
    let r = std::panic::catch_unwind(|| panic!("test"));
    std::process::exit(if r.is_err() { 42 } else { 1 });
}
