//#Ignore:__eh_frame needs FDE filtering (dead FDEs cause phantom matches)

fn main() {
    let r = std::panic::catch_unwind(|| panic!("test"));
    std::process::exit(if r.is_err() { 42 } else { 1 });
}
