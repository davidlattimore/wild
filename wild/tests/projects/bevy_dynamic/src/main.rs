use bevy::{app::ScheduleRunnerPlugin, prelude::*};

fn main() {
    App::new()
        .add_plugins(MinimalPlugins.set(ScheduleRunnerPlugin::run_once()))
        .add_systems(Update, exit_with_success_code)
        .run();
}

fn exit_with_success_code() {
    std::process::exit(42);
}
