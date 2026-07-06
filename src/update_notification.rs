use crate::cache::Cacher;
use notify_rust::Notification;

pub fn show_update_notification(cacher: &mut Cacher) {
    let _ = Notification::new()
        .summary(&format!(
            "New ghidra version available: {}",
            cacher.cache.latest_known
        ))
        .icon("ghidra")
        .show();
}
