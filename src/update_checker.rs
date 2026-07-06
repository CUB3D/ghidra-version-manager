use crate::args::arguments::Args;
use crate::cache::Cacher;
use crate::update_notification::UpdateDialogAction;
use crate::{update_latest_version, update_notification};
use chrono::Utc;
use tracing::{debug, warn};

pub struct UpdateCheckResults {
    pub new_version_available: bool,
    pub next_action: UpdateDialogAction,
}

impl Default for UpdateCheckResults {
    fn default() -> Self {
        Self {
            new_version_available: false,
            next_action: UpdateDialogAction::Launch(None),
        }
    }
}

pub async fn do_update_check(
    cacher: &mut Cacher,
    args: &Args,
) -> anyhow::Result<UpdateCheckResults> {
    debug!("Checking for updates");

    let mut results = UpdateCheckResults::default();

    let old_latest_version = cacher.cache.latest_known.clone();

    let new_version = match update_latest_version(cacher).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to check for update: {e:?}");
            results.new_version_available = false;
            return Ok(results);
        }
    };

    // Show update notification if running in launcher mode
    if new_version && args.launcher {
        results.next_action =
            update_notification::show_update_notification(cacher, old_latest_version).await;
    }
    cacher.with_cache(|c| c.last_update_check = Utc::now())?;

    results.new_version_available = new_version;
    Ok(results)
}
