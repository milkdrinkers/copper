use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::fs::create_dir_all;
use tokio::sync::watch::{self, Sender};
use tokio::sync::Semaphore;
use tokio::task::{self, JoinSet};
use tracing::{debug, trace};

use crate::errors::{DownloadTasks, SaveError};
use crate::util::{
    create_client, create_download_task, DownloadProgress, DownloadWatcher, ListOfResultHandles,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetIndex {
    pub objects: HashMap<String, Object>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Object {
    pub hash: String,
    pub size: i64,
}

impl AssetIndex {
    #[tracing::instrument]
    pub async fn save_index(&self, save_path: PathBuf) -> Result<(), SaveError> {
        // serialize the struct to a json string
        trace!("Serializing AssetIndex to JSON");
        let json = serde_json::to_string(self)?;

        create_dir_all(&save_path.parent().ok_or(SaveError::NoParentPath)?).await?;

        // create file and save it
        debug!("Creating AssetIndex file at {}", &save_path.display());
        let mut file = std::fs::File::create(&save_path)?;
        debug!("Writing JSON to AssetIndex file");
        file.write_all(json.as_bytes())?;

        debug!(
            "Saved AssetIndex to {}",
            &save_path.to_str().ok_or(SaveError::NotValidUtf8Path)?
        );
        Ok(())
    }

    /// The save path should be /assets/objects
    #[tracing::instrument]
    pub async fn download_assets(
        &self,
        save_path: PathBuf,
    ) -> Result<ListOfResultHandles, DownloadTasks> {
        trace!("Downloading assets");
        let client = create_client();
        let semaphore = Arc::new(Semaphore::new(75));
        let mut tasks = JoinSet::new();

        // create a final path and return it along with the url
        let path_and_url: HashMap<String, String> = self
            .objects
            .iter()
            .map(|(_path, object)| {
                let url = format!(
                    "https://resources.download.minecraft.net/{}/{}",
                    &object.hash[..2],
                    object.hash
                );

                let download_path = format!("{}/{}", &object.hash[..2], object.hash);
                (download_path, url)
            })
            .collect();

        // loop over the paths + urls
        trace!("Creating asset download tasks");
        for (path, url) in path_and_url.into_iter() {
            // because the path includes the file name, we need to remove the last part
            let full_path = save_path.join(path);

            // Checks if we need to download the file
            if full_path.try_exists()? && full_path.is_file() {
                trace!("Skipped file at {}", &full_path.display());
                continue;
            };

            debug!("Creating download task for {}", &full_path.display());
            tasks.spawn(create_download_task(
                url,
                full_path,
                Some(client.clone()),
                semaphore.clone().acquire_owned().await?,
            ));
        }

        debug!("Created {} asset download tasks", tasks.len());
        Ok(tasks)
    }

    #[tracing::instrument]
    async fn run_downloads(
        mut tasks: ListOfResultHandles,
        progress_sender: Sender<DownloadProgress>,
    ) {
        trace!("Running asset download tasks");
        let total = tasks.len();
        let mut finished = 0;

        while let Some(_res) = tasks.join_next().await {
            finished += 1;
            debug!("{}/{} asset downloads finished", finished, total);
            let _ = progress_sender.send(DownloadProgress {
                total_size: total as u64,
                finished,
            });
        }

        debug!("All asset downloads finished");
    }

    #[tracing::instrument]
    pub async fn start_download_assets(
        &self,
        save_path: PathBuf,
    ) -> Result<DownloadWatcher, DownloadTasks> {
        trace!("Starting download assets");
        trace!("Creating progress watcher");
        let (progress_sender, progress_receiver) = watch::channel(DownloadProgress {
            finished: 0,
            total_size: 0,
        });

        trace!("Creating download tasks");
        let tasks = self.download_assets(save_path).await?;
        trace!("Starting download tasks");
        let download_task = task::spawn(Self::run_downloads(tasks, progress_sender));

        Ok(DownloadWatcher {
            progress_watcher: progress_receiver,
            download_task,
        })
    }
}
