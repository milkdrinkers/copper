pub use serde::{ser::Serializer, Serialize};
use tauri::{
    command,
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime, State, Window,
};

use std::{collections::HashMap, sync::Mutex};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

struct AuthInfo {
    id: String,
    secret: String,
}

/// Initializes the plugin.
///
/// Arguments
/// `ms_client_id` The microsoft azure client ID
/// `ms_client_secret` The microsoft azure client secret.
///
/// Look at [The microsoft oauth2 flow docs](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) on how to get these tokens
pub fn init<R: Runtime>(ms_client_id: String, ms_client_secret: String) -> TauriPlugin<R> {
    Builder::new("copper")
        .invoke_handler(tauri::generate_handler![])
        .setup(|app| {
            app.manage(AuthInfo {
                id: ms_client_id,
                secret: ms_client_secret,
            });
            Ok(())
        })
        .build()
}
