mod auth;

use copper::auth::Auth;
pub use serde::{ser::Serializer, Serialize};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

use crate::auth::*;

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

/// Initializes the plugin.
///
/// Arguments
/// `ms_client_id` The microsoft azure client ID
///
/// Look at [The microsoft oauth2 flow docs](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) on how to get these tokens
pub fn init<R: Runtime>(ms_client_id: String) -> TauriPlugin<R> {
    Builder::new("copper")
        .invoke_handler(tauri::generate_handler![
            get_auth_info,
            get_ms_token,
            get_mc_token
        ])
        .setup(|app| {
            app.manage(Auth {
                client_id: ms_client_id,
                http_client: reqwest::Client::new(),
            });
            Ok(())
        })
        .build()
}
