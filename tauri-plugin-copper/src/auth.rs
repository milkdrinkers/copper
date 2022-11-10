use copper::{
    auth::{
        structs::{AuthToken, AuthTokenError, DeviceCode, MinecraftToken},
        Auth,
    },
    errors::{DeviceCodeError, InternalReqwestError, XstsError},
};
use tauri::command;

#[command]
pub async fn get_auth_info(auth: tauri::State<'_, Auth>) -> Result<DeviceCode, DeviceCodeError> {
    auth.create_device_code().await
}

#[command]
pub async fn get_ms_token(
    auth_info: DeviceCode,
    auth: tauri::State<'_, Auth>,
) -> Result<AuthToken, AuthTokenError> {
    auth.get_microsoft_auth_token(&auth_info).await
}

#[command]
pub async fn get_mc_token(
    auth_info: AuthToken,
    auth: tauri::State<'_, Auth>,
) -> Result<MinecraftToken, XstsError> {
    let xbox_token = auth
        .authenticate_xbox_live(&auth_info)
        .await
        .map_err(InternalReqwestError)?;

    let xsts_token = auth.get_xsts_token(&xbox_token).await?;

    Ok(auth
        .get_minecraft_token(&xsts_token)
        .await
        .map_err(InternalReqwestError)?)
}
