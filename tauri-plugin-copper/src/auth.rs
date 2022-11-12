use copper::{
    auth::{
        structs::{AuthData, AuthToken, AuthTokenError, DeviceCode},
        Auth,
    },
    errors::{
        DeviceCodeError, InternalReqwestError, JWTVerificationError, MinecraftProfileError,
        XstsError, XstsMsError,
    },
};
use serde::Serialize;
use tauri::command;
use thiserror::Error;

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
pub async fn get_auth_data(
    auth_token: AuthToken,
    auth: tauri::State<'_, Auth>,
) -> Result<AuthData, AuthDataError> {
    let xbox_token = auth
        .get_xbox_auth_token(&auth_token)
        .await
        .map_err(InternalReqwestError)?;

    let xsts_token = auth
        .get_xsts_token(&xbox_token)
        .await
        .map_err(|e| match e {
            XstsError::MicrosoftError(e) => AuthDataError::MicrosoftError(e),
            XstsError::ReqwestError(e) => AuthDataError::ReqwestError(e),
        })?;

    let auth_info = auth
        .get_minecraft_token(&xsts_token)
        .await
        .map_err(InternalReqwestError)?;

    if !auth.verify_minecraft_ownership(&auth_info).await? {
        return Err(AuthDataError::NotOwned);
    }

    let minecraft_profile = auth
        .get_minecraft_profile(&auth_info)
        .await
        .map_err(|e| match e {
            MinecraftProfileError::ReqwestError(e) => AuthDataError::ReqwestError(e.into()),
            MinecraftProfileError::NotFound => AuthDataError::NotFound,
        })?;

    Ok(auth.create_auth_data(&auth_info, &minecraft_profile, &auth_token, &xbox_token))
}

#[command]
pub async fn refresh_ms_token(
    auth_data: AuthData,
    auth: tauri::State<'_, Auth>,
) -> Result<AuthToken, InternalReqwestError> {
    auth.refresh_token(&auth_data)
        .await
        .map_err(InternalReqwestError)
}

#[derive(Error, Debug, Serialize)]
pub enum AuthDataError {
    #[error("auth_data_error.request_error(error={})", .0)]
    ReqwestError(#[from] InternalReqwestError),

    #[error("auth_data_error.microsoft_error(error={})", .0)]
    MicrosoftError(XstsMsError),

    #[error("auth_data_error.validation_error(error={})", .0)]
    ValidationError(#[from] JWTVerificationError),

    #[error("auth_data_error.not_owned")]
    NotOwned,

    #[error("auth_data_error.profile_not_found")]
    /// Note that Xbox Game Pass users who haven't logged into the new Minecraft Launcher at least once will not return a profile, and will need to login once after activating Xbox Game Pass to setup their Minecraft username.
    NotFound,
}
