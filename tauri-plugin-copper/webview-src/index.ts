import { invoke } from '@tauri-apps/api/tauri'

export interface DeviceCode {
  deviceCode: string,
  userCode: string,
  verificationUri: string,
  expiresIn: number,
  interval: number,
  message: string
}

export interface AuthToken {
  tokenType: string,
  scope: string,
  expiresIn: number,
  accessToken: string,
  refreshToken: string,
}

export interface AuthData {
  accessToken: string,
  refreshToken: string,
  uuid: string,
  username: string,
  /**
   * Remember to refresh the token after it expires
   */
  expiresAt: number,
  xuid: string,
}

/**
 * Gets device information for starting the authorization process.
 *
 * @returns {Promise<DeviceCode>} The device information. use this in {@link getMicrosoftToken}
 */
export async function getAuthenticationInfo(): Promise<DeviceCode> {
  const v: any = await invoke('plugin:copper|get_auth_info')

  return ({
    deviceCode: v.device_code,
    userCode: v.user_code,
    verificationUri: v.verification_uri,
    expiresIn: v.expires_in,
    interval: v.interval,
    message: v.message,
  })
}

/**
 * Gets the access token for a microsoft account.
 *
 * @param authInfo The device information.
 * @returns {Promise<AuthToken>} The authentication token information. Use this in {@link getAuthData}.
 */
export async function getMicrosoftToken(authInfo: DeviceCode): Promise<AuthToken> {
  const v: any = await invoke('plugin:copper|get_ms_token', {
    authInfo: {
      device_code: authInfo.deviceCode,
      user_code: authInfo.userCode,
      verification_uri: authInfo.verificationUri,
      expires_in: authInfo.expiresIn,
      interval: authInfo.interval,
      message: authInfo.message,
    }
  })

  return ({
    tokenType: v.token_type,
    scope: v.scope,
    expiresIn: v.expires_in,
    accessToken: v.access_token,
    refreshToken: v.refresh_token,
  })
}

/**
 * Refreshes the authentication token for usage after it has expired.
 * @param authData The authentication data you had previously.
 * @returns A new auth token to be used in {@link getAuthData}
 */
export async function refreshAuthToken(authData: AuthData): Promise<AuthToken> {
  const v: any = await invoke('plugin:copper|refresh_ms_token', {
    authData: {
      access_token: authData.accessToken,
      refresh_token: authData.refreshToken,
      uuid: authData.uuid,
      username: authData.username,
      expires_at: authData.expiresAt,
      xuid: authData.xuid,
    }
  })

  return ({
    tokenType: v.token_type,
    scope: v.scope,
    expiresIn: v.expires_in,
    accessToken: v.access_token,
    refreshToken: v.refresh_token,
  })
}

/**
 * Gets the necessary authentication data for launching minecraft.
 *
 * @param authInfo The authentication token information.
 * @returns {Promise<AuthData>} The authentication data. Store this somewhere safe, and use it when launching minecraft. Remember to rather refresh the access_token rather than getting another one via the device flow.
 */
export async function getAuthData(authInfo: AuthToken): Promise<AuthData> {
  const v: any = await invoke('plugin:copper|get_auth_data', {
    authInfo: {
      token_type: authInfo.tokenType,
      scope: authInfo.scope,
      expires_in: authInfo.expiresIn,
      access_token: authInfo.accessToken,
      refresh_token: authInfo.refreshToken,
    }
  })

  return ({
    accessToken: v.access_token,
    refreshToken: v.refresh_token,
    uuid: v.uuid,
    username: v.username,
    expiresAt: v.expires_at,
    xuid: v.xuid,
  })
}