export interface DeviceCode {
    deviceCode: string;
    userCode: string;
    verificationUri: string;
    expiresIn: number;
    interval: number;
    message: string;
}
export interface AuthToken {
    tokenType: string;
    scope: string;
    expiresIn: number;
    accessToken: string;
    refreshToken: string;
}
export interface AuthData {
    accessToken: string;
    refreshToken: string;
    uuid: string;
    username: string;
    /**
     * Remember to refresh the token after it expires
     */
    expiresAt: number;
    xuid: string;
}
/**
 * Gets device information for starting the authorization process.
 *
 * @returns {Promise<DeviceCode>} The device information. use this in {@link getMicrosoftToken}
 */
export declare function getAuthenticationInfo(): Promise<DeviceCode>;
/**
 * Gets the access token for a microsoft account.
 *
 * @param authInfo The device information.
 * @returns {Promise<AuthToken>} The authentication token information. Use this in {@link getAuthData}.
 */
export declare function getMicrosoftToken(authInfo: DeviceCode): Promise<AuthToken>;
/**
 * Refreshes the authentication token for usage after it has expired.
 * @param authData The authentication data you had previously.
 * @returns A new auth token to be used in {@link getAuthData}
 */
export declare function refreshAuthToken(authData: AuthData): Promise<AuthToken>;
/**
 * Gets the necessary authentication data for launching minecraft.
 *
 * @param authToken The authentication token information.
 * @returns {Promise<AuthData>} The authentication data. Store this somewhere safe, and use it when launching minecraft. Remember to rather refresh the access_token rather than getting another one via the device flow.
 */
export declare function getAuthData(authToken: AuthToken): Promise<AuthData>;
