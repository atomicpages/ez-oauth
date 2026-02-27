export enum ClientAuth {
  CLIENT_SECRET_JWT = "client_secret_jwt",
  PRIVATE_KEY_JWT = "private_key_jwt",
  NONE = "none",
  TLS_CLIENT_AUTH = "tls_client_auth",
  CLIENT_SECRET_POST = "client_secret_post",
  CLIENT_SECRET_BASIC = "client_secret_basic",
}

export enum GrantType {
  AUTHORIZATION_CODE = "authorization_code",
  CLIENT_CREDENTIALS = "client_credentials",
}
