(* Client Library for OAuth2 *)
(* Built to follow https://datatracker.ietf.org/doc/html/rfc6749 *)

type flow_type =
  | AuthorizationCode
  | ClientCredentials
  | DeviceCode
  | RefreshToken

type token_auth_method =
  | Basic
  | Body

type pkce_style =
  | No_Pkce
  | Plain
  | S256

type authorization_code_config = {
  authorization_endpoint: Uri.t;
  client_id: string;
  client_secret: string;
  pkce: (pkce_style [@default No_Pkce]);
  pkce_verifier: (string option [@default None]);
  redirect_uri: Uri.t;
  scope: string list;
  token_auth_method: (token_auth_method [@default Basic]);
  token_endpoint: Uri.t;
} [@@deriving yojson]

type client_credentials_config = {
  client_id: string;
  client_secret: string;
  scope: string list;
  token_auth_method: (token_auth_method [@default Basic]);
  token_endpoint: Uri.t;
} [@@deriving yojson]

type device_code_config = {
  client_id: string;
  device_authorization_endpoint: Uri.t;
  token_endpoint: Uri.t;
  scope: string list;
} [@@deriving yojson]

type refresh_token_config = {
  client_id: string;
  client_secret: string;
  token_endpoint: Uri.t;
  refresh_token: string;
  scope: string list option;
} [@@deriving yojson]

type config =
  | AuthorizationCodeConfig of authorization_code_config
  | ClientCredentialsConfig of client_credentials_config
  | DeviceCodeConfig of device_code_config
  | RefreshTokenConfig of refresh_token_config
[@@deriving yojson]

type token_response = {
  access_token: string;
  token_type: string;
  expires_in: (int option [@default None]);
  refresh_token: (string option [@default None]);
  scope: (string option [@default None]);
} [@@deriving yojson]

type device_code_response = {
  device_code: string;
  user_code: string;
  verification_uri: Uri.t;
  verification_uri_complete: Uri.t option;
  expires_in: int;
  interval: int;
} [@@deriving yojson]

type t = {
  flow_type: flow_type;
  config: config;
}

val create : flow_type -> config -> t
val get_authorization_url : t -> Uri.t * string * string
val exchange_code_for_token : string -> string -> token_response Lwt.t
val get_client_credentials_token : t -> token_response Lwt.t
val get_device_code : t -> device_code_response Lwt.t
val poll_for_device_token : t -> device_code_response -> token_response Lwt.t
val refresh_token : t -> token_response Lwt.t 
