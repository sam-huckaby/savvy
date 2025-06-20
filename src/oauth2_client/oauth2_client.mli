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
  client_secret: string option;
  pkce: pkce_style;
  pkce_verifier: string option;
  redirect_uri: Uri.t;
  scope: string list;
  token_auth_method: token_auth_method;
  token_endpoint: Uri.t;
} [@@deriving yojson]

type client_credentials_config = {
  client_id: string;
  client_secret: string;
  scope: string list;
  token_auth_method: token_auth_method;
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
  token_auth_method: token_auth_method;
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
  expires_in: int option;
  refresh_token: string option;
  scope: string option;
} [@@deriving yojson]

type device_code_response = {
  device_code: string;
  user_code: string;
  verification_uri: Uri.t;
  verification_uri_complete: Uri.t option;
  expires_in: int;
  interval: int;
} [@@deriving yojson]

module DefaultInMemoryStorage : sig
  type value = string * config
  val ttl : float
end

module type OAUTH2_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string * string), string) result
  val exchange_code_for_token : string -> string -> (token_response, string) result Lwt.t
  val get_client_credentials_token : config:config -> (token_response, string) result Lwt.t
  val refresh_token : config:config -> (token_response, string) result Lwt.t
  (* Additional flows handled later *)
end

module OAuth2Client (_ : Storage.STORAGE_UNIT with type value = (string * config)) : OAUTH2_CLIENT

