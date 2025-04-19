(* Savvy - A high-level OAuth2 client library *)

module Oauth2_client : module type of Oauth2_client

type t = {
  oauth2_client: Oauth2_client.t;
}

type flow_type = Oauth2_client.flow_type
type token_auth_method = Oauth2_client.token_auth_method
type pkce_style = Oauth2_client.pkce_style
type authorization_code_config = Oauth2_client.authorization_code_config
type client_credentials_config = Oauth2_client.client_credentials_config
type device_code_config = Oauth2_client.device_code_config
type refresh_token_config = Oauth2_client.refresh_token_config
type config = Oauth2_client.config
type token_response = Oauth2_client.token_response
type device_code_response = Oauth2_client.device_code_response

val create : flow_type -> config -> t
val get_authorization_url : t -> Uri.t * string * string
val exchange_code_for_token : t -> string -> token_response Lwt.t
val get_client_credentials_token : t -> token_response Lwt.t
val get_device_code : t -> device_code_response Lwt.t
val poll_for_device_token : t -> device_code_response -> token_response Lwt.t
val refresh_token : t -> token_response Lwt.t 