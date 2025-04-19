(* Savvy - A high-level OAuth2 client library *)

module Oauth2_client = Oauth2_client

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

let create flow_type config = {
  oauth2_client = Oauth2_client.create flow_type config;
}

let get_authorization_url t = Oauth2_client.get_authorization_url t.oauth2_client
let exchange_code_for_token state code = Oauth2_client.exchange_code_for_token state code
let get_client_credentials_token t = Oauth2_client.get_client_credentials_token t.oauth2_client
let get_device_code t = Oauth2_client.get_device_code t.oauth2_client
let poll_for_device_token t device_code = Oauth2_client.poll_for_device_token t.oauth2_client device_code
let refresh_token t = Oauth2_client.refresh_token t.oauth2_client
