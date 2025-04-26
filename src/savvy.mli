(* When implementing this interface, be sure to handle cleaning stale entries somehow *)
module type STORAGE_UNIT =
  sig 
    type t
    val get: string -> ( string * Oauth2_client.config * float ) option
    val remove: string -> unit
    val update: string -> ( string * Oauth2_client.config ) -> unit
  end

module type OAUTH2_CLIENT =
  sig
  val get_authorization_url : config:Oauth2_client.config -> (Uri.t * string * string)
  val exchange_code_for_token : string -> string -> Oauth2_client.token_response Lwt.t
  val get_client_credentials_token : config:Oauth2_client.config -> Oauth2_client.token_response Lwt.t
  val refresh_token : config:Oauth2_client.config -> Oauth2_client.token_response Lwt.t
  (* Additional flows handled later *)
end

module InMemoryStorage : STORAGE_UNIT

module OAuth2Client (_ : STORAGE_UNIT) : OAUTH2_CLIENT

