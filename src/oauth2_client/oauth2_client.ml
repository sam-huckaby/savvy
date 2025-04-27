(* Client Library for OAuth2 *)
(* Built to follow https://datatracker.ietf.org/doc/html/rfc6749 *)

open Lwt.Infix
open Cohttp_lwt_unix

module Uri = struct
  include Uri
  let to_yojson uri = `String (Uri.to_string uri)
  let of_yojson = function
    | `String s -> Ok (Uri.of_string s)
    | _ -> Error "expected string for Uri.t"
end

(* First flows to build, insecure flow types omitted for now *)
type flow_type =
  | AuthorizationCode
  | ClientCredentials
  | DeviceCode
  | RefreshToken

(* Token requests must receive credentials in one of two ways. See: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1 *)
type token_auth_method =
  | Basic
  | Body

let token_auth_method_to_yojson = function
  | Basic -> `String "basic"
  | Body -> `String "body"

let token_auth_method_of_yojson = function
  | `String "basic" -> Ok Basic
  | `String "body" -> Ok Body
  | `String _ -> Ok Basic (* Default to Basic for unknown values *)
  | _ -> Error "expected `String for token_auth_method"

(* I almost made this pkce_cut, but decided that might be too much *)
type pkce_style =
  | No_Pkce
  | Plain
  | S256

let pkce_style_to_yojson = function
  | No_Pkce -> `String ""
  | Plain -> `String "plain"
  | S256 -> `String "s256"

let pkce_style_of_yojson = function
  | `String "plain" -> Ok Plain
  | `String "s256" -> Ok S256
  | `String _ -> Ok No_Pkce (* Default to Basic for unknown values *)
  | _ -> Error "expected `String for pkce_style"

type authorization_code_config = {
  authorization_endpoint: Uri.t;
  client_id: string;
  client_secret: string;
  (* For more information about the PKCE protocol: https://datatracker.ietf.org/doc/html/rfc7636 *)
  pkce: (pkce_style [@default No_Pkce]);
  pkce_verifier: (string option [@default None]);
  redirect_uri: Uri.t;
  scope: string list;
  (* Token requests must receive credentials in one of two ways. See: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1 *)
  token_auth_method: (token_auth_method [@default Basic]);
  token_endpoint: Uri.t;
} [@@deriving yojson]

type client_credentials_config = {
  client_id: string;
  client_secret: string;
  scope: string list;
  (* Token requests must receive credentials in one of two ways. See: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1 *)
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
  token_auth_method: (token_auth_method [@default Basic]);
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

type token_error_code =
  | Invalid_Request
  | Invalid_Client
  | Invalid_Grant
  | Unauthorized_Client
  | Unsupported_Grant_Type
  | Invalid_Scope
  | Invalid_Token

let token_error_code_to_yojson = function
  | Invalid_Request -> `String "invalid_request"
  | Invalid_Client -> `String "invalid_client"
  | Invalid_Grant -> `String "invalid_grant"
  | Unauthorized_Client -> `String "unauthorized_client"
  | Unsupported_Grant_Type -> `String "unsupported_grant_type"
  | Invalid_Scope -> `String "invalid_scope"
  | Invalid_Token -> `String "invalid_token"

let token_error_code_of_yojson = function
  | `String "invalid_request" -> Ok Invalid_Request
  | `String "invalid_client" -> Ok Invalid_Client
  | `String "invalid_grant" -> Ok Invalid_Grant
  | `String "unauthorized_client" -> Ok Unauthorized_Client
  | `String "unsupported_grant_type" -> Ok Unsupported_Grant_Type
  | `String "invalid_scope" -> Ok Invalid_Scope
  | `String "invalid_token" -> Ok Invalid_Token
  | `String _ -> Ok Invalid_Request (* Default to Basic for unknown values *)
  | _ -> Error "expected string for error code"

type token_error = {
  error: token_error_code;
  error_description: string;
  error_uri: (Uri.t option [@default None]);
} [@@deriving yojson]

type device_code_response = {
  device_code: string;
  user_code: string;
  verification_uri: Uri.t;
  verification_uri_complete: Uri.t option;
  expires_in: int;
  interval: int;
} [@@deriving yojson]

(* Any user-defined storage implementation must have at least these three methods *)
module type STORAGE_UNIT =
  sig 
    type t
    (* When implementing this interface, I recommend doing a clean out of stale values in get *)
    val get: string -> ( string * config * float ) option
    val remove: string -> unit
    val update: string -> ( string * config ) -> unit
  end

(* Shared in-memory Hashtbl that uses state values as keys and stores code_verifiers and configs *)
(* NOTE: This should NOT be used in production. *)
module InMemoryStorage : STORAGE_UNIT =
  struct
    type t = (string, (string * config * float)) Hashtbl.t

    let store = Hashtbl.create 100

    (* TTL: 1 hour (in seconds) is pretty safely invalid *)
    let ttl = 3600.0

    let is_expired created_at =
      Unix.time () -. created_at > ttl

    let clean () =
      Hashtbl.filter_map_inplace
        (fun _key (_verifier, _config, created_at) ->
          if is_expired created_at then None
          else Some (_verifier, _config, created_at))
        store

    (* Due to sealing, only the below methods are publicly accessible *)
    let get state = 
      clean ();
      Hashtbl.find_opt store state

    let remove state = Hashtbl.remove store state
    
    let update state (verifier, config) = Hashtbl.replace store state (verifier, config, Unix.time ())
  end

(* This is the completely generic OAuth2 client. Will add modules later for popular providers such as GitHub *)
module type OAUTH2_CLIENT =
sig
  val get_authorization_url : config:config -> (Uri.t * string * string)
  val exchange_code_for_token : string -> string -> token_response Lwt.t
  val get_client_credentials_token : config:config -> token_response Lwt.t
  val refresh_token : config:config -> token_response Lwt.t
  (* Additional flows handled later *)
end

(* Functor to create a client module that users of Savvy will use *)
module OAuth2Client (Storage : STORAGE_UNIT) : OAUTH2_CLIENT = struct
  (* This is a helper function to construct the necessary auth url to pass to the user agent *)
  let get_authorization_url ~config =
    match config with
    | AuthorizationCodeConfig ac_config ->
      (* Always generate a nice, safe, random, state value, since humans can't be trusted *)
      let state = Utils.generate_state () in
      (* Determine whether there is a PKCE code_verifier to work with or if we need to make our own *)
      (* In some cases, like when not using PKCE, this value will be disregarded *)
      (* Ideally, we generate our own PKCE code_verifier, but there may be a case where someone wants to provide their own *)
      let verifier = (match ac_config.pkce_verifier with
      | Some verifier_str -> verifier_str
      | None -> Utils.generate_code_verifier ()) in
      let params = [
        ("response_type", "code");
        ("client_id", ac_config.client_id);
        ("redirect_uri", Uri.to_string ac_config.redirect_uri);
        ("scope", String.concat " " ac_config.scope);
        ("state", state);
      ] @ (
        match ac_config.pkce with
          | S256 -> [ ("code_challenge", Utils.generate_code_challenge verifier) ; ("code_challenge_method", "S256") ]
          | Plain -> [ ("code_challenge", verifier) ; ("code_challenge_method", "plain") ]
          | No_Pkce -> []
      ) in
      (* Store the things we will need for the second half of this operation *)
      Storage.update state ( verifier, config );
      let url = Uri.add_query_params' ac_config.authorization_endpoint params in
      (url, state, verifier)
    | _ -> failwith "Authorization URL only available for Authorization Code flow"
  
  let exchange_code_for_token state code =
    match Storage.get state with
    | Some (verifier, stored_config, _expires) -> begin
      Storage.remove state;
      match stored_config with
      | AuthorizationCodeConfig config -> begin
        let params = (
          match config.token_auth_method with
            | Basic -> [
                ("grant_type", "authorization_code");
                ("code", code);
                ("redirect_uri", Uri.to_string config.redirect_uri);
              ]
            | Body -> [
                ("grant_type", "authorization_code");
                ("code", code);
                ("client_id", config.client_id);
                ("client_secret", config.client_secret); (* TODO: Per the RFC, ONLY if the client is confidential, it must authenticate with this *)
                ("redirect_uri", Uri.to_string config.redirect_uri);
              ]
        ) @ (
          match config.pkce with
            | No_Pkce -> []
            | _ -> [ ("code_verifier", verifier) ]
        ) in
        let body = Utils.form_encode params in
        let headers = (
          match config.token_auth_method with
          | Basic -> 
            Cohttp.Header.of_list [
              ("Content-Type", "application/x-www-form-urlencoded") ;
              ("Authorization", "Basic " ^ (Base64.encode_string (config.client_id ^ ":" ^ config.client_secret)))
            ] 
          | Body -> Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded"
        ) in
        Client.post ~headers ~body config.token_endpoint
        >>= fun (_, body) -> Cohttp_lwt.Body.to_string body
        >>= fun body_str ->
        (* This decoder is created by @@deriving yojson *)
        let json = Yojson.Safe.from_string body_str in
        match token_response_of_yojson json with
        | Ok token -> begin
          Lwt.return token
          end
        | Error _ -> begin
          match token_error_of_yojson json with
          | Ok error -> begin
            print_endline error.error_description;
            Lwt.fail_with error.error_description
            end
          | Error e -> begin
            print_endline e;
            Lwt.fail_with e
            end
          end
        end
      | _ -> failwith "Code exchange only available for Authorization Code flow"
      end
    | None -> failwith "State value did not match a known session"
  
  let get_client_credentials_token ~config =
    match config with
    | ClientCredentialsConfig cc_config -> begin
      let params = (
        match cc_config.token_auth_method with
          | Basic -> [
              ("grant_type", "client_credentials");
              ("scope", String.concat " " cc_config.scope);
            ]
          | Body -> [
              ("grant_type", "client_credentials");
              ("client_id", cc_config.client_id);
              ("client_secret", cc_config.client_secret);
              ("scope", String.concat " " cc_config.scope);
            ]
      ) in
      (*
        There are two methods by which client credentials may be passed:
        - form-urlencoded in the body
        - encoded together in for Basic auth in the Authorization header
        For more information: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
      *)
      let body = Utils.form_encode params in
      let headers = (
        match cc_config.token_auth_method with
        | Basic -> Cohttp.Header.of_list [
                    ("Content-Type", "application/x-www-form-urlencoded") ;
                    ("Authorization", "Basic " ^ (Base64.encode_string (cc_config.client_id ^ ":" ^ cc_config.client_secret)))
                  ]
        | Body -> Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded"
      ) in
      Client.post ~headers ~body cc_config.token_endpoint
      >>= fun (_, body) -> Cohttp_lwt.Body.to_string body
      >>= fun body_str ->
      let json = Yojson.Safe.from_string body_str in
      match token_response_of_yojson json with
      | Ok token -> Lwt.return token
      | Error _ -> begin
        match token_error_of_yojson json with
        | Ok error -> begin
          print_endline error.error_description;
          Lwt.fail_with error.error_description
          end
        | Error e -> begin
          print_endline e;
          Lwt.fail_with e
          end
        end
      end
    | _ -> failwith "Client credentials token only available for Client Credentials flow"

  let refresh_token ~config =
    match config with
    | RefreshTokenConfig refresh_config -> begin
      let params = (
        [
          ("grant_type", "refresh_token");
          ("refresh_token", refresh_config.refresh_token);
        ]
      ) @ (
        match refresh_config.token_auth_method with
          | Basic -> []
          | Body -> [
              ("client_id", refresh_config.client_id);
              ("client_secret", refresh_config.client_secret); (* TODO: Per the RFC, ONLY if the client is confidential, it must authenticate with this *)
            ]
      ) @ (match refresh_config.scope with
          (* The refresh_token scopes MUST NOT include any NEW scopes to the access_token *)
          (* For more info: https://datatracker.ietf.org/doc/html/rfc6749#section-6 *)
          | Some scopes -> [("scope", String.concat " " scopes)]
          | None -> []) in
      let body = Utils.form_encode params in
      let headers = (
        match refresh_config.token_auth_method with
        | Basic -> 
          Cohttp.Header.of_list [
            ("Content-Type", "application/x-www-form-urlencoded") ;
            ("Authorization", "Basic " ^ (Base64.encode_string (refresh_config.client_id ^ ":" ^ refresh_config.client_secret)))
          ] 
        | Body -> Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded"
      ) in
      Client.post ~headers ~body refresh_config.token_endpoint
      >>= fun (_, body) ->
      Cohttp_lwt.Body.to_string body
      >>= fun body_str ->
      let json = Yojson.Safe.from_string body_str in
      match token_response_of_yojson json with
      | Ok token -> Lwt.return token
      | Error _ -> begin
        match token_error_of_yojson json with
        | Ok error -> begin
          print_endline error.error_description;
          Lwt.fail_with error.error_description
          end
        | Error e -> begin
          (* We error'd trying to read the error - there be dragons *)
          print_endline e;
          Lwt.fail_with e
          end
        end
      end
    | _ -> failwith "Refresh token only available for Refresh Token flow"
(* Implementing refresh_token next *)

(*
  let refresh_token t =
    match t.config with
    | RefreshTokenConfig config -> begin
      let body = [
        ("grant_type", ["refresh_token"]);
        ("client_id", [config.client_id]);
        ("client_secret", [config.client_secret]);
        ("refresh_token", [config.refresh_token]);
      ] @ (match config.scope with
          | Some scope -> [("scope", [String.concat " " scope])]
          | None -> []) in
      let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
      Client.post_form ~headers ~params:body config.token_endpoint
      >>= fun (_, body) ->
      Cohttp_lwt.Body.to_string body
      >>= fun body_str ->
      match token_response_of_yojson (Yojson.Safe.from_string body_str) with
      | Ok token -> Lwt.return token
      | Error e -> begin
        print_endline e;
        Lwt.fail_with e
        end
      end
    | _ -> failwith "Refresh token only available for Refresh Token flow" 
*)

(* Below are less common flows that will be made available later *)

(*  
  let get_device_code t =
    match t.config with
    | DeviceCodeConfig config -> begin
      let params = [
        ("client_id", config.client_id);
        ("scope", String.concat " " config.scope);
      ] in
      let body = Utils.form_encode params in
      let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
      Client.post ~headers ~body config.device_authorization_endpoint
      >>= fun (_, body) ->
      Cohttp_lwt.Body.to_string body
      >>= fun body_str ->
      match device_code_response_of_yojson (Yojson.Safe.from_string body_str) with
      | Ok device_code -> Lwt.return device_code
      | Error e -> begin
        print_endline e;
        Lwt.fail_with e
        end
      end
    | _ -> failwith "Device code only available for Device Code flow"
  
  let poll_for_device_token t device_code =
    match t.config with
    | DeviceCodeConfig config ->
      let rec poll () =
        let params = [
          ("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
          ("device_code", device_code.device_code);
          ("client_id", config.client_id);
        ] in
        let body = Utils.form_encode params in
        let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
        Client.post ~headers ~body config.token_endpoint
        >>= fun (_, body) ->
        Cohttp_lwt.Body.to_string body
        >>= fun body_str ->
        match token_response_of_yojson (Yojson.Safe.from_string body_str) with
        | Ok token -> Lwt.return token
        | Error _ ->
          print_endline "waiting for token...";
          Lwt_unix.sleep (float_of_int device_code.interval)
          >>= fun () ->
          poll ()
      in
      poll ()
    | _ -> failwith "Device token polling only available for Device Code flow"
 *)  
end

