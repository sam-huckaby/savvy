(*
        - A Facebook config struct
        - Create URL for the developer to put in a button
        - Create a token exchange method
*)
open Lwt.Infix
open Cohttp_lwt_unix

let ( let* ) = Lwt.bind

type facebook_oauth_config = {
  client_id: string;
  client_secret: string;
  redirect_uri: Json_uri.t;
  scope: string list;
} [@@deriving yojson]

type user_response = {
  id: string;
  name: string;
  email: string option;
} [@@deriving yojson]

type token_response = {
  access_token: string;
  token_type: (string option [@default None]);
  expires_in: (int option [@default None]);
} [@@deriving yojson]

type config =
  | FacebookOauthConfig of facebook_oauth_config
[@@deriving yojson]

module DefaultInMemoryStorage = struct
  type value = config
  let ttl = 3600.0
end

module type FACEBOOK_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string), string) result
  val exchange_code_for_token : string -> string -> (token_response, string) result Lwt.t
  val get_user_info : token_response -> (user_response, string) result Lwt.t
end

module FacebookClient (Storage : Storage.STORAGE_UNIT with type value = config) : FACEBOOK_CLIENT = struct
  let get_authorization_url ~config =
    match config with
    | FacebookOauthConfig fb_config -> begin
      let state = Utils.generate_state () in
      let params = [
        ("client_id", fb_config.client_id);
        ("redirect_uri", Json_uri.to_string fb_config.redirect_uri);
        ("state", state);
      ] @ (
        match fb_config.scope with
        | [] -> []
        | scopes -> [ ("scope", String.concat "," scopes) ]
      ) in
      Storage.update state config;
      let url = Uri.add_query_params' (Uri.of_string "https://www.facebook.com/v20.0/dialog/oauth") params in
      Ok (url, state)
    end

  let exchange_code_for_token state code =
    match Storage.get state with
    | Some ((stored_config), _expires) -> begin
      Storage.remove state;
      match stored_config with
      | FacebookOauthConfig config -> begin
        let params = [
          ("client_id", config.client_id);
          ("client_secret", config.client_secret);
          ("code", code);
          ("redirect_uri", Json_uri.to_string config.redirect_uri);
        ] in
        let uri = Uri.add_query_params' (Uri.of_string "https://graph.facebook.com/v20.0/oauth/access_token") params in
        Client.get uri
        >>= fun (_resp, body) -> Cohttp_lwt.Body.to_string body
        >>= fun body_str ->
        let json = Yojson.Safe.from_string body_str in
        match token_response_of_yojson json with
        | Ok token -> Lwt.return (Ok token)
        | Error _ -> begin
          let open Yojson.Safe.Util in
          let err = member "error" json in
          if err <> `Null then
            let message = err |> member "message" |> to_string_option |> Option.value ~default:"Unknown error" in
            Lwt.return (Error message)
          else
            Lwt.return (Error "Failed to decode token response")
        end
      end
    end
    | None -> Lwt.return (Error "State value did not match a known session")

  let get_user_info token =
    let uri = Uri.add_query_params' (Uri.of_string "https://graph.facebook.com/me") [
      ("fields", "id,name,email");
      ("access_token", token.access_token);
    ] in
    let* (resp, body) = Cohttp_lwt_unix.Client.get uri in
    let code = resp
      |> Cohttp.Response.status
      |> Cohttp.Code.code_of_status in
    if Cohttp.Code.is_success code
    then
      let* body_str = Cohttp_lwt.Body.to_string body in
      let json = Yojson.Safe.from_string body_str in
      match user_response_of_yojson json with
      | Ok user -> Lwt.return (Ok user)
      | Error _ -> Lwt.return (Error "Failed to unwrap user object")
    else
      Lwt.return (Error "Failed to successfully retrieve user")
end
