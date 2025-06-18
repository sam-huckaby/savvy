(*
        - A GitHub config struct
        - Create URL for the developer to put in a button
        - Create a token exchange method
*)
open Lwt.Infix
open Cohttp_lwt_unix

let ( let* ) = Lwt.bind

type github_prompt =
  | No_Prompt
  | Select_Account
  | Other of string

let github_prompt_of_yojson = function
  | `String "no_prompt" -> Ok No_Prompt
  | `String "select_account" -> Ok Select_Account
  | `String str -> Ok (Other str) (* Default to Basic for unknown values *)
  | _ -> Error "expected `String for pkce_style"

let github_prompt_to_yojson = function
  | No_Prompt -> `String "no_prompt"
  | Select_Account -> `String "select_account"
  | Other str -> `String str

type github_oauth_config = {
  client_id: string;
  client_secret: string;
  redirect_uri: Json_uri.t; (* GitHub calls this "Authorization callback URL" *)
  scope: string list;
  login: string option;
  allow_signup: bool option;
  prompt: github_prompt;
} [@@deriving yojson]

type github_plan = {
  name: string;
  space: int;
  private_repos: int;
  collaborators: int;
} [@@deriving yojson]

type user_response = {
  login: string;
  id: int;
  node_id: string;
  avatar_url: Json_uri.t;
  gravatar_id: string;
  url: Json_uri.t;
  html_url: Json_uri.t;
  followers_url: Json_uri.t;
  following_url: Json_uri.t;
  gists_url: Json_uri.t;
  starred_url: Json_uri.t;
  subscriptions_url: Json_uri.t;
  organizations_url: Json_uri.t;
  repos_url: Json_uri.t;
  events_url: Json_uri.t;
  received_events_url: Json_uri.t;
  user_type: string; (* NOTE: comes from github as "type" *)
  site_admin: bool;
  name: string;
  company: string;
  blog: Json_uri.t;
  location: string;
  email: string;
  hireable: bool;
  bio: string;
  twitter_username: string;
  public_repos: int;
  public_gists: int;
  followers: int;
  following: int;
  created_at: string;
  updated_at: string;
  private_gists: int;
  total_private_repos: int;
  owned_private_repos: int;
  disk_usage: int;
  collaborators: int;
  two_factor_authentication: bool;
  plan: github_plan
} [@@deriving yojson]

type token_response = {
  access_token: string;
  scope: (string option [@default None]);
  token_type: string;
} [@@deriving yojson]

(* NOTE: Some of these may never be used by GitHub, they're just copied from OAuth2 *)
type token_error_code =
  | Incorrect_Client_Credentials
  | Invalid_Request
  | Invalid_Client
  | Invalid_Grant
  | Unauthorized_Client
  | Unsupported_Grant_Type
  | Invalid_Scope
  | Invalid_Token

(* NOTE: Some of these may never be used by GitHub, they're just copied from OAuth2 *)
let token_error_code_to_yojson = function
  | Incorrect_Client_Credentials -> `String "incorrect_client_credentials"
  | Invalid_Request -> `String "invalid_request"
  | Invalid_Client -> `String "invalid_client"
  | Invalid_Grant -> `String "invalid_grant"
  | Unauthorized_Client -> `String "unauthorized_client"
  | Unsupported_Grant_Type -> `String "unsupported_grant_type"
  | Invalid_Scope -> `String "invalid_scope"
  | Invalid_Token -> `String "invalid_token"

(* NOTE: Some of these may never be used by GitHub, they're just copied from OAuth2 *)
let token_error_code_of_yojson = function
  | `String "incorrect_client_credentials" -> Ok Incorrect_Client_Credentials
  | `String "invalid_request" -> Ok Invalid_Request
  | `String "invalid_client" -> Ok Invalid_Client
  | `String "invalid_grant" -> Ok Invalid_Grant
  | `String "unauthorized_client" -> Ok Unauthorized_Client
  | `String "unsupported_grant_type" -> Ok Unsupported_Grant_Type
  | `String "invalid_scope" -> Ok Invalid_Scope
  | `String "invalid_token" -> Ok Invalid_Token
  | `String _ -> Ok Invalid_Request (* Default to Basic for unknown values *)
  | _ -> Error "expected string for error code"

(* NOTE: GitHub returns form-encoded values not JSON, this is primarily for reference *)
type token_error = {
  error: token_error_code;
  error_description: string;
  error_uri: (Json_uri.t option [@default None]);
} [@@deriving yojson]

type config =
  | GithubOauthConfig of github_oauth_config
[@@deriving yojson]

module DefaultInMemoryStorage = struct
  type value = config
  let ttl = 3600.0
end

module type GITHUB_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string), string) result
  val exchange_code_for_token : string -> string -> (token_response, string) result Lwt.t
  val get_user_info : token_response -> (user_response, string) result Lwt.t
end

module GitHubClient (Storage : Storage.STORAGE_UNIT with type value = config) : GITHUB_CLIENT = struct
  let get_authorization_url ~config =
    match config with
    | GithubOauthConfig gh_config -> begin
      (* Always generate a nice, safe, random, state value, since humans can't be trusted *)
      let state = Utils.generate_state () in
      let params = [
        ("client_id", gh_config.client_id);
        ("redirect_uri", Json_uri.to_string gh_config.redirect_uri);
        ("scope", String.concat " " gh_config.scope);
        ("state", state);
      ] @ (
        match gh_config.login with
          | Some login_value -> [ ("login", login_value) ]
          | None -> []
      ) @ (
        match gh_config.allow_signup with
          | Some true -> [ ("allow_signup", "true") ]
          | Some false -> [ ("allow_signup", "false") ]
          | None -> []
      ) @ (
        match gh_config.prompt with
          | Select_Account -> [ ("prompt", "select_account") ]
          | Other prompt_value -> [ ("prompt", prompt_value) ]
          | No_Prompt -> []
      ) in
      (* Store the things we will need for the second half of this operation *)
      Storage.update state config;
      let url = Uri.add_query_params' (Uri.of_string "https://github.com/login/oauth/authorize") params in
      Ok (url, state)
      end

  let exchange_code_for_token state code =
    match Storage.get state with
    | Some ((stored_config), _expires) -> begin
      Storage.remove state;
      match stored_config with
      | GithubOauthConfig config -> begin
        let params = [
          ("client_id", config.client_id);
          ("client_secret", config.client_secret);
          ("code", code);
          ("redirect_uri", Json_uri.to_string config.redirect_uri);
        ] in
        let body = Utils.form_encode params in
        Client.post ~body (Uri.of_string "https://github.com/login/oauth/access_token")
        >>= fun (_, body) -> Cohttp_lwt.Body.to_string body
        >>= fun body_str ->

        let decoded = Utils.form_decode body_str in
        let token_val = Hashtbl.find_opt decoded "access_token" in
        let scope_val = Hashtbl.find_opt decoded "scope" in
        let token_type_val = Option.value ~default:"" (Hashtbl.find_opt decoded "token_type") in
        let error_val = Hashtbl.find_opt decoded "error" in
        let error_desc_val = Option.value ~default:"" (Hashtbl.find_opt decoded "error_description") in
        let error_uri_val = Option.value ~default:"" (Hashtbl.find_opt decoded "error_uri") in

        match error_val, token_val with
        | Some err, None -> begin
          print_endline "Error:";
          print_endline err;
          print_endline error_desc_val;
          print_endline error_uri_val;
          Lwt.return (Error err)
          end
        | None, Some token -> begin
          Lwt.return (Ok { access_token = token ; scope = scope_val ; token_type = token_type_val })
          end
        | Some err, Some token -> begin
          print_endline "Both an error and a token were received and this is very strange";
          print_endline "Error:";
          print_endline err;
          print_endline error_desc_val;
          print_endline error_uri_val;
          Lwt.return (Ok { access_token = token ; scope = scope_val ; token_type = token_type_val })
          end
        | None, None -> begin
          print_endline "No error was returned, but also no token. Suspicious.";
          Lwt.return (Error "No token received")
          end
        end
      end
    | None -> Lwt.return (Error "State value did not match a known session")

  let get_user_info token =
    let headers = Cohttp.Header.init () in
    let headers = Cohttp.Header.add headers "Accept" "application/vnd.github+json" in
    let headers = Cohttp.Header.add headers "Authorization" ("Bearer " ^ token.access_token) in
    let* (resp, body) = Cohttp_lwt_unix.Client.get ~headers (Uri.of_string "https://api.github.com/user") in
    let code = resp
      |> Cohttp.Response.status
      |> Cohttp.Code.code_of_status in
    if Cohttp.Code.is_success code
    then
      let* body_str = Cohttp_lwt.Body.to_string body in
      (* This decoder is created by @@deriving yojson *)
      let json = Yojson.Safe.from_string body_str in
      match user_response_of_yojson json with
      | Ok user -> begin
        Lwt.return (Ok user)
        end
      | Error _ -> begin
          Lwt.return (Error "Failed to unwrap user object")
        end
    else
      Lwt.return (Error "Failed to successfully retrieve user")

end
