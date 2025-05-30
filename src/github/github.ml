(*
        - A GitHub config struct
        - Create URL for the developer to put in a button
        - Create a token exchange method
*)
open Lwt.Infix
open Cohttp_lwt_unix

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

type token_response = {
  access_token: string;
  scope: (string option [@default None]);
  token_type: string;
} [@@deriving yojson]

type token_error_code =
  | Incorrect_Client_Credentials
  | Invalid_Request
  | Invalid_Client
  | Invalid_Grant
  | Unauthorized_Client
  | Unsupported_Grant_Type
  | Invalid_Scope
  | Invalid_Token

let token_error_code_to_yojson = function
  | Incorrect_Client_Credentials -> `String "incorrect_client_credentials"
  | Invalid_Request -> `String "invalid_request"
  | Invalid_Client -> `String "invalid_client"
  | Invalid_Grant -> `String "invalid_grant"
  | Unauthorized_Client -> `String "unauthorized_client"
  | Unsupported_Grant_Type -> `String "unsupported_grant_type"
  | Invalid_Scope -> `String "invalid_scope"
  | Invalid_Token -> `String "invalid_token"

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
        (match Hashtbl.find_opt decoded "error" with
        | Some desc -> Printf.printf "Key 'error': \"%s\"\n" desc
        | None -> Printf.printf "Key 'error': Not found\n");

        (* This decoder is created by @@deriving yojson *)
        let json = Yojson.Safe.from_string body_str in

        match token_response_of_yojson json with
        | Ok token -> begin
          Lwt.return (Ok token)
          end
        | Error _ -> begin
          match token_error_of_yojson json with
          | Ok error -> begin
            print_endline error.error_description;
            Lwt.return (Error error.error_description)
            end
          | Error e -> begin
            print_endline e;
            Lwt.return (Error e)
            end
          end
        end
      (* Uncomment when device flow is added (someday) (maybe) *)
      (*| _ -> Lwt.return (Error "Code exchange only available for Authorization Code flow")*)
      end
    | None -> Lwt.return (Error "State value did not match a known session")
end
