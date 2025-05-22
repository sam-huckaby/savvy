(*
        - A GitHub config struct
        - Create URL for the developer to put in a button
        - Create a token exchange method
*)

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

type config =
  | GithubOauthConfig of github_oauth_config
[@@deriving yojson]

module DefaultInMemoryStorage = struct
  type value = config
  let ttl = 3600.0
end

(* NOTE: When you wire in the auth request and token request, use the below values *)
(*
  token_endpoint: Uri.t; (* May always be: https://github.com/login/oauth/access_token *)
*)

module type GITHUB_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string), string) result
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
end
