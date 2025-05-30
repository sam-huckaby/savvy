(* Expose the necessary things to use GitHub *)

type github_prompt =
  | No_Prompt
  | Select_Account
  | Other of string

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
  scope: string option;
  token_type: string;
} [@@deriving yojson]

type config =
  | GithubOauthConfig of github_oauth_config
[@@deriving yojson]

module DefaultInMemoryStorage : sig
  type value = config
  val ttl : float
end

module type GITHUB_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string), string) result
  val exchange_code_for_token : string -> string -> (token_response, string) result Lwt.t
end

module GitHubClient (_ : Storage.STORAGE_UNIT with type value = config) : GITHUB_CLIENT
