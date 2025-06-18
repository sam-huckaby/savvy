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
  user_type: string; [@key "type"] (* NOTE: comes from github as "type" *)
  user_view_type: string;
  site_admin: bool;
  name: string;
  company: string;
  blog: Json_uri.t;
  location: string;
  email: string option;
  hireable: bool option;
  bio: string option;
  twitter_username: string;
  notification_email: string option;
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
  (** Retrieves the currently authenticated user's information *)
  val get_user_info : token_response -> (user_response, string) result Lwt.t
end

module GitHubClient (_ : Storage.STORAGE_UNIT with type value = config) : GITHUB_CLIENT
