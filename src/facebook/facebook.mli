(* Expose the necessary things to use Facebook *)

type facebook_oauth_config = {
  client_id: string;
  client_secret: string;
  redirect_uri: Json_uri.t;
  scope: string list;
} [@@deriving yojson]

(** A minimal user response; extend as needed *)
type user_response = {
  id: string;
  name: string;
  email: string option;
} [@@deriving yojson]

(** Token response per Facebook Graph API *)
type token_response = {
  access_token: string;
  token_type: string option;
  expires_in: int option;
} [@@deriving yojson]

(** Config wrapper type for storage *)
type config =
  | FacebookOauthConfig of facebook_oauth_config
[@@deriving yojson]

module DefaultInMemoryStorage : sig
  type value = config
  val ttl : float
end

module type FACEBOOK_CLIENT =
sig
  val get_authorization_url : config:config -> ((Uri.t * string), string) result
  val exchange_code_for_token : string -> string -> (token_response, string) result Lwt.t
  (** Retrieves the currently authenticated user's information *)
  val get_user_info : token_response -> (user_response, string) result Lwt.t
end

module FacebookClient (_ : Storage.STORAGE_UNIT with type value = config) : FACEBOOK_CLIENT
