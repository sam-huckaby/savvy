open Lwt.Infix
open Cohttp_lwt_unix

open Savvy

(* leverage the basic in-memory storage for demo purposes *)
module GenericInMemoryStorage = Storage.MakeInMemoryStorage(DefaultInMemoryStorage)
module Client = OAuth2Client(GenericInMemoryStorage)

(* leverage the basic in-memory storage for demo purposes (GitHub edition) *)
module GitHubInMemoryStorage = Storage.MakeInMemoryStorage(GitHubInMemoryStorage)
module GitHub = GitHubClient(GitHubInMemoryStorage)

(* A custom module might look something like this: *)
(*
module CustomStorage : STORAGE_UNIT = struct
  type t
  let storage_file = "oauth2_storage.txt"
  let get state_value = (* Use state_value to retrieve (code_verifier, config, expiration) *)
  let remove state_value = ()
  let update state_value (string * config) = ()
end
*)

(* This is an oversimplified http server to just demonstrate how things are laid out *)
(* It is however a _working_ example if you have an OAuth2 Server to point it to *)
let callback _conn req _body =
  (* Get the request path *)
  let path = Uri.path (Request.uri req) in
  
  match path with
  | "/client-creds" -> begin
      (* Each flow type has its own config type so the compiler can tell you forgot things *)
      let config = Oauth2_client.ClientCredentialsConfig {
        client_id = "your-client-id";
        client_secret = "your-client-secret";
        scope = ["foo:create" ; "foo:read" ; "foo:update"];
        token_auth_method = Basic; (* Can be Basic or Body - the two places that credentials can live in transit *)
        token_endpoint = Uri.of_string "https://example.com/token"; (* Client Credentials flow goes straight to the token endpoint *)
      } in
      Client.get_client_credentials_token ~config
        >>= fun token_result ->
        match token_result with
        | Ok token ->
          let token_info = 
            "<p>Auth was successful!</p>" ^
            "<p>Access Token: " ^ token.access_token ^ "</p>" ^
            (match token.refresh_token with
              | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
              | None -> "") in
          Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/client-creds'>Auth Again</a>") ()
        | Error message -> Server.respond_string ~status:`OK ~body:("Your princess is in another castle: " ^ message) ()
    end
  | "/" -> begin
      let config = Oauth2_client.AuthorizationCodeConfig {
        authorization_endpoint = Uri.of_string "https://example.com/authorize";
        client_id = "your-client-id";  (* Replace with your client ID *)
        client_secret = Some "your-client-secret";  (* Replace with your client secret UNLESS YOU ARE A PUBLIC CLIENT *)
        pkce = S256; (* Allowed values: S256, Plain, No_Pkce *)
        pkce_verifier = None; (* Pass None to have it auto-generate which is more secure *)
        redirect_uri = Uri.of_string "https://example.com/callback";  (* Replace with your redirect URI *)
        scope = ["bar:create" ; "bar:read" ; "bar:update"];  (* Replace with your desired scopes *)
        token_auth_method = Basic; (* Can be Basic or Body, depending on whether you are putting credentials in a basic header or the body *)
        token_endpoint = Uri.of_string "https://example.com/token";  (* Replace with your token endpoint *)
      } in
      match Client.get_authorization_url ~config with
      | Ok (auth_url, _state, _code_verifier) -> Server.respond_string ~status:`OK ~body:("<a href='" ^ Uri.to_string auth_url ^ "'>Authenticate</a>") ()
      | Error message -> Server.respond_string ~status:`OK ~body:("You've got problems: " ^ message) ()
    end
  | "/callback" -> begin
      let uri = Request.uri req in
      let code_query = Uri.get_query_param uri "code" in
      let state_query = Uri.get_query_param uri "state" in
      (* Here is where you should validate the state from the query params *)
      match state_query with
      | Some state -> begin
        match code_query with
        | Some code -> begin
          Client.exchange_code_for_token state code
          >>= fun token_result ->
            match token_result with
            | Ok token -> begin
            let token_info = 
              "<p>Auth was successful!</p>" ^
              "<p>Access Token: " ^ token.access_token ^ "</p>" ^
              (match token.refresh_token with
                | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
                | None -> "") in
            Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/'>Back to Login</a>") ()
          end
            | Error message -> Server.respond_string ~status:`OK ~body:("Authorization failed: " ^ message) ()
          end
        | None ->
          Server.respond_string ~status:`Bad_request ~body:"No code parameter provided" ()
        end
      | None -> Server.respond_string ~status:`Bad_request ~body:"No code parameter provided" ()
    end
  | "/refresh" -> begin
      let config = Oauth2_client.RefreshTokenConfig {
        client_id = "your-client-id";  (* Replace with your client ID *)
        client_secret = "your-client-secret";  (* Replace with your client secret *)
        refresh_token = "your-refresh-token"; (* Replace with the refresh token you saved for your user *)
        scope = Some(["bar:create" ; "bar:read" ; "bar:update"]);  (* Replace with the same or a more restrictive set of scopes that the access_token has already *)
        token_endpoint = Uri.of_string "https://example.com/token";  (* Replace with your token endpoint *)
        token_auth_method = Basic; (* Can be Basic or Body, depending on whether you are putting credentials in a basic header or the body *)
      } in
      Client.refresh_token ~config;
      >>= fun token_result ->
        match token_result with
        | Ok token -> begin
          let token_info = 
              "<p>Refresh was successful!</p>" ^
              "<p>Access Token: " ^ token.access_token ^ "</p>" ^
              (match token.refresh_token with
                | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
                | None -> "") in
            Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/'>Back to Login</a>") ()      (* Get our refresh_token (maybe in memory, in the session, etc *)
          end
        | Error message -> Server.respond_string ~status:`OK ~body:("There was an error: " ^ message) ()
    end
  | "/github" -> begin
    let config = Github.GithubOauthConfig {
      client_id = "your-client-id";
      client_secret = "your-client-secret";
      redirect_uri = Json_uri.of_string "your-github-callback-url";
      scope = ["user" ; "repo"];
      login = Some "my-user";
      (* While the spec lists allow_signup as a string, it ultimately just evaluates to true or false *)
      (* See here for more info: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps *)
      allow_signup = Some true; 
      prompt = No_Prompt; (* can force the account picker to appear if Select_Account is passed*)
    } in
    match GitHub.get_authorization_url ~config with
    | Ok (url, _state) -> Server.respond_string ~status:`OK ~body:("<a styles='padding: 4px; background-color: \"black\"; color: \"white\" border-radius: 4px;' href='" ^ Uri.to_string url ^ "'>Authenticate with GitHub</a>") ()
    | Error message -> Server.respond_string ~status:`OK ~body:("You've got problems: " ^ message) ()
    end
  | "/github-callback" -> begin
      Server.respond_string ~status:`OK ~body:("You did it!") ()
      (* Something needs to happen here *)
    end
  | _ -> begin
      (* Handle unknown paths *)
      Server.respond_string ~status:`Not_found ~body:"Not Found" ()
    end

let server =
  let callback = Server.make ~callback () in
  Server.create ~mode:(`TCP (`Port 8080)) callback

let () = Lwt_main.run server
