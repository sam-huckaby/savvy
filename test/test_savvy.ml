open Savvy

(* leverage the basic in-memory storage for demo purposes *)
module GenericInMemoryStorage = Storage.MakeInMemoryStorage(DefaultInMemoryStorage)
module Client = OAuth2Client(GenericInMemoryStorage)

(* leverage the basic in-memory storage for demo purposes (GitHub edition) *)
module GitHubInMemoryStorage = Storage.MakeInMemoryStorage(GitHubInMemoryStorage)
module GitHub = GitHubClient(GitHubInMemoryStorage)

let () =
  print_endline "===========================================================================";
  print_endline "Most secure Auth Code Setup";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = S256;
    pkce_verifier = None;
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)
  

let () =
  print_endline "===========================================================================";
  print_endline "PKCE Plain";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = Plain;
    pkce_verifier = None;
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)


let () =
  print_endline "===========================================================================";
  print_endline "No PKCE";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = No_Pkce;
    pkce_verifier = None;
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)

let () =
  print_endline "===========================================================================";
  print_endline "PKCE Custom Plain";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = Plain;
    pkce_verifier = Some("definitelyrandomandultrasecurestringthatnoonewillguess");
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)

let () =
  print_endline "===========================================================================";
  print_endline "PKCE Custom S256";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = S256;
    pkce_verifier = Some("definitelyrandomandultrasecurestringthatnoonewillguess");
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)

let () =
  print_endline "===========================================================================";
  print_endline "Body token auth";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = S256;
    pkce_verifier = None;
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = ["bar:create" ; "bar:read" ; "bar:update"];
    token_auth_method = Body;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)

let () =
  print_endline "===========================================================================";
  print_endline "No scopes requested";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = Some "your-client-secret";
    pkce = S256;
    pkce_verifier = None;
    redirect_uri = Uri.of_string "https://example.com/callback";
    scope = [];
    token_auth_method = Basic;
    token_endpoint = Uri.of_string "https://example.com/token";
  } in
  match Client.get_authorization_url ~config with
  | Ok (auth_url, _state, _code_verifier) -> Printf.printf "Auth URL: %s\n Generated State: %s\n Verifier Used: %s\n\n\n" (Uri.to_string auth_url) _state _code_verifier
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)

let () =
  print_endline "===========================================================================";
  print_endline "No scopes requested";
  let config = Github.GithubOauthConfig {
      client_id = "your-client-id";
      client_secret = "your-client-secret";
      redirect_uri = Json_uri.of_string "http://localhost:8080/github-callback";
      scope = ["user" ; "repo"];
      login = Some "my-user";
      (* While the spec lists allow_signup as a string, it ultimately just evaluates to true or false *)
      (* See here for more info: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps *)
      allow_signup = Some true; 
      prompt = No_Prompt; (* can force the account picker to appear if Select_Account is passed*)
    } in
  match GitHub.get_authorization_url ~config with
  | Ok (url, _state) -> Printf.printf "Auth URL: %s\n Generated State: %s\n\n\n" (Uri.to_string url) _state
  | Error message -> failwith ("THIS SHOULD HAVE WORKED: " ^ message)
