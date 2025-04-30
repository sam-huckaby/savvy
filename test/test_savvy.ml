open Savvy

module Client = OAuth2Client (InMemoryStorage)

let () =
  print_endline "===========================================================================";
  print_endline "Most secure Auth Code Setup";
  let config = Oauth2_client.AuthorizationCodeConfig {
    authorization_endpoint = Uri.of_string "https://example.com/authorize";
    client_id = "your-client-id";
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
    client_secret = "your-client-secret";
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
