# OAuth2 Client for OCaml

An easy to use OAuth2 client for your next OCaml app


## Example usages

Savvy is designed so that you can just open it at the top and leverage whatever you need. The below examples assume you have `open Savvy` at the top of your file, but if you would rather not do that, just add `Savvy.` before the functions (which you can find a list of in `src/savvy.mli`).

### Client Credentials

```ocaml
(* Each flow type has its own config type so the compiler can tell you forgot things *)
  let config = Oauth2_client.ClientCredentialsConfig {
    client_id = "your-client-id";
    client_secret = "your-client-secret";
    scope = ["foo:create" ; "foo:read" ; "foo:update"];
    token_auth_method = Basic; (* Can be Basic or Body - the two places that credentials can live in transit *)
    token_endpoint = Uri.of_string "https://example.com/token"; (* Client Credentials flow goes straight to the token endpoint *)
  } in
  Client.get_client_credentials_token ~config
    >>= fun token ->
      let token_info = 
        "<p>Auth was successful!</p>" ^
        "<p>Access Token: " ^ token.access_token ^ "</p>" ^
        (match token.refresh_token with
          | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
          | None -> "") in
      Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/client-creds'>Auth Again</a>") ()
```


### Authorization Code

First you need to construct the authorize URL, so you can pass your config in and have Savvy generate that for you.

```ocaml
let config = Oauth2_client.AuthorizationCodeConfig {
  authorization_endpoint = Uri.of_string "https://example.com/authorize";
  client_id = "your-client-id";  (* Replace with your client ID *)
  client_secret = "your-client-secret";  (* Replace with your client secret *)
  pkce = S256; (* Allowed values: S256, Plain, No_Pkce *)
  pkce_verifier = None; (* Pass None to have it auto-generate which is more secure *)
  redirect_uri = Uri.of_string "https://example.com/callback";  (* Replace with your redirect URI *)
  scope = ["bar:create" ; "bar:read" ; "bar:update"];  (* Replace with your desired scopes *)
  token_auth_method = Basic; (* Can be Basic or Body, depending on whether you are putting credentials in a basic header or the body *)
  token_endpoint = Uri.of_string "https://example.com/token";  (* Replace with your token endpoint *)
} in
let (auth_url, _state, _code_verifier) = Client.get_authorization_url ~config in
```

When generating the authorize URL, you will also receive a state value and a PKCE code_verifier. Savvy will store these (as noted below) but if you need them for an external auth service or because your callback route is being served from another server, you can grab them and stash them wherever you please.

Because token exchange is a request FROM the OAuth2 server TO your app, it will happen in a separate part of your code. Savvy can store the PKCE code_verifier and flow config in-memory for you, using the InMemoryStorage module that comes bundled in, but you should plan to implement your own storage module that matches the STORAGE_UNIT interface before going to production.
```ocaml
let uri = Request.uri req in
let code_query = Uri.get_query_param uri "code" in
let state_query = Uri.get_query_param uri "state" in
(* Here is where you should validate the state from the query params *)
match state_query with
| Some state -> begin
  match code_query with
  | Some code -> begin
    Client.exchange_code_for_token state code
    >>= fun token ->
      let token_info = 
        "<p>Auth was successful!</p>" ^
        "<p>Access Token: " ^ token.access_token ^ "</p>" ^
        (match token.refresh_token with
          | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
          | None -> "") in
      Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/'>Back to Login</a>") ()
    end
  | None ->
    Server.respond_string ~status:`Bad_request ~body:"No code parameter provided" ()
  end
| None -> Server.respond_string ~status:`Bad_request ~body:"No code parameter provided" ()
```

