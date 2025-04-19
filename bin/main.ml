open Lwt.Infix
open Cohttp_lwt_unix

open Savvy

let callback _conn req _body =
  (* Get the request path *)
  let path = Uri.path (Request.uri req) in
  
  match path with
  | "/client-creds" -> begin
      (* Each flow type has its own config type so the compiler can tell you forgot things *)
      let config = Oauth2_client.ClientCredentialsConfig {
        client_id = "your-client-id";
        client_secret = "your-client-secret";
        token_auth_method = Basic; (* Can be Basic or Body - the two places that credentials can live in transit *)
        token_endpoint = Uri.of_string "https://example.com/token";
        scope = ["foo:create" ; "foo:read" ; "foo:update"];
      } in
      let client = create ClientCredentials config in
      get_client_credentials_token client;
        >>= fun token ->
          let token_info = 
            "<p>Auth was successful!</p>" ^
            "<p>Access Token: " ^ token.access_token ^ "</p>" ^
            (match token.refresh_token with
              | Some refresh_token -> "<p>Refresh Token: " ^ refresh_token ^ "</p>"
              | None -> "") in
          Server.respond_string ~status:`OK ~body:(token_info ^ "<a href='/client-creds'>Auth Again</a>") ()
    end
  | "/" -> begin
      let config = Oauth2_client.AuthorizationCodeConfig {
        authorization_endpoint = Uri.of_string "https://example.com/authorize";
        client_id = "your-client-id";  (* Replace with your client ID *)
        client_secret = "your-client-secret";  (* Replace with your client secret *)
        pkce = S256; (* Allowed values: S256, Plain, No_Pkce *)
        pkce_verifier = Some("definitelyrandomandultrasecurestringthatnoonewillguess"); (* Pass None to have it auto-generate which is more secure *)
        redirect_uri = Uri.of_string "https://example.com/callback";  (* Replace with your redirect URI *)
        scope = ["bar:create" ; "bar:read" ; "bar:update"];  (* Replace with your desired scopes *)
        token_auth_method = Basic;
        token_endpoint = Uri.of_string "https://example.com/token";  (* Replace with your token endpoint *)
      } in
      let client = create AuthorizationCode config in
      (* TODO: Let's build an in-memory storage for state/code_verifier that the user can optionally replace *)
      (* This will allow the library to do the checks automatically, and then when the app goes to production *)
      (* The developer will just need to provide their own storage implementation (or risk memory issues) *)
      let (auth_url, _state, _code_verifier) = get_authorization_url client in
      (* Handle root path *)
      Server.respond_string ~status:`OK ~body:("<a href='" ^ Uri.to_string auth_url ^ "'>Authenticate</a>") ()
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
          exchange_code_for_token state code
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
    end
  | _ -> begin
      (* Handle unknown paths *)
      Server.respond_string ~status:`Not_found ~body:"Not Found" ()
    end

let server =
  let callback = Server.make ~callback () in
  Server.create ~mode:(`TCP (`Port 8080)) callback

let () = Lwt_main.run server
