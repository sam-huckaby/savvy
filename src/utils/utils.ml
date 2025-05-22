(* Generate a cryptographically secure random state value *)
let generate_state () =
  let open Cryptokit in
  let rng = Random.device_rng "/dev/urandom" in
  transform_string (Hexa.encode ()) (Random.string rng 32)

(* Create a code_verifier for PKCE *)
let generate_code_verifier () =
  let open Cryptokit in
  let rng = Random.device_rng "/dev/urandom" in
  transform_string (Hexa.encode ()) (Random.string rng 128)

let generate_code_challenge verifier =
  let hasher = Cryptokit.Hash.sha256 () in
  hasher#add_string verifier;
  let base64_string = Base64.encode_string ~pad:false hasher#result in
  (* URLs are so picky, can't have pluses, can't have slashes, can't have pictures, the worst. *)
  String.map (function '+' -> '-' | '/' -> '_' | c -> c) base64_string

let form_encode p =
  p |> List.map (fun (k,v) -> Printf.sprintf "%s=%s" k v)
  |> String.concat "&"
  |> Cohttp_lwt.Body.of_string

module Uri = struct
  include Uri
  let to_yojson uri = `String (Uri.to_string uri)
  let of_yojson = function
    | `String s -> Ok (Uri.of_string s)
    | _ -> Error "expected string for Uri.t"
end

