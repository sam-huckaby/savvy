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
  p |> List.map (fun (k, v) -> Printf.sprintf "%s=%s" k v)
    |> String.concat "&"
    |> Cohttp_lwt.Body.of_string

let replace_char_in_string str old_char new_char =
  String.map (fun c -> if c = old_char then new_char else c) str

(* Function to parse a URL-encoded string (query string) into a hash table *)
let form_decode p : (string, string) Hashtbl.t =
  (* Create a new hash table to store the parameters.
     The initial size (e.g., 10) is a hint and doesn't limit the table's capacity.
  *)
  let params_tbl = Hashtbl.create 10 in

  (* Handle empty input string: return an empty hash table *)
  if String.length p = 0 then
    params_tbl
  else
    begin
      (* Split the query string into segments by '&' *)
      String.split_on_char '&' p

      (* Filter out any empty segments that might result from "&&" or trailing/leading "&" *)
      |> List.filter (fun s -> String.length s > 0)
      (* Process each segment (which should be a "key=value" string) *)
      |> List.iter (fun pair_str ->
          (* Split the segment into a key and a value part.
             We look for the first '=' to separate key from value.
             If no '=' is found, the whole string is considered a key with an empty value.
          *)
          let (raw_key, raw_value) =
            match String.index_opt pair_str '=' with
            | Some idx ->
                (* Found '=', split into key and value *)
                (String.sub pair_str 0 idx,
                 String.sub pair_str (idx + 1) (String.length pair_str - idx - 1))
            | None ->
                (* No '=', the whole string is the key, value is empty *)
                (pair_str, "")
          in

          (* Decode the key:
             1. Replace '+' with ' ' (space).
             2. Percent-decode (e.g., %2F becomes /).
          *)
          let key =
            raw_key
            |> (fun s -> replace_char_in_string s '+' ' ')
            |> Uri.pct_decode
          in

          (* Decode the value:
             1. Replace '+' with ' ' (space).
             2. Percent-decode.
          *)
          let value =
            raw_value
            |> (fun s -> replace_char_in_string s '+' ' ')
            |> Uri.pct_decode
          in

          (* Add the decoded key-value pair to the hash table.
             If the key already exists, its value will be updated (last one wins).
          *)
          Hashtbl.replace params_tbl key value
        );
      params_tbl (* Return the populated hash table *)
    end

module Uri = struct
  include Uri
  let to_yojson uri = `String (Uri.to_string uri)
  let of_yojson = function
    | `String s -> Ok (Uri.of_string s)
    | _ -> Error "expected string for Uri.t"
end

