module T = struct
  type t = Uri.t
  let to_yojson uri = `String (Uri.to_string uri)
  let of_yojson = function
    | `String s -> Ok (Uri.of_string s)
    | _ -> Error "expected string for Uri.t"
end

(* This is a fancy way of wrapping our new methods (above) into the Uri module *)
(* Essentially what's happening here is the Uri module is brought into context *)
(* and then our struct above is added to context on top of it and the total is returned *)
include Uri
include T
