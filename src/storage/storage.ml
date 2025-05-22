(* Any user-defined storage implementation must have at least these three methods *)
module type STORAGE_UNIT =
  sig 
    type t
    type value (* (string * config * float) *)

    (* All storage mechanisms want to be sure that old data is cleared out eventually *)
    val ttl: float

    (* When implementing this interface, I recommend doing a clean out of stale values in get *)
    val get: string -> (value * float) option
    val remove: string -> unit
    val update: string -> value -> unit
  end

module type STORAGE_KIND =
  sig
    type value
    val ttl : float
  end

module MakeInMemoryStorage(V : STORAGE_KIND) : STORAGE_UNIT with type value = V.value =
  struct
    type value = V.value
    type stored = (value * float)
    type t = (string, stored) Hashtbl.t

    let ttl = V.ttl

    let store = Hashtbl.create 100

    let is_expired (_value, created_at) =
      Unix.time () -. created_at > V.ttl

    let clean () =
      Hashtbl.filter_map_inplace
        (fun _key v -> if is_expired v then None else Some v)
        store

    (* Due to sealing, only the below methods are publicly accessible *)
    let get state = 
      clean ();
      Hashtbl.find_opt store state

    let remove state = Hashtbl.remove store state
    
    let update state value = Hashtbl.replace store state (value, Unix.time ())
  end

