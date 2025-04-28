(lang dune 3.16)

(name savvy)

(generate_opam_files true)

(source
 (github sam-huckaby/savvy))

(authors "Sam huckaby")

(maintainers "Sam Huckaby")

(license MIT)

(documentation https://github.com/sam-huckaby/savvy)

(package
 (name savvy)
 (synopsis "A straightforward OAuth2 client")
 (description "A client library for OAuth2 that will help make the setup of secure auth flows easy to manage.")
 (depends
  ocaml
  dune
  (base64 (>= 3.5.0))
  cohttp-lwt-unix
  yojson
  uri
  ppx_deriving
  ppx_deriving_yojson
  cryptokit)
 (tags
  (oauth2 security oauth)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
