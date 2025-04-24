(* Savvy - A high-level OAuth2 client library *)

module type STORAGE_UNIT = Oauth2_client.STORAGE_UNIT
module type OAUTH2_CLIENT = Oauth2_client.OAUTH2_CLIENT
module InMemoryStorage = Oauth2_client.InMemoryStorage
module OAuth2Client = Oauth2_client.OAuth2Client

