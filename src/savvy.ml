(* Savvy - A high-level OAuth2 client library *)

module type STORAGE_UNIT = Storage.STORAGE_UNIT
module type OAUTH2_CLIENT = Oauth2_client.OAUTH2_CLIENT
module type GITHUB_CLIENT = Github.GITHUB_CLIENT

module DefaultInMemoryStorage = Oauth2_client.DefaultInMemoryStorage
module GitHubInMemoryStorage = Github.DefaultInMemoryStorage
module OAuth2Client = Oauth2_client.OAuth2Client
module GitHubClient = Github.GitHubClient
