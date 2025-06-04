## 0.4.0 (2025-06-04)

### Added 

- Implemented GitHub integration for Savvy! You can now authenticate with GitHub as your source of truth.

## 0.3.0 (2025-05-04)

### Added

- Handling for public clients by passing None to client_secret

### Changed

- Confidential clients now need to pass a string option to client_secret


## 0.2.0 (2025-04-25)

### Added

- InMemoryStorage is now available as a simple storage utility

### Changed

- OAuth2Client now requires a storage interface to be passed into the constructor

