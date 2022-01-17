# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2022-01-17
### Changed
- Allowed to use a key with different than 32-bytes length, what is more
  user-friendly, but somewhat less secure. The key is padded with zeroes and
  trimmed to 32 bytes automatically. Backward compatible.

## [1.2.0] - 2021-04-27
### Changed
- Changed original middleware, now you don't have to set response 'Set-Cookie' headers manually, it will handle it if you operate on Request.context['cookies'] storage, see example.
- Now CookieParser have separated lists of Request cookies [cookies] and Response cookies [responseCookies], so this is a somewhat a breaking change.
- Now 'get' methods operate on a request cookies list, and 'set' on a response list. The exception is a 'getResponse' method that allows to read a newly set cookie if you need that.

## [1.1.0] - 2021-04-27
### Fixed
- Changed original middleware, now you have to set response headers explicitly, see example. But I will rearrange this later.
- Now encrypted cookies use `base64Url` encoding instead of `base64`.

## [1.0.6] - 2021-04-27
### Fixed
- Fixed CHANGELOG

## [1.0.5] - 2021-04-27
### Fixed
- Fixed middleware to accept secureKey
- Updated example and readme

## [1.0.2] - 2021-04-27
### Fixed
- Changed API, now secureKey is set at construction, get/setEncrypted methods use the same signature as get/set

## [1.0.1] - 2021-04-27
### Fixed
- Fixed security issue

## [1.0.0] - 2021-04-10
### Added
- Cookie parser with setEncrypted & getEncrypted methods
- All original code copied from null-safe branch of shelf_cookie
