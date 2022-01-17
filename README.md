# shelf_secure_cookie
Encrypted cookies use `base64Url` encoding. See `example/example.dart` for details.

Based on `shelf_cookie` package, added async `setEncrypted` and `getEncrypted` cookie methods, that support `AES-GCM` cipher with digest. These should be used to store sensitive data, if you prefer a cookie storage.

Both methods require a 32-byte secret key. You can use a key with a different
length, but be warned that it will be padded with zeroes and trimed to 32
bytes exactly.

This package is not battle-tested yet, but I'm working on this. Also if you happened to download 1.0.0 version, update to >=1.0.2 as soon as possible.

## Original docs

Cookie parser middleware for the Dart Shelf ecosystem.
Reads cookies in request, sets cookies in response.

Adds a `CookieParser` instance to `request.context['cookies']` to help
manipulate cookies.

## Example

```dart
import 'dart:io';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf_cookie/shelf_cookie.dart';

/// Handle a request that contains a `Cookie` header.
/// e.g. 'Cookie': 'ping=foo'
var handler = const shelf.Pipeline()
    // initialize cookie parser middleware
    .addMiddleware(cookieParser())
    .addHandler((req) async {
  CookieParser cookies = req.context['cookies'];

  // Retrieve request cookies.
  var reqCookie = cookies.get('ping');
  print(reqCookie.name); // foo

  // Clear cookies because Shelf currently only supports
  // a single `Set-Cookie` header in response.
  cookies.clear();

  // Create a cookie for response.
  var resCookie = cookies.set('pong', 'bar', secure: true);

  // Middleware will add `Set-Cookie` response header.
  // e.g. 'Set-Cookie': 'pong=bar; Secure; HttpOnly'
  return shelf.Response.ok('OK', headers: {HttpHeaders.setCookieHeader: cookies.toHeader()});
});
```

## TODO
Add handy Request & Response extensions or adapt `cookieParser()` middleware to read newly set cookies. The original version of middleware required to call `cookies.clear()` every time before setting new values and if you forget this, it became messy. So now you have to set headers explicitly, but hopefully not for long.
