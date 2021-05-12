import 'dart:async';
import 'dart:io';
import 'package:shelf/shelf.dart';

import 'cookie_parser.dart';

/// Creates a Shelf [Middleware] to parse cookies.
///
/// Adds a [CookieParser] instance to `request.context['cookies']`,
/// with convenience methods to manipulate cookies in request handlers.
///
/// Adds a `Set-Cookie` HTTP header to the response with all cookies.

Middleware cookieParser([String secretKey = ""]) {
  return (Handler innerHandler) {
    return (Request request) {
      final cookies = CookieParser.fromHeader(request.headers, secretKey);
      return Future.sync(() {
        return innerHandler(
          request.change(context: {'cookies': cookies}),
        );
      }).then((Response response) {
        return cookies.isResponseEmpty
            ? response
            : response.change(
                headers: {HttpHeaders.setCookieHeader: cookies.toHeader()});
      });
    };
  };
}
