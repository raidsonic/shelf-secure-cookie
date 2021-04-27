import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_cookie/shelf_secure_cookie.dart';

void main() {
  /// Request contains cookie header.
  /// e.g. 'cookie': 'ping=foo'

  /// use your 32-byte secure key during middleware construction
  /// don't save it in your source code btw
  /// consider something like this:
  /// final secretKey = myConfig.load('config.json').secretKey
  /// and add config.json to .gitignore
  final secretKey = "12345678901234567890123456789012";
  var handler = const shelf.Pipeline()
      .addMiddleware(cookieParser(secretKey))
      .addHandler((req) async {
    CookieParser cookies = req.context['cookies'] as CookieParser;
    if (cookies.get('ping') != null) {
      // Clear cookies because Shelf currently only supports
      // a single `Set-Cookie` header in response.
      cookies.clear();
      //secure: true - means send it via https only
      cookies.setEncrypted('pong', 'bar', secure: true, httpOnly: true);
    }

    // Response will set cookie header.
    // e.g. 'set-cookie': 'pong=someencryptedandsignedvalue; Secure; HttpOnly'
    return shelf.Response.ok('check your cookies');
  });

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });
}
