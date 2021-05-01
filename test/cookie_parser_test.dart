import 'dart:io';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_secure_cookie/shelf_secure_cookie.dart';
import 'package:test/test.dart';

class NoCookieException implements Exception {}

class TestRouter {
  Handler get handler {
    final router = Router();

    router.get('/gets', (Request request) async {
      var cookies = request.context["cookies"] as CookieParser;
      if (cookies == null || cookies.get("user") == null)
        throw NoCookieException();
      return Response.ok("a");
    });
    router.get('/sets', (Request request) async {
      final cp = CookieParser();
      cp.set("user", "1");
      return Response.ok("a",
          headers: {HttpHeaders.setCookieHeader: cp.toHeader()});
    });

    var handler =
        const Pipeline().addMiddleware(cookieParser()).addHandler(router);

    return handler;
  }
}

void main() {
  late final Handler router = TestRouter().handler;

  test('isEmpty is true if header is empty', () {
    var cookies = CookieParser.fromCookieValue(null);
    expect(cookies.isEmpty, isTrue);
  });

  test('isEmpty is true if default constructor used', () {
    var cookies = CookieParser();
    expect(cookies.isEmpty, isTrue);
  });

  test('parses cookies from `cookie` header value', () {
    var cookies = CookieParser.fromCookieValue('foo=bar; baz=qux');
    expect(cookies.isEmpty, isFalse);
    expect(cookies.get('foo')!.value, equals('bar'));
    expect(cookies.get('baz')!.value, equals('qux'));
  });

  test('parses cookies from raw headers map', () {
    var cookies =
        CookieParser.fromHeader({HttpHeaders.cookieHeader: 'foo=bar; baz=qux'});
    expect(cookies.isEmpty, isFalse);
    expect(cookies.get('foo')!.value, equals('bar'));
    expect(cookies.get('baz')!.value, equals('qux'));
  });

  test('adds new cookie to cookies list', () {
    var cookies = CookieParser.fromCookieValue('foo=bar');
    expect(cookies.isEmpty, isFalse);
    expect(cookies.get('baz'), isNull);
    cookies.set('baz', 'qux');
    expect(cookies.get('baz')!.value, 'qux');
  });

  test('removes cookie from cookies list by name', () {
    var cookies = CookieParser.fromCookieValue('foo=bar; baz=qux');
    expect(cookies.get('baz')!.value, equals('qux'));
    cookies.remove('baz');
    expect(cookies.get('baz'), isNull);
  });

  test('clears all cookies in list', () {
    var cookies = CookieParser.fromCookieValue('foo=bar; baz=qux');
    expect(cookies.get('baz')!.value, equals('qux'));
    cookies.clear();
    expect(cookies.isEmpty, isTrue);
  });

  //encrypted cookies
  test('encodes and ciphers an encrypted cookie', () async {
    final keyStr = "12345678901234567890123456789012";
    var cookies = CookieParser.fromCookieValue(null, keyStr);
    await cookies.setEncrypted('baz', 'qux');
    var cookie = cookies.get('baz');
    var decoded = base64.decode(cookie!.value);
    final algorithm = AesGcm.with256bits();
    final key = await algorithm.newSecretKeyFromBytes(utf8.encode(keyStr));
    //can't use fromConcatenation constructor because of this:
    //https://github.com/dint-dev/cryptography/issues/55
    //final box = SecretBox.fromConcatenation(decoded, nonceLength: 12, macLength: 16);
    final cipherText = decoded.skip(12).take(decoded.length - 12 - 16).toList();
    final nonce = decoded.take(12).toList();
    final mac =
        decoded.skip(nonce.length + cipherText.length).take(16).toList();
    final box = SecretBox(cipherText, nonce: nonce, mac: Mac(mac));
    final bytes = await algorithm.decrypt(box, secretKey: key);
    final value = utf8.decode(bytes);
    expect(value, 'qux');
  });

  test('decodes and deciphers an encrypted cookie', () async {
    final keyStr = "12345678901234567890123456789012";
    var cookies = CookieParser(keyStr);
    await cookies.setEncrypted('baz', 'qux');
    var cookie = await cookies.getEncrypted('baz');
    expect(cookie != null, true);
    expect(cookie!.value, 'qux');
  });

  test('Middleware sets and reads cookies', () async {
    final cp = CookieParser();
    final cookie = cp.set("user", "1");
    final cookieWrong = cp.set("user2", "1");

    try {
      final Response response = await router(Request(
        'GET',
        Uri.parse('http://localhost:8080/gets'),
        headers: {"cookie": cookie.toString()},
      ));
      expect(true, true, reason: "user cookie present in headers");
      expect(response.headers[HttpHeaders.setCookieHeader], null,
          reason: "Does not retranslate cookies as before");
    } catch (e) {
      expect(true, false, reason: e.toString());
    }

    try {
      await router(Request(
        'GET',
        Uri.parse('http://localhost:8080/gets'),
        headers: {"cookie": cookieWrong.toString()},
      ));
      expect(true, false, reason: "Must throw NoCookieException");
    } on NoCookieException {} catch (e) {
      expect(true, false, reason: e.toString());
    }

    try {
      final response = await router(Request(
        'GET',
        Uri.parse('http://localhost:8080/sets'),
      ));
      expect(response != null, true);
      expect(response.headers[HttpHeaders.setCookieHeader] != null, true);
      final cookie = Cookie.fromSetCookieValue(
          response.headers[HttpHeaders.setCookieHeader]!);
      expect(cookie.name, "user");
      expect(cookie.value, "1");
    } catch (e) {
      expect(true, false, reason: e.toString());
    }
  });
}
