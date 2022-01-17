import 'dart:io';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_secure_cookie/shelf_secure_cookie.dart';
import 'package:test/test.dart';

class NoCookieException implements Exception {}

Matcher throwsNoCookieException = throwsA(isA<NoCookieException>());

class TestRouter {
  Handler get handler {
    final router = Router();

    router.get('/gets', (Request request) async {
      var cookies = request.context["cookies"] as CookieParser;
      if (cookies.get("user") == null) throw NoCookieException();
      return Response.ok("a");
    });
    router.get('/sets', (Request request) async {
      var cookies = request.context["cookies"] as CookieParser;
      cookies.set("user", "1");
      return Response.ok("a");
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

  test('isResponseEmpty is true if header is empty', () {
    var cookies = CookieParser.fromCookieValue(null);
    expect(cookies.isResponseEmpty, isTrue);
  });

  test('isResponseEmpty is true if default constructor used', () {
    var cookies = CookieParser();
    expect(cookies.isResponseEmpty, isTrue);
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

  test('adds new cookie to responseCookies list', () {
    var cookies = CookieParser();
    expect(cookies.getResponse('baz'), isNull);
    cookies.set('baz', 'qux');
    expect(cookies.getResponse('baz')!.value, 'qux');
  });

  test('removes cookie from cookies list by name', () {
    var cookies = CookieParser();
    cookies.set('baz', 'qux');
    cookies.remove('baz');
    expect(cookies.getResponse('baz'), isNull);
  });

  test('clears all cookies in list', () {
    var cookies = CookieParser();
    cookies.set('baz', 'qux');
    cookies.clear();
    expect(cookies.isResponseEmpty, isTrue);
  });

  //encrypted cookies
  test('encodes and ciphers an encrypted cookie', () async {
    final keyStr = "12345678901234567890123456789012";
    var cookies = CookieParser(keyStr);
    await cookies.setEncrypted('baz', 'qux');
    var cookie = cookies.getResponse('baz');
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
    var cookie = await cookies.setEncrypted('baz', 'qux');
    //as cookies list is split now, need to create a new parser as if I'm working in a subsequent request
    var cookie2 = Cookie.fromSetCookieValue(cookie.toString());
    var cookies2 = CookieParser(keyStr)..cookies.add(cookie2);
    var cookie3 = await cookies2.getEncrypted('baz');
    expect(cookie3, isNotNull);
    expect(cookie3!.value, 'qux');
  });

  test('works with key less than 32 bytes in length', () async {
    final keyStr = "12345678901234567890";
    var cookies = CookieParser(keyStr);
    var cookie = await cookies.setEncrypted('baz', 'qux');
    //as cookies list is split now, need to create a new parser as if I'm working in a subsequent request
    var cookie2 = Cookie.fromSetCookieValue(cookie.toString());
    var cookies2 = CookieParser(keyStr)..cookies.add(cookie2);
    var cookie3 = await cookies2.getEncrypted('baz');
    expect(cookie3, isNotNull);
    expect(cookie3!.value, 'qux');
  });

  test('works with key more than 32 bytes in length', () async {
    final keyStr =
        "123456789012345678901234567890129999999999999999999999999999";
    var cookies = CookieParser(keyStr);
    var cookie = await cookies.setEncrypted('baz', 'qux');
    //as cookies list is split now, need to create a new parser as if I'm working in a subsequent request
    var cookie2 = Cookie.fromSetCookieValue(cookie.toString());
    var cookies2 = CookieParser(keyStr)..cookies.add(cookie2);
    var cookie3 = await cookies2.getEncrypted('baz');
    expect(cookie3, isNotNull);
    expect(cookie3!.value, 'qux');
  });

  test('Middleware reads cookies and does not write if not told to', () async {
    final cp = CookieParser();
    final cookie = cp.set("user", "1");
    final request = Request(
      'GET',
      Uri.parse('http://localhost:8080/gets'),
      headers: {"cookie": cookie.toString()},
    );

    expect(() async => await router(request), returnsNormally);

    final Response response = await router(request);
    expect(response.headers[HttpHeaders.setCookieHeader], null,
        reason: "Does not retranslate cookies as before");
  });

  test('Middleware throws NoCookieException if expected cookie not set',
      () async {
    final cp = CookieParser();
    final cookieWrong = cp.set("user2", "1");
    final request = Request(
      'GET',
      Uri.parse('http://localhost:8080/gets'),
      headers: {"cookie": cookieWrong.toString()},
    );
    expect(() async => await router(request), throwsNoCookieException);
  });

  test('Middleware sets a cookie', () async {
    final request = Request(
      'GET',
      Uri.parse('http://localhost:8080/sets'),
    );
    expect(() async => await router(request), returnsNormally);
    final response = await router(request);
    expect(response, isNotNull);
    expect(response.headers[HttpHeaders.setCookieHeader], isNotNull);
    final cookie = Cookie.fromSetCookieValue(
        response.headers[HttpHeaders.setCookieHeader]!);
    expect(cookie.name, "user");
    expect(cookie.value, "1");
  });
}
