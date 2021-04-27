import 'dart:io';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:shelf_secure_cookie/shelf_secure_cookie.dart';
import 'package:test/test.dart';

void main() {
  test('isEmpty is true if header is empty', () {
    var cookies = CookieParser.fromCookieValue(null);
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

  test('folds all cookies into single set-cookie header value', () {
    var cookies = CookieParser.fromCookieValue('foo=bar');
    expect(cookies.toString(), equals('foo=bar; HttpOnly'));
    cookies.set('baz', 'qux', secure: true);
    expect(
      cookies.toString(),
      equals('foo=bar; HttpOnly, baz=qux; Secure; HttpOnly'),
    );
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
    var cookies = CookieParser.fromCookieValue(null, keyStr);
    await cookies.setEncrypted('baz', 'qux');
    var cookie = await cookies.getEncrypted('baz');
    expect(cookie != null, true);
    expect(cookie!.value, 'qux');
  });
}
