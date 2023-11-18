import 'dart:io';
import 'dart:convert';

import 'package:collection/collection.dart' show IterableExtension;
import 'package:cryptography/cryptography.dart';
import 'package:shelf/shelf.dart';

/// Parses cookies from the `Cookie` header of a [Request].
///
/// Stores all cookies in a [cookies] list, and has convenience
/// methods to manipulate this list.
class CookieParser {
  //There were two paths... We need to distinguish request and response cookies.
  //So either clear each time the cookies store before returning response
  //Or create a separate CookieParser for responses only and manually set 'Set-Cookie' header
  //But I decided to split CookieParser.cookies list into two parts
  // An original list of parsed request cookies.
  final List<Cookie> cookies = [];
  final List<Cookie> responseCookies = [];
  final String _secretKey;

  // creates new empty CookieParser, same as CookieParser.fromCookieValue(null)
  CookieParser([String secretKey = ""])
      : _secretKey =
            (secretKey + "00000000000000000000000000000000").substring(0, 32);

  /// Creates a new [CookieParser] by parsing the `Cookie` header [value].
  CookieParser.fromCookieValue(String? value, [String secretKey = ""])
      : this._secretKey =
            (secretKey + "00000000000000000000000000000000").substring(0, 32) {
    if (value != null) {
      cookies.addAll(_parseCookieString(value));
    }
  }

  /// Factory constructor to create a new instance from request [headers].
  factory CookieParser.fromHeader(Map<String, dynamic> headers,
      [String secretKey = ""]) {
    return CookieParser.fromCookieValue(
        headers[HttpHeaders.cookieHeader], secretKey);
  }

  /// Use this method to set Response's 'set-cookie' header
  /// Shelf now supports multiple 'set-cookie' values, that is why method returns List<String>
  List<String> toHeader() => responseCookies.map((c) => c.toString()).toList();

  /// Denotes whether the [cookies] list is empty.
  bool get isEmpty => cookies.isEmpty;
  bool get isResponseEmpty => responseCookies.isEmpty;

  /// Retrieves a cookie by [name].
  Cookie? get(String name) =>
      cookies.firstWhereOrNull((Cookie cookie) => cookie.name == name);

  /// Retrieves a response cookie by [name]. You will rarely need this, but in case.
  Cookie? getResponse(String name) =>
      responseCookies.firstWhereOrNull((Cookie cookie) => cookie.name == name);

  /// Adds a new cookie to [responseCookies] list.
  Cookie set(String name, String value,
      {String? domain,
      String? path,
      DateTime? expires,
      bool? httpOnly,
      bool? secure,
      int? maxAge,
      SameSite? sameSite}) {
    var cookie = Cookie(name, value);
    if (domain != null) cookie.domain = domain;
    if (path != null) cookie.path = path;
    if (expires != null) cookie.expires = expires;
    if (httpOnly != null) cookie.httpOnly = httpOnly;
    if (secure != null) cookie.secure = secure;
    if (maxAge != null) cookie.maxAge = maxAge;
    if (sameSite != null) cookie.sameSite = sameSite;
    // Update existing cookie, or append new one to list.
    var index = responseCookies.indexWhere((item) => item.name == name);
    if (index != -1) {
      responseCookies.replaceRange(index, index + 1, [cookie]);
    } else {
      responseCookies.add(cookie);
    }
    return cookie;
  }

  /// Retrieves a deciphered cookie by [name].
  // secretKey length must be exactly 32 bytes
  Future<Cookie?> getEncrypted(String name) async {
    final keyBytes = utf8.encode(_secretKey);
    if (keyBytes.length != 32)
      throw Exception(
          'Expected secretKey length is 32, but got: ${keyBytes.length}');
    final scookie = get(name);
    if (scookie == null) return null;
    //copy cookie to prevent raw data leak :D
    final cookie = Cookie(scookie.name, scookie.value)
      ..domain = scookie.domain
      ..expires = scookie.expires
      ..httpOnly = scookie.httpOnly
      ..maxAge = scookie.maxAge
      ..path = scookie.path
      ..secure = scookie.secure;
    var decoded = base64Url.decode(cookie.value);
    if (decoded.length <= 12 + 16)
      throw Exception('Wrong encrypted cookie length');
    final algorithm = AesGcm.with256bits();
    final key = await algorithm.newSecretKeyFromBytes(keyBytes);
    //can't use fromConcatenation constructor because of this:
    //https://github.com/dint-dev/cryptography/issues/55
    //final box = SecretBox.fromConcatenation(decoded, nonceLength: 12, macLength: 16);
    final cipherText = decoded.skip(12).take(decoded.length - 12 - 16).toList();
    final nonce = decoded.take(12).toList();
    final mac =
        decoded.skip(nonce.length + cipherText.length).take(16).toList();
    final box = SecretBox(cipherText, nonce: nonce, mac: Mac(mac));
    final bytes = await algorithm.decrypt(box, secretKey: key);
    cookie.value = utf8.decode(bytes);
    return cookie;
  }

  /// Adds a new ciphered cookie to [cookies] list.
  // secretKey length must be exactly 32 bytes
  Future<Cookie> setEncrypted(
    String name,
    String value, {
    String? domain,
    String? path,
    DateTime? expires,
    bool? httpOnly,
    bool? secure,
    int? maxAge,
  }) async {
    final keyBytes = utf8.encode(_secretKey);
    if (keyBytes.length != 32)
      throw Exception(
          'Expected secretKey length is 32, but got: ${keyBytes.length}');
    final valueBytes = utf8.encode(value);
    final algorithm = AesGcm.with256bits(nonceLength: 12);

    final key = await algorithm.newSecretKeyFromBytes(keyBytes);
    // Encrypt
    final secretBox = await algorithm.encrypt(valueBytes, secretKey: key);
    var encryptedValue = base64Url.encode(secretBox.concatenation());

    return set(name, encryptedValue,
        domain: domain,
        path: path,
        expires: expires,
        httpOnly: httpOnly,
        secure: secure,
        maxAge: maxAge);
  }

  /// Removes a cookie from list by [name].
  /// Note: this does not delete a cookie in the browser
  /// To remove the cookie from browser cache you need to set a new one
  /// with exactly same name, path and domain, but with the expires date in the past, value is irrelevant
  void remove(String name) =>
      responseCookies.removeWhere((Cookie cookie) => cookie.name == name);

  /// Clears the cookie list.
  void clear() => responseCookies.clear();
}

/// Parse a Cookie header value according to the rules in RFC 6265.
/// This function was adapted from `dart:io`.
List<Cookie> _parseCookieString(String s) {
  var cookies = <Cookie>[];

  int index = 0;

  bool done() => index == -1 || index == s.length;

  void skipWS() {
    while (!done()) {
      if (s[index] != " " && s[index] != "\t") return;
      index++;
    }
  }

  String parseName() {
    int start = index;
    while (!done()) {
      if (s[index] == " " || s[index] == "\t" || s[index] == "=") break;
      index++;
    }
    return s.substring(start, index);
  }

  String parseValue() {
    int start = index;
    while (!done()) {
      if (s[index] == " " || s[index] == "\t" || s[index] == ";") break;
      index++;
    }
    return s.substring(start, index);
  }

  bool expect(String expected) {
    if (done()) return false;
    if (s[index] != expected) return false;
    index++;
    return true;
  }

  while (!done()) {
    skipWS();
    if (done()) continue;
    String name = parseName();
    skipWS();
    if (!expect("=")) {
      index = s.indexOf(';', index);
      continue;
    }
    skipWS();
    String value = parseValue();
    try {
      cookies.add(Cookie(name, value));
    } catch (_) {
      // Skip it, invalid cookie data.
    }
    skipWS();
    if (done()) continue;
    if (!expect(";")) {
      index = s.indexOf(';', index);
      continue;
    }
  }

  return cookies;
}
