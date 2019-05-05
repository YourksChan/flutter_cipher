part of flutter_cipher;

/// Wraps the RSA Engine Algorithm.
class RSA extends Asymmetric {
  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;

  final PublicKeyParameter<RSAPublicKey> _publicKeyParams;
  final PrivateKeyParameter<RSAPrivateKey> _privateKeyParameter;

  final AsymmetricBlockCipher _asymmetricBlockCipher = PKCS1Encoding(RSAEngine());


  RSA({this.publicKey, this.privateKey})
      : this._publicKeyParams = PublicKeyParameter(publicKey),
        this._privateKeyParameter = PrivateKeyParameter(privateKey);

  @override
  String decryptPrivate(Encrypted encrypted, {IV iv}) {
    if (privateKey == null) {
      throw StateError('Can\'t decrypt without a private key, null given.');
    }

    _asymmetricBlockCipher
      ..reset()
      ..init(false, _privateKeyParameter);

    return convert.utf8.decode(_asymmetricBlockCipher.process(encrypted.bytes));
  }

  @override
  String decryptPublic(Encrypted encrypted, {IV iv}) {
    if (publicKey == null) {
      throw StateError('Can\'t decrypt without a public key, null given.');
    }

    _asymmetricBlockCipher
      ..reset()
      ..init(false, _publicKeyParams);

    return convert.utf8.decode(_asymmetricBlockCipher.process(encrypted.bytes));
  }

  @override
  Encrypted encryptPrivate(String input, {IV iv}) {
    if (null == input || input.isEmpty) {
      throw StateError('The data cannot be null or empty.');
    }

    if (privateKey == null) {
      throw StateError('Can\'t encrypt without a private key, null given.');
    }

    _asymmetricBlockCipher
      ..reset()
      ..init(true, _privateKeyParameter);

    return Encrypted(
        _asymmetricBlockCipher.process(Uint8List.fromList(convert.utf8.encode(input))));
  }

  @override
  Encrypted encryptPublic(String input, {IV iv}) {
    if (null == input || input.isEmpty) {
      throw StateError('The data cannot be null or empty.');
    }

    if (null == publicKey) {
      throw StateError('Can\'t encrypt without a public key, null given.');
    }

    _asymmetricBlockCipher
      ..reset()
      ..init(true, _publicKeyParams);

    return Encrypted(
        _asymmetricBlockCipher.process(Uint8List.fromList(convert.utf8.encode(input))));
  }
}

/// RSA PEM parser.
class RSAKeyParser {
  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus, exponent);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(convert.base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[1] as ASN1BitString;
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1BitString bitString = sequence.elements[2] as ASN1BitString;
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}

