part of flutter_cipher;

/// Wraps the AES Algorithm.
class AES implements Symmetry {
  final Key key;
  final AESMode mode;
  final String padding;
  final BlockCipher _blockCipher;

  AES(this.key, {this.mode = AESMode.sic, this.padding = 'PKCS7'})
      : _blockCipher = padding != null
      ? PaddedBlockCipher('AES/${_modes[mode]}/$padding')
      : BlockCipher('AES/${_modes[mode]}');

  @override
  Encrypted encrypt(Uint8List bytes, {IV iv}) {
    _blockCipher
      ..reset()
      ..init(true, _buildParams(iv));

    return Encrypted(_blockCipher.process(bytes));
  }

  @override
  Encrypted encryptString(String input, {IV iv}) {
    _blockCipher
      ..reset()
      ..init(true, _buildParams(iv));

    return Encrypted(
        _blockCipher.process(Uint8List.fromList(convert.utf8.encode(input))));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV iv}) {
    _blockCipher
      ..reset()
      ..init(false, _buildParams(iv));

    return _blockCipher.process(encrypted.bytes);
  }

  @override
  String decrypt2String(Encrypted encrypted, {IV iv}) {
    _blockCipher
      ..reset()
      ..init(false, _buildParams(iv));

    return convert.utf8.decode(_blockCipher.process(encrypted.bytes));
  }

  CipherParameters _buildParams(IV iv) {
    if (padding != null) {
      return _paddedParams(iv);
    }

    if (mode == AESMode.ecb) {
      return KeyParameter(key.bytes);
    }

    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }

  PaddedBlockCipherParameters _paddedParams(IV iv) {
    if (mode == AESMode.ecb) {
      return PaddedBlockCipherParameters(KeyParameter(key.bytes), null);
    }

    return PaddedBlockCipherParameters(
        ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes),
        null);
  }
}

enum AESMode {
  cbc,
  cfb64,
  ctr,
  ecb,
  ofb64Gctr,
  ofb64,
  sic,
}

const Map<AESMode, String> _modes = {
  AESMode.cbc: 'CBC',
  AESMode.cfb64: 'CFB-64',
  AESMode.ctr: 'CTR',
  AESMode.ecb: 'ECB',
  AESMode.ofb64Gctr: 'OFB-64/GCTR',
  AESMode.ofb64: 'OFB-64',
  AESMode.sic: 'SIC',
};