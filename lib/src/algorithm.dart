part of flutter_cipher;

/// Interface for the Algorithms.
abstract class Symmetry {
  /// Encrypt [bytes].
  Encrypted encrypt(Uint8List bytes, {IV iv});

  Encrypted encryptString(String input, {IV iv});

  /// Decrypt [encrypted] value.
  Uint8List decrypt(Encrypted encrypted, {IV iv});

  String decrypt2String(Encrypted encrypted, {IV iv});
}

abstract class Asymmetric {
  /// Encrypt [String].
  Encrypted encryptPublic(String input, {IV iv});

  Encrypted encryptPrivate(String input, {IV iv});


  /// Decrypt [encrypted] value.
  String decryptPublic(Encrypted encrypted, {IV iv});

  String decryptPrivate(Encrypted encrypted, {IV iv});
}