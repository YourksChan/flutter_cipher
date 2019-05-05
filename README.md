# flutter_cipher

一个Flutter加密类库
A Flutter encryption class library

## Getting Started

兼容iOS和Android
Compatible with iOS and Android

RSA:
    密钥格式: PKCS#1
    Key format: PKCS#1

案例:
example:

    Asymmetric rsa = Cipher.getAsymmetricInstance(RSA(publicKey: publicKey, privateKey: privateKey));

    //encryption
    var encryptPublic = rsa.encryptPublic(content);
    var encryptPrivate = rsa.encryptPrivate(content);

    //decrypt
    var decryptPublic = rsa.decryptPublic(encryptPrivate);
    var decryptPrivate = rsa.decryptPrivate(encryptPublic);




AES:

案例:
example:

    Key key = Key.fromUtf8('32 length key................');
    IV iv = IV.fromLength(16);

    Symmetry aes = Cipher.getSymmetryInstance(AES(key, iv)));

    var encrypted = aes.encrypt(bytes);
    var encrypted = aes.encryptString(str);

    var content = aes.decrypt(encrypted);
    var content = aes.decrypt2String(encrypted);




Finally, we would like to thank leocavalcante, as the main content of this library is derived from the encrypt library.