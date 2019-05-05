part of flutter_cipher;

/// Wraps Algorithms in a unique Container.
class Cipher {
  static Asymmetric getAsymmetricInstance(Asymmetric asymmetric) {
    return asymmetric;
  }
  static Symmetry getSymmetryInstance(Symmetry symmetry) {
    return symmetry;
  }
}
