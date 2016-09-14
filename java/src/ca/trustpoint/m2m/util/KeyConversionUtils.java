/**
 *  Copyright 2016 TrustPoint Innovation Technologies, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package ca.trustpoint.m2m.util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Converts Public and Private keys to and from supported encodings
 *
 * A PublicKey object when created with keyPairGenerator.getInstance, using "ECDSA" and BouncyCastle
 * as the provider and exported using key.getEncoded() has the following format:
 *
 * SEQUENCE(2 elem) SEQUENCE(2 elem) OBJECT IDENTIFIER1.2.840.10045.2.1 OBJECT
 * IDENTIFIER1.2.840.10045.3.1.1 BIT STRING(392 bit)
 *
 * The 392-bit BIT STRING element in the outer sequence is the Public Key (encoded as specified in
 * X9.62)
 *
 * A similarly exported PrivateKey object is encoded in a format similar to PKCS8.
 *
 * Different versions of Bouncy Castle may provide slightly different encodings; if so, this code
 * will have to be modified to detect these changes for proper parsing.
 *
 * The first OID in the sequence above if for EC public key. So it should be acceptable for ECQV.
 * This conversion routine would need to be expanded to include RSA, when we support it. (TODO)
 * Additionally, right now we are assuming secp192r1, secp224r1 and secp256r1. This may need to be
 * expanded as well. (TODO)
 *
 * The Algorithm params (X962Parameters) for the public and private key are currently chosen based
 * on the public key length or private key length. We may want to choose based on the OID from the
 * cert if passed in. (TODO)
 */
public class KeyConversionUtils {
  /** Private constructor to prevent instantiation. */
  private KeyConversionUtils() {}

  public static boolean isCompressedEcPoint(byte[] rawPoint) throws InvalidKeyException {
    boolean isCompressed = false;

    switch (rawPoint[0]) {
      case 02: // Compressed
      case 03:
        isCompressed = true;
        break;
      case 04: // Uncompressed
        break;
      default:
        throw new InvalidKeyException("unrecognized public EC point type: (" + rawPoint[0] + ")");
    }

    return isCompressed;
  }

  /**
   * Constructs a PublicKey object from raw EC public key data.
   *
   * @param rawKey Raw EC public key data.
   * @return A PublicKey object constructed from the raw EC public key data.
   *
   * @throws InvalidKeyException if key type or length is unrecognized.
   * @throws IOException if raw data reading error.
   */
  public static PublicKey convertRawBytestoEcPublicKey(byte[] rawKey)
      throws IllegalArgumentException, InvalidKeyException, IOException {
    if (rawKey == null) {
      throw new IllegalArgumentException("rawKey cannot be null.");
    }

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    boolean isCompressed = isCompressedEcPoint(rawKey);

    X962Parameters params = null;
    int keyCompressedLength = 0;

    // Obtain the length of the compressed public key
    if (isCompressed) {
      keyCompressedLength = rawKey.length;
    } else {
      keyCompressedLength = (rawKey.length - 1) / 2 + 1;
    }

    switch (keyCompressedLength) {
      case 25: // compressed 192 curve
        params = new X962Parameters(X9ObjectIdentifiers.prime192v1);
        break;
      case 29: // compressed 224 curve
        params = new X962Parameters(SECObjectIdentifiers.secp224r1);
        break;
      case 31: // compressed 233 curve
        params = new X962Parameters(SECObjectIdentifiers.sect233r1);
        break;
      case 33: // compressed 256 curve
        params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
        break;
      case 49: // compressed 384 curve
        params = new X962Parameters(SECObjectIdentifiers.secp384r1);
        break;
      case 67: // compressed 521 curve
        params = new X962Parameters(SECObjectIdentifiers.secp521r1);
        break;
      default:
        throw new InvalidKeyException(
            "unrecognized public key length: (" + keyCompressedLength + ")");
    }

    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId, rawKey);

    BCECPublicKey key = (BCECPublicKey) BouncyCastleProvider.getPublicKey(info);
    if (isCompressed) {
      key.setPointFormat("COMPRESSED");
    }

    return key;
  }

  /**
   * Converts EC {@link java.security.PublicKey PublicKey} objects to the corresponding raw byte
   * encoding.
   *
   * @param key EC {@link java.security.PublicKey PublicKey} to convert.
   * @param withCompression True if the output should be the compressed representation of the point.
   * @return The raw byte encoding of the given point.
   * @throws IllegalArgumentException if key is null or not a
   *         {@link org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey BCECPublicKey}
   *         object.
   */
  public static byte[] convertEcPublicKeyToRawBytes(PublicKey key, boolean withCompression)
      throws IllegalArgumentException {
    if (key == null) {
      throw new IllegalArgumentException("key cannot be null.");
    } else if (!(key instanceof BCECPublicKey)) {
      throw new IllegalArgumentException("Unsupported key format.");
    }

    BCECPublicKey ecKey = (BCECPublicKey) key;

    return ecKey.getQ().getEncoded(withCompression);
  }
}
