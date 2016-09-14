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

package ca.trustpoint.m2m;

/**
 * Enumerates the signature algorithm names for the supported signature algorithms.
 */
public enum BouncyCastleSignatureAlgorithms {
  /**
   * BouncyCastle algorithm name for ECDSA SHA256.
   */
  ECDSA_SHA256("SHA256withECDSA"),
  /**
   * BouncyCastle algorithm name for ECQV SHA256.
   */
  ECQV_SHA256("SHA256withIMPLICIT"),
  /**
   * BouncyCastle algorithm name for RSA SHA256.
   */
  RSA_SHA256("SHA256withRSA"),
  /**
   * BouncyCastle algorithm name for ECDSA SHA384.
   */
  ECDSA_SHA384("SHA384withECDSA"),
  /**
   * BouncyCastle algorithm name for ECQV SHA384.
   */
  ECQV_SHA384("SHA384withIMPLICIT"),
  /**
   * BouncyCastle algorithm name for ECDSA SHA512.
   */
  ECDSA_SHA512("SHA512withECDSA"),
  /**
   * BouncyCastle algorithm name for ECQV SHA512.
   */
  ECQV_SHA512("SHA512withIMPLICIT");

  private final String bouncyCastleName;

  /**
   * Constructor.
   */
  BouncyCastleSignatureAlgorithms(String bouncyCastleName) {
    this.bouncyCastleName = bouncyCastleName;
  }

  /**
   * Returns BouncyCastle name.
   *
   * @return BouncyCastle name.
   */
  public String getBouncyCastleName() {
    return bouncyCastleName;
  }

  /**
   * Returns the enumeration value that corresponds to the given bouncyCastleName.
   *
   * @param bouncyCastleName A BouncyCastle algorithm name.
   *
   * @return An instance of object in the enum associated with the given bouncyCastleName.
   * @throws IllegalArgumentException if bouncyCastleName is invalid.
   */
  public static BouncyCastleSignatureAlgorithms getInstance(String bouncyCastleName)
      throws IllegalArgumentException {
    if (bouncyCastleName.equals(ECDSA_SHA256.bouncyCastleName)) {
      return ECDSA_SHA256;
    }

    if (bouncyCastleName.equals(ECQV_SHA256.bouncyCastleName)) {
      return ECQV_SHA256;
    }

    if (bouncyCastleName.equals(RSA_SHA256.bouncyCastleName)) {
      return RSA_SHA256;
    }

    if (bouncyCastleName.equals(ECDSA_SHA384.bouncyCastleName)) {
      return ECDSA_SHA384;
    }

    if (bouncyCastleName.equals(ECQV_SHA384.bouncyCastleName)) {
      return ECQV_SHA384;
    }

    if (bouncyCastleName.equals(ECDSA_SHA512.bouncyCastleName)) {
      return ECDSA_SHA512;
    }

    if (bouncyCastleName.equals(ECQV_SHA512.bouncyCastleName)) {
      return ECQV_SHA512;
    }

    throw new IllegalArgumentException("unknow BouncyCastle name: " + bouncyCastleName);
  }
}
