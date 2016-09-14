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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.SignatureAlgorithms} class.
 */
public class SignatureAlgorithmsTest {
  /**
   * Test method for
   * {@link ca.trustpoint.m2m.SignatureAlgorithms#getInstance( M2mSignatureAlgorithmOids)}.
   */
  @Test
  public void testGetInstanceM2MSignatureAlgorithmOids() {
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP192R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP224R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECT233K1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECT233R1));
    assertEquals(
        SignatureAlgorithms.RSA_SHA256_RSA,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.RSA_SHA256_RSA));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA384_SECP384R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP192R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP224R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA256_SECT233K1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA256_SECT233R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA384_SECP384R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(M2mSignatureAlgorithmOids.ECQV_SHA512_SECP521R1));
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.SignatureAlgorithms#getInstance( NfcSignatureAlgorithmOids)}.
   */
  @Test
  public void testGetInstanceNFCSignatureAlgorithmOids() {
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP192R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP224R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA256_SECT233K1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA256_SECT233R1));
    assertEquals(
        SignatureAlgorithms.RSA_SHA256_RSA,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.RSA_SHA256_RSA));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA384_SECP384R1));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA256_SECP192R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA256_SECP224R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA256_SECP256R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA256_SECT233K1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA256_SECT233R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA384_SECP384R1));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(NfcSignatureAlgorithmOids.ECQV_SHA512_SECP521R1));
  }

  private byte[] getEncodedOid(String oid) throws IOException {
    return new ASN1ObjectIdentifier(oid).getEncoded();
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.SignatureAlgorithms#getInstance( byte[])}.
   */
  @Test
  public void testGetInstanceByteArray() throws IOException {
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.0")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.1")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.9")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.2")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.3")));
    assertEquals(
        SignatureAlgorithms.RSA_SHA256_RSA,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.8")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.11")));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.13")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.4")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.5")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.10")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.6")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.7")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.12")));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.14")));

    try {
      SignatureAlgorithms.getInstance(getEncodedOid("2.16.840.1.114513.1.99"));
    } catch (IllegalArgumentException e) {
      return;
    }

    fail("Expected IllegalArgumentException.");
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.SignatureAlgorithms#getInstance( String)}.
   */
  @Test
  public void testGetInstanceString() {
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.0"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.1"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.9"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.2"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.3"));
    assertEquals(
        SignatureAlgorithms.RSA_SHA256_RSA,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.8"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.11"));
    assertEquals(
        SignatureAlgorithms.ECDSA_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.13"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP192R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.4"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP224R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.5"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECP256R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.10"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233K1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.6"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA256_SECT233R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.7"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA384_SECP384R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.12"));
    assertEquals(
        SignatureAlgorithms.ECQV_SHA512_SECP521R1,
        SignatureAlgorithms.getInstance("2.16.840.1.114513.1.14"));

    try {
      SignatureAlgorithms.getInstance("2.16.840.1.114513.1.99");
    } catch (IllegalArgumentException e) {
      return;
    }

    fail("Expected IllegalArgumentException.");
  }
}
