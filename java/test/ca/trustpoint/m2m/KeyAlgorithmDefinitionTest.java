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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.KeyAlgorithmDefinition} class.
 */
public class KeyAlgorithmDefinitionTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#KeyAlgorithmDefinition()}.
   */
  @Test
  public void testKeyAlgorithmDefinition() {
    KeyAlgorithmDefinition keyDef = new KeyAlgorithmDefinition();
    assertNull(keyDef.getAlgorithm());
    assertNull(keyDef.getParameters());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#
   *     KeyAlgorithmDefinition(ca.trustpoint.m2m.SignatureAlgorithmOids, byte[])}.
   */
  @Test
  public void testKeyAlgorithmDefinitionSignatureAlgorithmOidsByteArray() {
    byte[] expectedParameters = new byte[] {0x03, 0x04, 0x7F, 0x55};
    KeyAlgorithmDefinition keyDef =
        new KeyAlgorithmDefinition(
            M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1, expectedParameters);
    assertEquals(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1, keyDef.getAlgorithm());
    assertArrayEquals(expectedParameters, keyDef.getParameters());

    expectedParameters = new byte[] {0x20, 0x6D, 0x22, 0x00};
    keyDef =
        new KeyAlgorithmDefinition(
            NfcSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1, expectedParameters);
    assertEquals(NfcSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1, keyDef.getAlgorithm());
    assertArrayEquals(expectedParameters, keyDef.getParameters());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#
   *     setAlgorithm(ca.trustpoint.m2m.SignatureAlgorithmOids)}.
   */
  @Test
  public void testSetAlgorithm() {
    KeyAlgorithmDefinition keyDef = new KeyAlgorithmDefinition();
    assertNull(keyDef.getAlgorithm());

    keyDef.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA384_SECP384R1);
    assertEquals(M2mSignatureAlgorithmOids.ECQV_SHA384_SECP384R1, keyDef.getAlgorithm());

    keyDef.setAlgorithm(NfcSignatureAlgorithmOids.RSA_SHA256_RSA);
    assertEquals(NfcSignatureAlgorithmOids.RSA_SHA256_RSA, keyDef.getAlgorithm());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#setParameters(byte[])}.
   */
  @Test
  public void testSetParameters() {
    KeyAlgorithmDefinition keyDef = new KeyAlgorithmDefinition();
    assertNull(keyDef.getParameters());

    byte[] expectedParameters = new byte[] {0x78, 0x4D, 0x11, 0x07};
    keyDef.setParameters(expectedParameters);
    assertArrayEquals(expectedParameters, keyDef.getParameters());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#getEncodedAlgorithm()}.
   */
  @Test
  public void testGetEncodedAlgorithm() throws IOException {
    KeyAlgorithmDefinition keyDef = new KeyAlgorithmDefinition();
    boolean exceptionThrown = false;

    try {
      keyDef.getEncodedAlgorithm();
    } catch (IOException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    byte[] expectedEncoding = new byte[] {0x06, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x0A};
    keyDef.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);
    assertArrayEquals(expectedEncoding, keyDef.getEncodedAlgorithm());

    expectedEncoding =
        new byte[] {
            0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE, 0x51, 0x01, 0x0A
        };
    keyDef.setAlgorithm(NfcSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);
    assertArrayEquals(expectedEncoding, keyDef.getEncodedAlgorithm());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyAlgorithmDefinition#getEncodedParameters()}.
   */
  @Test
  public void testGetEncodedParameters() throws IOException {
    KeyAlgorithmDefinition keyDef = new KeyAlgorithmDefinition();
    boolean exceptionThrown = false;

    try {
      keyDef.getEncodedParameters();
    } catch (IOException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    byte[] expectedEncoding = new byte[] {0x04, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    keyDef.setParameters(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05});
    assertArrayEquals(expectedEncoding, keyDef.getEncodedParameters());

    expectedEncoding = new byte[] {0x04, 0x08, 0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x00, 0x00, 0x00};
    keyDef.setParameters(new byte[] {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x00, 0x00, 0x00});
    assertArrayEquals(expectedEncoding, keyDef.getEncodedParameters());
  }
}
