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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.AuthorityKeyIdentifier} class.
 */
public class AuthorityKeyIdentifierTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#AuthorityKeyIdentifier()}.
   */
  @Test
  public void testAuthorityKeyIdentifier() {
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    assertNull(authKeyId.getKeyIdentifier());
    assertNull(authKeyId.getCertificateIssuer());
    assertNull(authKeyId.getCertificateSerialNumber());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#AuthorityKeyIdentifier(byte[],
   * ca.trustpoint.m2m.GeneralName, java.math.BigInteger)}.
   */
  @Test
  public void testAuthorityKeyIdentifierByteArrayGeneralNameBigInteger() {
    byte[] keyId = Hex.decode("3f2a7529ba22");
    GeneralName certIssuer = new GeneralName();
    BigInteger certSerialNumber = new BigInteger("2836741231236324239234726261890882");

    testConstructor(keyId, null, null);
    testConstructor(null, certIssuer, null);
    testConstructor(null, null, certSerialNumber);
    testConstructor(keyId, certIssuer, null);
    testConstructor(keyId, null, certSerialNumber);
    testConstructor(null, certIssuer, certSerialNumber);
    testConstructor(keyId, certIssuer, certSerialNumber);
  }

  private void testConstructor(byte[] keyId, GeneralName certIssuer, BigInteger certSerialNumber) {
    AuthorityKeyIdentifier authKeyId =
        new AuthorityKeyIdentifier(keyId, certIssuer, certSerialNumber);
    assertArrayEquals(keyId, authKeyId.getKeyIdentifier());
    assertEquals(certIssuer, authKeyId.getCertificateIssuer());
    assertEquals(certSerialNumber, authKeyId.getCertificateSerialNumber());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#setKeyIdentifier(byte[])}.
   */
  @Test
  public void testSetKeyIdentifier() {
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    assertNull(authKeyId.getKeyIdentifier());

    byte[] expectedValue = Hex.decode("02ac6e4a2285");
    authKeyId.setKeyIdentifier(expectedValue);
    assertArrayEquals(expectedValue, authKeyId.getKeyIdentifier());

    expectedValue = Hex.decode("99fe72ad72");
    authKeyId.setKeyIdentifier(expectedValue);
    assertArrayEquals(expectedValue, authKeyId.getKeyIdentifier());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#setCertificateIssuer(
   * ca.trustpoint.m2m.GeneralName)}.
   */
  @Test
  public void testSetCertificateIssuer() {
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    assertNull(authKeyId.getCertificateIssuer());

    GeneralName expectedValue = new GeneralName(); // TODO: Put real values here.
    authKeyId.setCertificateIssuer(expectedValue);
    assertEquals(expectedValue, authKeyId.getCertificateIssuer());

    expectedValue = new GeneralName(); // TODO: Put real values here.
    authKeyId.setCertificateIssuer(expectedValue);
    assertEquals(expectedValue, authKeyId.getCertificateIssuer());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#setCertificateSerialNumber(
   * java.math.BigInteger)}.
   */
  @Test
  public void testSetCertificateSerialNumber() {
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    assertNull(authKeyId.getCertificateSerialNumber());

    BigInteger expectedValue = new BigInteger("112326126934934737002347");
    authKeyId.setCertificateSerialNumber(expectedValue);
    assertEquals(expectedValue, authKeyId.getCertificateSerialNumber());

    expectedValue = new BigInteger("987349020273487090671346358");
    authKeyId.setCertificateSerialNumber(expectedValue);
    assertEquals(expectedValue, authKeyId.getCertificateSerialNumber());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#isValid()}.
   */
  @Test
  public void testIsValid() {
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    assertFalse(authKeyId.isValid());

    authKeyId.setKeyIdentifier(new byte[0]);
    assertFalse(authKeyId.isValid());

    authKeyId.setKeyIdentifier(Hex.decode("2347234aade22aec"));
    assertTrue(authKeyId.isValid());

    authKeyId.setCertificateIssuer(new GeneralName());
    assertFalse(authKeyId.isValid());

    EntityName entityName = new EntityName();
    entityName.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    GeneralName validName = new GeneralName(entityName);

    authKeyId.setCertificateIssuer(validName);
    assertTrue(authKeyId.isValid());

    authKeyId.setCertificateSerialNumber(
        new BigInteger(
            new byte[] {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
            }));
    assertFalse(authKeyId.isValid());

    authKeyId.setCertificateSerialNumber(new BigInteger("1231296712907230496192873916192874"));
    assertTrue(authKeyId.isValid());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.AuthorityKeyIdentifier#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws IOException {
    boolean exceptionThrown = false;
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();

    try {
      authKeyId.getEncoded();
    } catch(IOException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    byte[] expectedEncoding =
        new byte[] {
            0x30, 0x08, (byte) 0x80, 0x06, 0x73, 0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F
        };
    authKeyId.setKeyIdentifier(Hex.decode("7368a3dc6e4f"));
    assertArrayEquals(expectedEncoding, authKeyId.getEncoded());

    expectedEncoding =
        new byte[] {
            0x30, 0x16, (byte) 0x80, 0x06, 0x73, 0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F,
            (byte) 0xA1, 0x0C, (byte) 0x81, 0x0A, 0x74, 0x65, 0x73, 0x74, 0x64, 0x6F, 0x6D, 0x61,
            0x69, 0x6E
        };
    authKeyId.setCertificateIssuer(new GeneralName(GeneralNameAttributeId.DnsName, "testdomain"));
    assertArrayEquals(expectedEncoding, authKeyId.getEncoded());

    EntityName entityName = new EntityName();
    entityName.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    GeneralName validName = new GeneralName(entityName);

    expectedEncoding =
        new byte[] {
            0x30, 0x10, (byte) 0x80, 0x06, 0x73, 0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F,
            (byte) 0xA1, 0x06, (byte) 0xA2, 0x04, (byte) 0x80, 0x02, 0x43, 0x41
        };
    authKeyId.setCertificateIssuer(validName);
    assertArrayEquals(expectedEncoding, authKeyId.getEncoded());

    expectedEncoding =
        new byte[] {
            0x30, 0x20, (byte) 0x80, 0x06, 0x73, 0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F,
            (byte) 0xA1, 0x06, (byte) 0xA2, 0x04, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x82, 0x0E,
            0x3C, (byte) 0xB5, 0x26, 0x41, 0x37, (byte) 0x95, (byte) 0xFC, (byte) 0xD3, (byte) 0xEA,
            (byte) 0xFC, 0x22, (byte) 0x92, (byte) 0xD8, 0x6A
        };
    authKeyId.setCertificateSerialNumber(new BigInteger("1231296712907230496192873916192874"));
    assertArrayEquals(expectedEncoding, authKeyId.getEncoded());
  }
}
