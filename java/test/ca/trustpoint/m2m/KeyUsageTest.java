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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.KeyUsage} class.
 */
public class KeyUsageTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#KeyUsage()}.
   */
  @Test
  public void testKeyUsage() {
    KeyUsage usage = new KeyUsage();

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.KeyUsage#
   *     KeyUsage(boolean, boolean, boolean, boolean, boolean, boolean, boolean)}.
   */
  @Test
  public void testKeyUsageBooleanBooleanBooleanBooleanBooleanBooleanBoolean() {
    KeyUsage usage = new KeyUsage(true, false, false, false, false, false, false);

    assertTrue(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, true, false, false, false, false, false);

    assertFalse(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, false, true, false, false, false, false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, false, false, true, false, false, false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, false, false, false, true, false, false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, false, false, false, false, true, false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(false, false, false, false, false, false, true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage(true, true, true, true, true, true, true);

    assertTrue(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage(false, false, false, false, false, false, false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#KeyUsage(byte)}.
   */
  @Test
  public void testKeyUsageByte() {
    KeyUsage usage = new KeyUsage((byte) 0x80);

    assertTrue(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x40);

    assertFalse(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x20);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x10);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x08);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x04);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x02);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage((byte) 0xFE);

    assertTrue(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage((byte) 0x00);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    try {
      usage = new KeyUsage((byte) 0x01);
    } catch (IllegalArgumentException ex) {
      return;
    }

    fail("Expected IllegalArgumentException.");
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#KeyUsage(byte[])}.
   */
  @Test
  public void testKeyUsageByteArray() {
    KeyUsage usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x80});

    assertTrue(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x40});

    assertFalse(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x20});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x10});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x08});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x04});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x02});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0xFE});

    assertTrue(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x00});

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    try {
      usage = new KeyUsage(new byte[] {(byte) 0x04, (byte) 0x01, (byte) 0x01});
    } catch (IllegalArgumentException ex) {
      return;
    }

    fail("Expected IllegalArgumentException.");
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setDigitalSignature(boolean)}.
   */
  @Test
  public void testSetDigitalSignature() {
    KeyUsage usage = new KeyUsage();

    usage.setDigitalSignature(true);

    assertTrue(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setDigitalSignature(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setNonRepudiation(boolean)}.
   */
  @Test
  public void testSetNonRepudiation() {
    KeyUsage usage = new KeyUsage();

    usage.setNonRepudiation(true);

    assertFalse(usage.getDigitalSignature());
    assertTrue(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setNonRepudiation(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setKeyEncipherment(boolean)}.
   */
  @Test
  public void testSetKeyEncipherment() {
    KeyUsage usage = new KeyUsage();

    usage.setKeyEncipherment(true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertTrue(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setKeyEncipherment(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setDataEncipherment(boolean)}.
   */
  @Test
  public void testSetDataEncipherment() {
    KeyUsage usage = new KeyUsage();

    usage.setDataEncipherment(true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertTrue(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setDataEncipherment(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setKeyAgreement(boolean)}.
   */
  @Test
  public void testSetKeyAgreement() {
    KeyUsage usage = new KeyUsage();

    usage.setKeyAgreement(true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertTrue(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setKeyAgreement(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setKeyCertSign(boolean)}.
   */
  @Test
  public void testSetKeyCertSign() {
    KeyUsage usage = new KeyUsage();

    usage.setKeyCertSign(true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertTrue(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());

    usage.setKeyCertSign(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#setCrlSign(boolean)}.
   */
  @Test
  public void testSetCrlSign() {
    KeyUsage usage = new KeyUsage();

    usage.setCrlSign(true);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertTrue(usage.getCrlSign());

    usage.setCrlSign(false);

    assertFalse(usage.getDigitalSignature());
    assertFalse(usage.getNonRepudiation());
    assertFalse(usage.getKeyEncipherment());
    assertFalse(usage.getDataEncipherment());
    assertFalse(usage.getKeyAgreement());
    assertFalse(usage.getKeyCertSign());
    assertFalse(usage.getCrlSign());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.KeyUsage#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws IOException {
    KeyUsage usage = new KeyUsage(true, false, false, false, false, false, false);
    byte[] encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x80});

    usage = new KeyUsage(false, true, false, false, false, false, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x40});

    usage = new KeyUsage(false, false, true, false, false, false, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x20});

    usage = new KeyUsage(false, false, false, true, false, false, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x10});

    usage = new KeyUsage(false, false, false, false, true, false, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x08});

    usage = new KeyUsage(false, false, false, false, false, true, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x04});

    usage = new KeyUsage(false, false, false, false, false, false, true);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x02});

    usage = new KeyUsage(true, true, true, true, true, true, true);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0xFE});

    usage = new KeyUsage(false, false, false, false, false, false, false);
    encoded = usage.getEncoded();
    assertArrayEquals(encoded, new byte[] {0x04, 0x01, (byte) 0x00});
  }
}
