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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import ca.trustpoint.m2m.EntityName;
import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;
import ca.trustpoint.m2m.GeneralName;
import ca.trustpoint.m2m.GeneralNameAttributeId;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.GeneralName} class.
 */
public class GeneralNameTest {
  /**
   * Test method for
   * {@link ca.trustpoint.m2m.GeneralName#GeneralName( GeneralNameAttributeId,byte[])}.
   */
  @Test
  public void testGeneralNameGeneralNameAttributeIdByteArray() throws IllegalArgumentException {
    GeneralName generalName;
    String value = "196.168.0.1";

    generalName = new GeneralName(GeneralNameAttributeId.Rfc822Name, value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName = new GeneralName(GeneralNameAttributeId.DnsName, value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    try {
      new GeneralName(GeneralNameAttributeId.DirectoryName, value);
    } catch (IllegalArgumentException e) {
      System.out.println("Expected exception: " + e);
    }

    generalName = new GeneralName(GeneralNameAttributeId.Uri, value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName = new GeneralName(GeneralNameAttributeId.IpAddress, value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName = new GeneralName(GeneralNameAttributeId.RegisteredId, value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.GeneralName#GeneralName(EntityName)}.
   */
  @Test
  public void testGeneralNameGeneralEntityName() {
    EntityName entity = new EntityName();
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));

    GeneralName generalName = new GeneralName(entity);
    assertEquals(GeneralNameAttributeId.DirectoryName, generalName.getAttributeId());
    assertNotNull(generalName.getEntity());
    assertNull(generalName.getValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.GeneralName#setValue(String)}.
   */
  @Test
  public void testSetValueString() throws IllegalArgumentException {
    GeneralName generalName = new GeneralName();
    String value = "192.168.0.1";

    generalName.setAttributeId(GeneralNameAttributeId.Rfc822Name);
    generalName.setValue(value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName.setAttributeId(GeneralNameAttributeId.DnsName);
    generalName.setValue(value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName.setAttributeId(GeneralNameAttributeId.DirectoryName);
    try {
      generalName.setValue(value);
    } catch (IllegalArgumentException e) {
      System.out.println("Expected exception: " + e);
    }

    generalName.setAttributeId(GeneralNameAttributeId.Uri);
    generalName.setValue(value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName.setAttributeId(GeneralNameAttributeId.IpAddress);
    generalName.setValue(value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());

    generalName.setAttributeId(GeneralNameAttributeId.RegisteredId);
    generalName.setValue(value);
    assertNotNull(generalName.getValue());
    assertNull(generalName.getEntity());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.GeneralName#setEntity(EntityName)}.
   */
  @Test
  public void testSetEntityEntityName() {
    GeneralName generalName = new GeneralName();
    EntityName entity = new EntityName();
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));

    generalName.setEntity(entity);
    assertEquals(GeneralNameAttributeId.DirectoryName, generalName.getAttributeId());
    assertNotNull(generalName.getEntity());
    assertNull(generalName.getValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.GeneralName#isValid()}.
   */
  @Test
  public void testIsValid() throws IllegalArgumentException {
    GeneralName generalName;

    // Rfc822Name
    // Default constructor
    generalName = new GeneralName();
    assertFalse(generalName.isValid());
    // Set attribute ID
    generalName.setAttributeId(GeneralNameAttributeId.Rfc822Name);
    assertFalse(generalName.isValid());
    // Set attribute value
    generalName.setValue("myemail@gmail.com");
    assertTrue(generalName.isValid());

    // DnsName
    generalName = new GeneralName(GeneralNameAttributeId.DnsName, "trustpoint.ca");
    assertTrue(generalName.isValid());

    // DirectoryName
    EntityName entity = new EntityName();
    generalName = new GeneralName(entity);
    assertFalse(generalName.isValid());
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    generalName.setEntity(entity);
    assertTrue(generalName.isValid());
    entity.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Produce Co."));
    generalName.setEntity(entity);
    assertTrue(generalName.isValid());
    entity.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Production"));
    generalName.setEntity(entity);
    assertTrue(generalName.isValid());
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Locality, "Chicago"));
    generalName.setEntity(entity);
    assertTrue(generalName.isValid());

    // Uri
    // Valid URI
    generalName = new GeneralName(GeneralNameAttributeId.Uri, "trustpoint.ca");
    assertTrue(generalName.isValid());
    // Invalid URI
    generalName.setValue("https://");
    assertFalse(generalName.isValid());

    // IpAddress
    // IPv4
    generalName = new GeneralName(GeneralNameAttributeId.IpAddress, "192.168.1.1");
    assertTrue(generalName.isValid());
    // IPv6
    generalName.setValue("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assertTrue(generalName.isValid());
    // Invalid IP
    generalName.setValue("2001:0db8:85a3:0000");
    assertFalse(generalName.isValid());

    // RegisteredId
    generalName = new GeneralName(GeneralNameAttributeId.RegisteredId, "1.3.33.1235.28967");
    assertTrue(generalName.isValid());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.GeneralName#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws IllegalArgumentException, IOException {
    GeneralName generalName = new GeneralName();
    byte[] expectedBytes;

    // Rfc822Name
    generalName.setAttributeId(GeneralNameAttributeId.Rfc822Name);
    generalName.setValue("myemail@gmail.com");
    expectedBytes = new byte[] {(byte) 0x80, (byte) 0x11, (byte) 0x6D, (byte) 0x79, (byte) 0x65,
        (byte) 0x6D, (byte) 0x61, (byte) 0x69, (byte) 0x6C, (byte) 0x40, (byte) 0x67, (byte) 0x6D,
        (byte) 0x61, (byte) 0x69, (byte) 0x6C, (byte) 0x2E, (byte) 0x63, (byte) 0x6F, (byte) 0x6D};
    assertArrayEquals(expectedBytes, generalName.getEncoded());

    // DnsName
    generalName.setAttributeId(GeneralNameAttributeId.DnsName);
    generalName.setValue("trustpoint.ca");
    expectedBytes = new byte[] {(byte) 0x81, (byte) 0x0D, (byte) 0x74, (byte) 0x72, (byte) 0x75,
        (byte) 0x73, (byte) 0x74, (byte) 0x70, (byte) 0x6F, (byte) 0x69, (byte) 0x6E, (byte) 0x74,
        (byte) 0x2E, (byte) 0x63, (byte) 0x61};
    assertArrayEquals(expectedBytes, generalName.getEncoded());

    // DirectoryName
    EntityName entity = new EntityName();
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    entity.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Produce Co."));
    entity.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Production"));
    entity.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Locality, "Chicago"));
    generalName.setEntity(entity);
    expectedBytes =
        new byte[] {
            (byte) 0xA2, (byte) 0x2B, (byte) 0x80, (byte) 0x02, (byte) 0x43, (byte) 0x41,
            (byte) 0x81, (byte) 0x10, (byte) 0x41, (byte) 0x63, (byte) 0x6D, (byte) 0x65,
            (byte) 0x20, (byte) 0x50, (byte) 0x72, (byte) 0x6F, (byte) 0x64, (byte) 0x75,
            (byte) 0x63, (byte) 0x65, (byte) 0x20, (byte) 0x43, (byte) 0x6F, (byte) 0x2E,
            (byte) 0x82, (byte) 0x0A, (byte) 0x50, (byte) 0x72, (byte) 0x6F, (byte) 0x64,
            (byte) 0x75, (byte) 0x63, (byte) 0x74, (byte) 0x69, (byte) 0x6F, (byte) 0x6E,
            (byte) 0x85, (byte) 0x07, (byte) 0x43, (byte) 0x68, (byte) 0x69, (byte) 0x63,
            (byte) 0x61, (byte) 0x67, (byte) 0x6F
        };
    assertArrayEquals(expectedBytes, generalName.getEncoded());

    // Uri
    generalName.setAttributeId(GeneralNameAttributeId.Uri);
    generalName.setValue("https://blackseal.trustpoint.ca");
    expectedBytes = new byte[] {(byte) 0x83, (byte) 0x1F, (byte) 0x68, (byte) 0x74, (byte) 0x74,
        (byte) 0x70, (byte) 0x73, (byte) 0x3A, (byte) 0x2F, (byte) 0x2F, (byte) 0x62, (byte) 0x6C,
        (byte) 0x61, (byte) 0x63, (byte) 0x6B, (byte) 0x73, (byte) 0x65, (byte) 0x61, (byte) 0x6C,
        (byte) 0x2E, (byte) 0x74, (byte) 0x72, (byte) 0x75, (byte) 0x73, (byte) 0x74, (byte) 0x70,
        (byte) 0x6F, (byte) 0x69, (byte) 0x6E, (byte) 0x74, (byte) 0x2E, (byte) 0x63, (byte) 0x61};
    assertArrayEquals(expectedBytes, generalName.getEncoded());

    // IpAddress
    generalName.setAttributeId(GeneralNameAttributeId.IpAddress);
    generalName.setValue("192.168.0.1");
    expectedBytes =
        new byte[] {(byte) 0x84, (byte) 0x04, (byte) 0xC0, (byte) 0xA8, (byte) 0x00, (byte) 0x01};
    assertArrayEquals(expectedBytes, generalName.getEncoded());

    // RegisteredId
    generalName.setAttributeId(GeneralNameAttributeId.RegisteredId);
    generalName.setValue("1.3.33.1235.28967");
    expectedBytes = new byte[] {(byte) 0x85, (byte) 0x07, (byte) 0x2B, (byte) 0x21, (byte) 0x89,
        (byte) 0x53, (byte) 0x81, (byte) 0xE2, (byte) 0x27};
    assertArrayEquals(expectedBytes, generalName.getEncoded());
  }
}
