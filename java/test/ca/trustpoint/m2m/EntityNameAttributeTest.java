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

import org.junit.Test;

import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.EntityNameAttribute} class.
 */
public class EntityNameAttributeTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityNameAttribute#EntityNameAttribute()}.
   */
  @Test
  public void testEntityNameAttribute() {
    EntityNameAttribute attribute = new EntityNameAttribute();

    assertEquals(EntityNameAttributeId.Undefined, attribute.getId());
    assertNull(attribute.getValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.EntityNameAttribute#EntityNameAttribute(
   *            ca.trustpoint.m2m.EntityNameAttributeId, java.lang.String)}.
   */
  @Test
  public void testEntityNameAttributeEntityNameAttributeIdString() {
    testConstructor(EntityNameAttributeId.Country, "CA");
    testConstructor(EntityNameAttributeId.Organization, "TrustPoint Innovation");
    testConstructor(EntityNameAttributeId.OrganizationalUnit, "Testing");
    testConstructor(EntityNameAttributeId.DistinguishedNameQualifier, "Foo");
    testConstructor(EntityNameAttributeId.StateOrProvince, "Ontario");
    testConstructor(EntityNameAttributeId.Locality, "Waterloo");
    testConstructor(EntityNameAttributeId.CommonName, "M2M Library");
    testConstructor(EntityNameAttributeId.SerialNumber, "sdf7sdfhhaef756756");
    testConstructor(EntityNameAttributeId.DomainComponent, "trustpoint");
    testConstructor(EntityNameAttributeId.RegisteredId, "1.3.33.1235.28967");
    testConstructor(EntityNameAttributeId.OctetsName, "37fe2a67d0");
  }

  private void testConstructor(EntityNameAttributeId id, String value) {
    EntityNameAttribute attribute = new EntityNameAttribute(id, value);
    assertEquals(id, attribute.getId());
    assertEquals(value, attribute.getValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.EntityNameAttribute#setId(ca.trustpoint.m2m.EntityNameAttributeId)}.
   */
  @Test
  public void testSetId() {
    testSetIdMethod(EntityNameAttributeId.Country);
    testSetIdMethod(EntityNameAttributeId.Organization);
    testSetIdMethod(EntityNameAttributeId.OrganizationalUnit);
    testSetIdMethod(EntityNameAttributeId.DistinguishedNameQualifier);
    testSetIdMethod(EntityNameAttributeId.StateOrProvince);
    testSetIdMethod(EntityNameAttributeId.Locality);
    testSetIdMethod(EntityNameAttributeId.CommonName);
    testSetIdMethod(EntityNameAttributeId.SerialNumber);
    testSetIdMethod(EntityNameAttributeId.DomainComponent);
    testSetIdMethod(EntityNameAttributeId.RegisteredId);
    testSetIdMethod(EntityNameAttributeId.OctetsName);
  }

  private void testSetIdMethod(EntityNameAttributeId id) {
    EntityNameAttribute attribute = new EntityNameAttribute();
    assertEquals(EntityNameAttributeId.Undefined, attribute.getId());

    attribute.setId(id);
    assertEquals(id, attribute.getId());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityNameAttribute#setValue(java.lang.String)}.
   */
  @Test
  public void testSetValue() {
    EntityNameAttribute attribute = new EntityNameAttribute();
    assertNull(attribute.getValue());

    attribute.setValue("This is a value.");
    assertEquals("This is a value.", attribute.getValue());

    attribute.setValue(null);
    assertNull(attribute.getValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityNameAttribute#getEncoded()}.
   * @throws IOException
   */
  @Test
  public void testGetEncoded() throws IOException {
    byte[] expectedEncoding;

    expectedEncoding = new byte[] {(byte) 0x80, 0x02, 0x43, 0x41};
    testGetEncodedMethod(EntityNameAttributeId.Country, "CA", expectedEncoding);

    expectedEncoding =
        new byte[] {
            (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20,
            0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E};
    testGetEncodedMethod(
        EntityNameAttributeId.Organization, "TrustPoint Innovation", expectedEncoding);

    expectedEncoding = new byte[] {(byte) 0x82, 0x07, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67};
    testGetEncodedMethod(EntityNameAttributeId.OrganizationalUnit, "Testing", expectedEncoding);

    expectedEncoding = new byte[] {(byte) 0x83, 0x03, 0x46, 0x6F, 0x6F};
    testGetEncodedMethod(EntityNameAttributeId.DistinguishedNameQualifier, "Foo", expectedEncoding);

    expectedEncoding = new byte[] {(byte) 0x84, 0x02, 0x4F, 0x4E};
    testGetEncodedMethod(EntityNameAttributeId.StateOrProvince, "ON", expectedEncoding);

    expectedEncoding =
        new byte[] {(byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F};
    testGetEncodedMethod(EntityNameAttributeId.Locality, "Waterloo", expectedEncoding);

    expectedEncoding =
        new byte[] {
            (byte) 0x86, 0x0B, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79};
    testGetEncodedMethod(EntityNameAttributeId.CommonName, "M2M Library", expectedEncoding);

    expectedEncoding =
        new byte[] {
            (byte) 0x87, 0x12, 0x73, 0x64, 0x66, 0x37, 0x73, 0x64, 0x66, 0x68, 0x68, 0x61, 0x65,
            0x66, 0x37, 0x35, 0x36, 0x37, 0x35, 0x36};
    testGetEncodedMethod(
        EntityNameAttributeId.SerialNumber, "sdf7sdfhhaef756756", expectedEncoding);

    expectedEncoding =
        new byte[] {(byte) 0x88, 0x0A, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74};
    testGetEncodedMethod(EntityNameAttributeId.DomainComponent, "trustpoint", expectedEncoding);

    expectedEncoding =
        new byte[] {
            (byte) 0x89, 0x07, 0x2B, 0x21, (byte) 0x89, 0x53, (byte) 0x81, (byte) 0xE2, 0x27};
    testGetEncodedMethod(EntityNameAttributeId.RegisteredId, "1.3.33.1235.28967", expectedEncoding);

    expectedEncoding =
        new byte[] {
            (byte) 0x8A, 0x05, 0x37, (byte) 0xFE, 0x2A, 0x67, (byte) 0xD0};
    testGetEncodedMethod(EntityNameAttributeId.OctetsName, "37fe2a67d0", expectedEncoding);
  }

  private void testGetEncodedMethod(EntityNameAttributeId id, String value, byte[] expectedEncoding)
      throws IOException {
    EntityNameAttribute attribute = new EntityNameAttribute(id, value);
    assertArrayEquals(expectedEncoding, attribute.getEncoded());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityNameAttribute#isValid()}.
   */
  @Test
  public void testIsValid() {
    EntityNameAttribute attribute = new EntityNameAttribute();
    assertFalse(attribute.isValid());

    // Country

    attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "US");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "A");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "ABC");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "!%");
    assertFalse(attribute.isValid());

    // Organization

    attribute = new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Company");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Organization, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.Organization, "This company name is too long for this field.");
    assertFalse(attribute.isValid());

    // Organizational Unit

    attribute = new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Engineering");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.OrganizationalUnit, "This org unit is too long for this field.");
    assertFalse(attribute.isValid());

    // Distinguished Name Qualifier

    attribute =
        new EntityNameAttribute(EntityNameAttributeId.DistinguishedNameQualifier, "Qualifier");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.DistinguishedNameQualifier, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.DistinguishedNameQualifier,
            "This qualifier is too long for this field.");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.DistinguishedNameQualifier, "%^&#!$");
    assertFalse(attribute.isValid());

    // State or Province

    attribute = new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "AB");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "Alberta");
    assertFalse(attribute.isValid());

    // Locality

    attribute = new EntityNameAttribute(EntityNameAttributeId.Locality, "New York City");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.Locality, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.Locality, "This locality is too long for this field.");
    assertFalse(attribute.isValid());

    // Common Name

    attribute = new EntityNameAttribute(EntityNameAttributeId.CommonName, "A M2M Certificate");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.CommonName, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.CommonName, "This common name is too long for this field.");
    assertFalse(attribute.isValid());

    // Serial Number

    attribute = new EntityNameAttribute(EntityNameAttributeId.SerialNumber, "0123456789ABCDEF");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.SerialNumber, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.SerialNumber, "ThisSerialNumberIsTooLongForThisField");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.SerialNumber, "!$&#*^)");
    assertFalse(attribute.isValid());

    // Domain Component

    attribute = new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "somedomain");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.DomainComponent, "ThisDomainComponentIsTooLongForThisField");
    assertFalse(attribute.isValid());

    attribute =
        new EntityNameAttribute(
            EntityNameAttributeId.DomainComponent, new String(new char[] {0x80, 0xFF}));
    assertFalse(attribute.isValid());

    // Registered ID

    attribute = new EntityNameAttribute(EntityNameAttributeId.RegisteredId, "1.4.2.345.11");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.RegisteredId, "");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.RegisteredId, "a.23.g.22");
    assertFalse(attribute.isValid());

    // Octets Name

    attribute = new EntityNameAttribute(EntityNameAttributeId.OctetsName, "FE4522");
    assertTrue(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.OctetsName, "");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.OctetsName, "112233445566778899");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.OctetsName, "vu33s4z9");
    assertFalse(attribute.isValid());

    attribute = new EntityNameAttribute(EntityNameAttributeId.OctetsName, "1");
    assertFalse(attribute.isValid());
  }
}
