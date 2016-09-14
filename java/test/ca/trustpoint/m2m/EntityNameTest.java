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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import ca.trustpoint.m2m.EntityName;
import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.EntityName} class.
 */
public class EntityNameTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityName#EntityName()}.
   */
  @Test
  public void testEntityName() {
    EntityName name = new EntityName();
    assertEquals(0, name.getAttributes().size());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.EntityName#addAttribute(ca.trustpoint.m2m.EntityNameAttribute)}.
   */
  @Test
  public void testAddAttribute() {
    EntityName name = new EntityName();

    EntityNameAttribute attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "CA");
    name.addAttribute(attribute);

    List<EntityNameAttribute> attributes = name.getAttributes();
    assertEquals(1, attributes.size());
    assertEquals(attribute, attributes.get(0));

    EntityNameAttribute attribute2 =
        new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Produce Co.");
    name.addAttribute(attribute2);

    attributes = name.getAttributes();
    assertEquals(2, attributes.size());
    assertEquals(attribute, attributes.get(0));
    assertEquals(attribute2, attributes.get(1));

    EntityNameAttribute attribute3 =
        new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Production");
    name.addAttribute(attribute3);

    attributes = name.getAttributes();
    assertEquals(3, attributes.size());
    assertEquals(attribute, attributes.get(0));
    assertEquals(attribute2, attributes.get(1));
    assertEquals(attribute3, attributes.get(2));

    EntityNameAttribute attribute4 =
        new EntityNameAttribute(EntityNameAttributeId.Locality, "Chicago");
    name.addAttribute(attribute4);

    attributes = name.getAttributes();
    assertEquals(4, attributes.size());
    assertEquals(attribute, attributes.get(0));
    assertEquals(attribute2, attributes.get(1));
    assertEquals(attribute3, attributes.get(2));
    assertEquals(attribute4, attributes.get(3));

    EntityNameAttribute attribute5 =
        new EntityNameAttribute(EntityNameAttributeId.RegisteredId, "1.3.55.222.11");

    try {
      name.addAttribute(attribute5);
    } catch (IllegalArgumentException ex) {
      return; // Expected exception.
    }

    fail("Expected IllegalArgumentException.");
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityName#isValid()}.
   */
  @Test
  public void testIsValid() {
    EntityName name = new EntityName();
    assertFalse(name.isValid());

    EntityNameAttribute attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "CA");
    name.addAttribute(attribute);
    assertTrue(name.isValid());

    EntityNameAttribute attribute2 =
        new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Produce Co.");
    name.addAttribute(attribute2);
    assertTrue(name.isValid());

    EntityNameAttribute attribute3 =
        new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Production");
    name.addAttribute(attribute3);
    assertTrue(name.isValid());

    EntityNameAttribute attribute4 =
        new EntityNameAttribute(EntityNameAttributeId.Locality, "Chicago");
    name.addAttribute(attribute4);
    assertTrue(name.isValid());

    EntityNameAttribute attribute5 =
        new EntityNameAttribute(EntityNameAttributeId.RegisteredId, "1.3.55.222.11");
    name.getAttributes().add(attribute5);
    assertFalse(name.isValid());

    name.getAttributes().remove(attribute5);
    assertTrue(name.isValid());

    attribute4.setValue("This value is really too long for this attribute.");
    assertFalse(name.isValid());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.EntityName#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws IOException {
    EntityName name = new EntityName();
    byte[] encodedName = null;
    byte[] expectedEncoding = null;
    boolean exceptionThrown = false;

    try {
      encodedName = name.getEncoded();
    } catch (IOException ex) {
      exceptionThrown = true; // Expected result.
    }

    assertTrue(exceptionThrown);

    EntityNameAttribute attribute = new EntityNameAttribute(EntityNameAttributeId.Country, "CA");
    name.addAttribute(attribute);

    expectedEncoding = new byte[] {0x30, 0x04, (byte) 0x80, 0x02, 0x43, 0x41};
    encodedName = name.getEncoded();
    assertArrayEquals(expectedEncoding, encodedName);

    EntityNameAttribute attribute2 =
        new EntityNameAttribute(EntityNameAttributeId.Organization, "Acme Produce Co.");
    name.addAttribute(attribute2);

    expectedEncoding =
        new byte[] {
            0x30, 0x16, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x81, 0x10, 0x41, 0x63, 0x6D, 0x65,
            0x20, 0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x65, 0x20, 0x43, 0x6F, 0x2E};
    encodedName = name.getEncoded();
    assertArrayEquals(expectedEncoding, encodedName);

    EntityNameAttribute attribute3 =
        new EntityNameAttribute(EntityNameAttributeId.OrganizationalUnit, "Production");
    name.addAttribute(attribute3);

    expectedEncoding =
        new byte[] {
            0x30, 0x22, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x81, 0x10, 0x41, 0x63, 0x6D, 0x65,
            0x20, 0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x65, 0x20, 0x43, 0x6F, 0x2E, (byte) 0x82,
            0x0A, 0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74, 0x69, 0x6F, 0x6E};
    encodedName = name.getEncoded();
    assertArrayEquals(expectedEncoding, encodedName);

    EntityNameAttribute attribute4 =
        new EntityNameAttribute(EntityNameAttributeId.Locality, "Chicago");
    name.addAttribute(attribute4);

    expectedEncoding =
        new byte[] {
            0x30, 0x2B, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x81, 0x10, 0x41, 0x63, 0x6D, 0x65,
            0x20, 0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x65, 0x20, 0x43, 0x6F, 0x2E, (byte) 0x82,
            0x0A, 0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74, 0x69, 0x6F, 0x6E, (byte) 0x85, 0x07,
            0x43, 0x68, 0x69, 0x63, 0x61, 0x67, 0x6F};
    encodedName = name.getEncoded();
    assertArrayEquals(expectedEncoding, encodedName);
  }
}
