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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;

import ca.trustpoint.m2m.util.FormattingUtils;

/**
 * Represents a Name object.
 *
 * An EntityName is composed of between 1 and 4 (inclusive) {@link EntityNameAttribute} objects. It
 * is defined in the M2M spec as:
 *
 * <pre>
 *     Name ::= SEQUENCE SIZE (1..4) OF AttributeValue
 * </pre>
 *
 * @see EntityNameAttribute
 */
public class EntityName {
  /** Minimum number of attributes that must be defined for an EntityName instance. */
  public static final int MINIMUM_ATTRIBUTES = 1;

  /** Maximum number of attributes that may be defined for an EntityName instance. */
  public static final int MAXIMUM_ATTRIBUTES = 4;

  private ArrayList<EntityNameAttribute> attributes = new ArrayList<EntityNameAttribute>(4);

  /** Create a new instance. */
  public EntityName() {}

  public List<EntityNameAttribute> getAttributes() {
    return attributes;
  }

  /**
   * Adds the given {@link EntityNameAttribute} to this instance.
   *
   * @param attribute The {@link EntityNameAttribute} to add.
   * @throws IllegalArgumentException if the given {@link EntityNameAttribute} is invalid or if this
   *         this instance already contains {@link EntityName#MAXIMUM_ATTRIBUTES MAX_ATTRIBUTES}
   *         attributes.
   */
  public void addAttribute(EntityNameAttribute attribute) throws IllegalArgumentException {
    if ((attributes == null) || (!attribute.isValid())) {
      throw new IllegalArgumentException("attribute not valid.");
    } else if (attributes.size() >= MAXIMUM_ATTRIBUTES) {
      throw new IllegalArgumentException("too many attributes.");
    }

    attributes.add(attribute);
  }

  /**
   * Return true if this instance is a valid EntityName, per the M2M spec.
   *
   * @return True if this instance is valid.
   */
  public boolean isValid() {
    if ((attributes.size() < MINIMUM_ATTRIBUTES) || (attributes.size() > MAXIMUM_ATTRIBUTES)) {
      return false;
    }

    for (EntityNameAttribute attribute : attributes) {
      if (!attribute.isValid()) {
        return false;
      }
    }

    return true;
  }

  /**
   * Returns the DER encoding of this instance.
   *
   * @return The DER encoding of this instance.
   * @throws IOException if this instance cannot be encoded.
   */
  public byte[] getEncoded() throws IOException {
    if (!isValid()) {
      throw new IOException("EntityName is not valid.");
    }

    ByteArrayOutputStream encodedBytes = new ByteArrayOutputStream();
    DERSequenceGenerator generator = new DERSequenceGenerator(encodedBytes);

    for (EntityNameAttribute attribute : attributes) {
      generator.addObject(DERTaggedObject.getInstance(attribute.getEncoded()));
    }

    generator.close();
    encodedBytes.close();

    return (encodedBytes.toByteArray());
  }

  @Override
  public String toString() {
    return (toString(0));
  }

  /**
   * Converts this instance to its string representation using the given indentation level.
   *
   * @param depth Indentation level.
   * @return String representation of this instance at the given indentation level.
   */
  public String toString(int depth) {
    StringBuffer buffer = new StringBuffer();

    final String LINE_SEPARATOR = System.getProperty("line.separator");

    FormattingUtils.indent(buffer, depth).append("Name SEQUENCE {").append(LINE_SEPARATOR);

    for (EntityNameAttribute attribute : attributes) {
      buffer.append(attribute.toString(depth + 1));
    }

    FormattingUtils.indent(buffer, depth).append("}").append(LINE_SEPARATOR);

    return buffer.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (obj instanceof EntityName) {
      EntityName other = (EntityName) obj;

      return (attributes.equals(other.attributes));
    } else {
      return false;
    }
  }

  @Override
  public int hashCode() {
    return (attributes.hashCode());
  }
}
