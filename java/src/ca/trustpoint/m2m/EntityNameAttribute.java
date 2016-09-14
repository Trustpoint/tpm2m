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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;

import ca.trustpoint.m2m.util.FormattingUtils;
import ca.trustpoint.m2m.util.ValidationUtils;

/**
 * Represents an attribute of an EntityName object. The M2M spec defines these attributes as one of:
 *
 * <pre>
 *     AttributeValue ::= CHOICE {
 *        country           PrintableString (SIZE (2)),
 *        organization      UTF8String (SIZE (1..32)),
 *        organizationalUnit UTF8String (SIZE (1..32)),
 *        distinguishedNameQualifier  PrintableString (SIZE (1..32)),
 *        stateOrProvince   UTF8String (SIZE (1..4)),
 *        locality          UTF8String (SIZE (1..32)),
 *        commonName        UTF8String (SIZE (1..32)),
 *        serialNumber      PrintableString (SIZE (1..32)),
 *        domainComponent   IA5String (SIZE (1..32)),
 *        registeredId      OBJECT IDENTIFIER,
 *        octetsName        OCTET STRING (SIZE (1..8))
 *     }
 * </pre>
 *
 * @see EntityName
 */
public class EntityNameAttribute {
  private EntityNameAttributeId id;
  private String value;

  /**
   * Creates a new empty instance.
   */
  public EntityNameAttribute() {
    this(EntityNameAttributeId.Undefined, null);
  }

  /**
   * Creates a new instance with the given values.
   *
   * @param attributeId Type ID of the attribute.
   * @param value Value of the attribute.
   */
  public EntityNameAttribute(EntityNameAttributeId attributeId, String value) {
    id = attributeId;
    this.value = value;
  }

  public EntityNameAttributeId getId() {
    return id;
  }

  public void setId(EntityNameAttributeId attributeId) {
    id = attributeId;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  /**
   * Returns the DER encoding of this instance.
   *
   * @return The DER encoding of this instance.
   * @throws IOException if this instance cannot be encoded.
   */
  public byte[] getEncoded() throws IOException {
    if (!isValid()) {
      throw new IOException("Attribute is not valid.");
    }

    ASN1Encodable encodedValue;

    switch (id) {
      case Country:
      case DistinguishedNameQualifier:
      case SerialNumber:
        encodedValue = new DERPrintableString(value);
        break;
      case Organization:
      case OrganizationalUnit:
      case StateOrProvince:
      case Locality:
      case CommonName:
        encodedValue = new DERUTF8String(value);
        break;
      case DomainComponent:
        encodedValue = new DERIA5String(value);
        break;
      case RegisteredId:
        encodedValue = new ASN1ObjectIdentifier(value);
        break;
      case OctetsName:
        encodedValue = new DEROctetString(Hex.decode(value));
        break;
      default:
        throw new IOException("Unknown attribute type ID.");
    }

    return new DERTaggedObject(false, id.getIndexId(), encodedValue).getEncoded();
  }

  /**
   * Return true if this instance is a valid EntityName attribute. Values are checked for length and
   * allowed content against the attribute type rules.
   *
   * @return True if this instance is a valid EntityName attribute.
   */
  public boolean isValid() {
    switch (id) {
      case Country:
        if ((value == null) || (value.length() != 2)) {
          return false;
        }

        return DERPrintableString.isPrintableString(value);
      case Organization:
      case OrganizationalUnit:
      case Locality:
      case CommonName:
        return ((value != null) && (value.length() >= 1) && (value.length() <= 32));
      case DistinguishedNameQualifier:
      case SerialNumber:
        if ((value == null) || (value.length() < 1) || (value.length() > 32)) {
          return false;
        }

        return DERPrintableString.isPrintableString(value);
      case StateOrProvince:
        return ((value != null) && (value.length() >= 1) && (value.length() <= 4));
      case DomainComponent:
        if ((value == null) || (value.length() < 1) || (value.length() > 32)) {
          return false;
        }

        return DERIA5String.isIA5String(value);
      case RegisteredId:
        if ((value == null) || (value.length() < 1) || (value.length() > 32)) {
          return false;
        }

        return (ValidationUtils.isValidOid(value));
      case OctetsName:
        if ((value == null) || (value.length() < 1) || (value.length() > 16)) {
          return false;
        }

        return (ValidationUtils.isValidHex(value));
      default:
        return false;
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (obj instanceof EntityNameAttribute) {
      EntityNameAttribute other = (EntityNameAttribute) obj;

      if (id != other.id) {
        return false;
      }

      return ((value == null) ? (other.value == null) : (value.equals(other.value)));
    } else {
      return false;
    }
  }

  @Override
  public int hashCode() {
    int hashcode = 0;

    if (id != null) {
      hashcode = id.hashCode();
    }

    if (value != null) {
      hashcode += value.hashCode();
    }

    return hashcode;
  }

  @Override
  public String toString() {
    return toString(0);
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

    switch (id) {
      case Country: // 0.
        FormattingUtils.indent(buffer, depth).append("[0] country PrintableString: ");
        break;
      case Organization: // 1.
        FormattingUtils.indent(buffer, depth).append("[1] organization UTF8String: ");
        break;
      case OrganizationalUnit: // 2.
        FormattingUtils.indent(buffer, depth).append("[2] organizationalUnit UTF8String: ");
        break;
      case DistinguishedNameQualifier: // 3.
        FormattingUtils.indent(buffer, depth)
            .append("[3] distinguishedNameQualifier PrintableString: ");
        break;
      case StateOrProvince: // 4.
        FormattingUtils.indent(buffer, depth).append("[4] stateOrProvince UTF8String: ");
        break;
      case Locality: // 5.
        FormattingUtils.indent(buffer, depth).append("[5] locality UTF8String: ");
        break;
      case CommonName: // 6.
        FormattingUtils.indent(buffer, depth).append("[6] commonName UTF8String: ");
        break;
      case SerialNumber: // 7.
        FormattingUtils.indent(buffer, depth).append("[7] serialNumber PrintableString: ");
        break;
      case DomainComponent: // 8.
        FormattingUtils.indent(buffer, depth).append("[8] domainComponent IA5String: ");
        break;
      case RegisteredId: // 9.
        FormattingUtils.indent(buffer, depth).append("[9] registeredId OBJECT IDENTIFIER: ");
        break;
      case OctetsName: // 10.
        FormattingUtils.indent(buffer, depth).append("[10] octetsName OCTET STRING: ");
        break;
      default:
        FormattingUtils.indent(buffer, depth).append("[-1] Undefined value. ");
        break;
    }

    if (value != null) {
      buffer.append(value);
    }

    buffer.append(LINE_SEPARATOR);

    return buffer.toString();
  }
}
