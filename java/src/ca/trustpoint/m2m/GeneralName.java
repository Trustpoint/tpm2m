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
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import ca.trustpoint.m2m.util.FormattingUtils;

/**
 * Represents a general name.
 *
 * The GeneralName type is defined in the M2M spec as below:
 *
 * <pre>
 *      GeneralName ::= CHOICE {
 *          rfc822Name                  IA5String (SIZE (1..128)),
 *          dNSName                     IA5String (SIZE (1..128)),
 *          directoryName               Name,
 *          uniformResourceIdentifier   IA5String (SIZE (1..128)),
 *          iPAddress                   OCTET STRING (SIZE (1..8)),
 *                                      --4 octets for IPv4 and 16 octets for IPv6
 *          registeredID                OBJECT IDENTIFIER
 *      }
 * </pre>
 */
public class GeneralName {
  private GeneralNameAttributeId id;
  private String value;
  private EntityName entity;

  /**
   * Constructor.
   */
  public GeneralName() {
    id = null;
    value = null;
    entity = null;
  }

  /**
   * Constructor.
   *
   * @param id Type ID of the attribute.
   * @param value Attribute value.
   * @throws IllegalArgumentException if id is DirectoryName.
   */
  public GeneralName(GeneralNameAttributeId id, String value) throws IllegalArgumentException {
    if (id == GeneralNameAttributeId.DirectoryName) {
      throw new IllegalArgumentException("invalid id: " + id);
    }

    this.id = id;
    this.value = value;
    this.entity = null;
  }

  /**
   * Constructor.
   *
   * @param entity Attribute value.
   */
  public GeneralName(EntityName entity) {
    this.id = GeneralNameAttributeId.DirectoryName;
    this.entity = entity;
    this.value = null;
  }

  /**
   * <p>
   * Sets the attribute type ID.
   * </p>
   *
   * <p>
   * <b>NOTE:</b> The currently stored value will be cleared as a result of calling this method.
   * </p>
   *
   * @param id Attribute type ID.
   */
  public void setAttributeId(GeneralNameAttributeId id) {
    this.id = id;
    this.value = null;
    this.entity = null;
  }

  public GeneralNameAttributeId getAttributeId() {
    return id;
  }

  public void setValue(String value) throws IllegalArgumentException {
    if (id == GeneralNameAttributeId.DirectoryName) {
      throw new IllegalArgumentException("invalid call for id: " + id);
    }
    this.value = value;
    this.entity = null;
  }

  public String getValue() {
    return value;
  }

  public void setEntity(EntityName entity) {
    this.id = GeneralNameAttributeId.DirectoryName;
    this.entity = entity;
    this.value = null;
  }

  public EntityName getEntity() {
    return entity;
  }

  /**
   * Validate id and value.
   *
   * @return true if both are valid, false if either one or both are invalid.
   */
  public boolean isValid() {
    if (id == null) {
      return false;
    } else if (((id == GeneralNameAttributeId.DirectoryName) && (entity == null))
        || ((id != GeneralNameAttributeId.DirectoryName) && (value == null))) {
      return false;
    }

    switch (id) {
      case Rfc822Name:
      case DnsName:
        if (!DERIA5String.isIA5String(value)) {
          return false;
        }
        break;

      case DirectoryName:
        return entity.isValid();

      case Uri:
        try {
          new URI(value);
        } catch (Exception e) {
          return false;
        }
        break;

      case IpAddress:
        try {
          InetAddress.getByName(value);
        } catch (UnknownHostException e) {
          return false;
        }
        break;

      case RegisteredId:
        try {
          new ASN1ObjectIdentifier(value);
        } catch (IllegalArgumentException e) {
          return false;
        }
        break;

      default:
        return false;
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
      throw new IOException("name id and/or value is invalid.");
    }

    ASN1Encodable encodable;
    switch (id) {
      case Rfc822Name:
      case DnsName:
      case Uri:
        encodable = new DERIA5String(value);
        break;

      case DirectoryName:
        encodable = DERSequence.getInstance(entity.getEncoded());
        break;

      case IpAddress:
        encodable = new DEROctetString(InetAddress.getByName(value).getAddress());
        break;

      case RegisteredId:
        encodable = new ASN1ObjectIdentifier(value);
        break;

      default:
        throw new IOException("invalid name id.");
    }

    return new DERTaggedObject(false, id.getIndexId(), encodable).getEncoded();
  }

  /**
   * Converts the instance content to a string.
   *
   * @return A string representation of the instance content.
   */
  @Override
  public String toString() {
    return toString(0);
  }

  /**
   * Converts the instance content to a string using the given indentation level.
   *
   * @param depth Indentation level.
   * @return A string representation of the instance content at the given indentation level.
   */
  public String toString(int depth) {
    StringBuffer buffer = new StringBuffer();

    final String LINE_SEPARATOR = System.getProperty("line.separator");

    FormattingUtils.indent(buffer, depth).append("[" + id.getIndexId() + "] ");
    switch (id) {
      case Rfc822Name:
        buffer.append("rfc822Name IA5String: ").append(value);
        break;

      case DnsName:
        buffer.append("dNSName IA5String: ").append(value);
        break;

      case DirectoryName:
        buffer.append("directoryName Name: ").append(entity.toString());
        break;

      case Uri:
        buffer.append("uniformResourceIdentifier IA5String: ").append(value);
        break;

      case IpAddress:
        buffer.append("iPAddress OCTECT STRING: ");
        try {
          buffer.append(InetAddress.getByName(value).getHostAddress());
        } catch (UnknownHostException e) {
          buffer.append(value);
        }
        break;

      case RegisteredId:
        buffer.append("registeredID OBJECT IDENTIFIER: ").append(value);
        break;

      default:
        buffer.append("invalid name id: " + id);
        break;
    }
    buffer.append(LINE_SEPARATOR);

    return buffer.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (!(obj instanceof GeneralName)) {
      return false;
    }

    GeneralName other = (GeneralName) obj;

    if (id == null) {
      if (other.getAttributeId() != null) {
        return false;
      }
    } else if (id != other.getAttributeId()) {
      return false;
    }

    if (entity == null) {
      if (other.getEntity() != null) {
        return false;
      }
    } else if (!entity.equals(other.getEntity())) {
      return false;
    }

    if (value == null) {
      if (other.getValue() != null) {
        return false;
      }
    } else if (!value.equals(other.getValue())) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 0;

    if (id != null) {
      hashCode += 31 * id.hashCode();
    }

    if (entity != null) {
      hashCode += 73 * entity.hashCode();
    }

    if (value != null) {
      hashCode += 23 * value.hashCode();
    }

    return hashCode;
  }
}
