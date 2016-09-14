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

/**
 * Enumerates possible attribute identifiers for EntityName objects.
 *
 * @see EntityName
 * @see EntityNameAttribute
 */
public enum EntityNameAttributeId {
  /** Not defined. */
  Undefined(-1),

  /**
   * Country code. Only <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1
   * alpha-2</a> codes are acceptable as values.
   */
  Country(0),

  /** Organization. Value may be 1 to 32 characters in length. */
  Organization(1),

  /** Organizational Unit. Value may be 1 to 32 characters in length. */
  OrganizationalUnit(2),

  /**
   * Distinguished Name Qualifier. Value may be 1 to 32 ASN.1 PrintableString characters in length.
   */
  DistinguishedNameQualifier(3),

  /** State or Province. Value may be 1 to 4 characters in length. */
  StateOrProvince(4),

  /** Locality. Value may be 1 to 32 characters in length. */
  Locality(5),

  /** Common Name. Value may be 1 to 32 characters in length. */
  CommonName(6),

  /** Serial Number. Value may be 1 to 32 ASN.1 PrintableString characters in length. */
  SerialNumber(7),

  /**
   * Domain Component as defined in <a href="https://tools.ietf.org/html/rfc4519#section-2.4">RFC
   * 4519</a>. Value may be 1 to 32 ASN.1 IA5String characters in length.
   */
  DomainComponent(8),

  /** Registered ID. Value is a ASN.1 Object Identifier. */
  RegisteredId(9),

  /** Octets Name. Value is an ASN.1 Octet String of 1 to 8 bytes. */
  OctetsName(10);

  private final int indexId;

  /**
   * Constructor.
   */
  EntityNameAttributeId(int id) {
    indexId = id;
  }

  /**
   * Returns attribute ID.
   *
   * @return ID of the attribute.
   */
  public int getIndexId() {
    return indexId;
  }

  /**
   * Returns the enumeration value that corresponds to the given id value.
   *
   * @param id An attribute ID
   *
   * @return An instance of attribute in the enum associated with the given id.
   * @throws IllegalArgumentException if id is invalid.
   */
  public static EntityNameAttributeId getInstance(int id) throws IllegalArgumentException {
    if (id == Country.indexId) {
      return Country;
    } else if (id == Organization.indexId) {
      return Organization;
    } else if (id == OrganizationalUnit.indexId) {
      return OrganizationalUnit;
    } else if (id == DistinguishedNameQualifier.indexId) {
      return DistinguishedNameQualifier;
    } else if (id == StateOrProvince.indexId) {
      return StateOrProvince;
    } else if (id == Locality.indexId) {
      return Locality;
    } else if (id == CommonName.indexId) {
      return CommonName;
    } else if (id == SerialNumber.indexId) {
      return SerialNumber;
    } else if (id == DomainComponent.indexId) {
      return DomainComponent;
    } else if (id == RegisteredId.indexId) {
      return RegisteredId;
    } else if (id == OctetsName.indexId) {
      return OctetsName;
    } else {
      throw new IllegalArgumentException("unknown attribute id: " + id);
    }
  }
}
