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
 * Enumerates possible attribute identifiers for GeneralName objects.
 *
 * @see GeneralName
 */
public enum GeneralNameAttributeId {
  /**
   * Rfc822 Name. Value may be 1 to 128 ASN.1 IA5String characters in length.
   */
  Rfc822Name(0),
  /**
   * DNS Name. Value may be 1 to 128 ASN.1 IA5String characters in length.
   */
  DnsName(1),
  /**
   * Directory Name. Value type is EntityName
   *
   * @see EntityName
   */
  DirectoryName(2),
  /**
   * URI. Value may be 1 to 128 ASN.1 IA5String characters in length.
   */
  Uri(3),
  /**
   * IP Address. Value is an ASN.1 Octet String of 1 to 16 bytes. It's 4 octets for IPv4 and 16
   * octets for IPv6.
   */
  IpAddress(4),
  /**
   * Registered ID. Value is a ASN.1 Object Identifier.
   */
  RegisteredId(5);

  private final int indexId;

  /**
   * Constructor.
   */
  GeneralNameAttributeId(int id) {
    indexId = id;
  }

  /**
   * Returns attribute ID.
   *
   * @return Attribute ID.
   */
  public int getIndexId() {
    return indexId;
  }

  /**
   * Returns the enumeration value that corresponds to the given id value.
   *
   * @param id ID of an attribute in this enum.
   *
   * @return An instance of attribute in the enum associated with the given id.
   * @throws IllegalArgumentException if id is invalid.
   */
  public static GeneralNameAttributeId getInstance(int id) throws IllegalArgumentException {
    if (id == Rfc822Name.indexId) {
      return Rfc822Name;
    } else if (id == DnsName.indexId) {
      return DnsName;
    } else if (id == DirectoryName.indexId) {
      return DirectoryName;
    } else if (id == Uri.indexId) {
      return Uri;
    } else if (id == IpAddress.indexId) {
      return IpAddress;
    } else if (id == RegisteredId.indexId) {
      return RegisteredId;
    } else {
      throw new IllegalArgumentException("unknown attribute id: " + id);
    }
  }
}
