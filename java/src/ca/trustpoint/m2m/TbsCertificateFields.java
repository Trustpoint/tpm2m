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
 * Enumeration of the fields and associated tag numbers in a M2M TBS Certificate. Package visible
 * only.
 */
enum TbsCertificateFields {
  VERSION(0),
  SERIAL_NUMBER(1),
  CA_ALGORITHM(2),
  CA_ALGORITHM_PARAMETERS(3),
  ISSUER(4),
  VALID_FROM(5),
  VALID_DURATION(6),
  SUBJECT(7),
  PUBLIC_KEY_ALGORITHM(8),
  PUBLIC_KEY_ALGORITHM_PARAMETERS(9),
  PUBLIC_KEY(10),
  AUTHORITY_KEY_ID(11),
  SUBJECT_KEY_ID(12),
  KEY_USAGE(13),
  BASIC_CONSTRAINTS(14),
  CERTIFICATE_POLICY(15),
  SUBJECT_ALTERNATE_NAME(16),
  ISSUER_ALTERNATE_NAME(17),
  EXTENDED_KEY_USAGE(18),
  AUTHENTICATION_INFO_ACCESS_OCSP(19),
  CRL_DISTRIBUTION_POINT_URI(20),
  EXTENSIONS(21);

  private int tagNumber;

  TbsCertificateFields(int tagNumber) {
    this.tagNumber = tagNumber;
  }

  public int getTagNumber() {
    return tagNumber;
  }

  public static TbsCertificateFields getInstance(int tagNumber) throws IllegalArgumentException {
    if (tagNumber == VERSION.tagNumber) {
      return VERSION;
    } else if (tagNumber == SERIAL_NUMBER.tagNumber) {
      return SERIAL_NUMBER;
    } else if (tagNumber == CA_ALGORITHM.tagNumber) {
      return CA_ALGORITHM;
    } else if (tagNumber == CA_ALGORITHM_PARAMETERS.tagNumber) {
      return CA_ALGORITHM_PARAMETERS;
    } else if (tagNumber == ISSUER.tagNumber) {
      return ISSUER;
    } else if (tagNumber == VALID_FROM.tagNumber) {
      return VALID_FROM;
    } else if (tagNumber == VALID_DURATION.tagNumber) {
      return VALID_DURATION;
    } else if (tagNumber == SUBJECT.tagNumber) {
      return SUBJECT;
    } else if (tagNumber == PUBLIC_KEY_ALGORITHM.tagNumber) {
      return PUBLIC_KEY_ALGORITHM;
    } else if (tagNumber == PUBLIC_KEY_ALGORITHM_PARAMETERS.tagNumber) {
      return PUBLIC_KEY_ALGORITHM_PARAMETERS;
    } else if (tagNumber == PUBLIC_KEY.tagNumber) {
      return PUBLIC_KEY;
    } else if (tagNumber == AUTHORITY_KEY_ID.tagNumber) {
      return AUTHORITY_KEY_ID;
    } else if (tagNumber == SUBJECT_KEY_ID.tagNumber) {
      return SUBJECT_KEY_ID;
    } else if (tagNumber == KEY_USAGE.tagNumber) {
      return KEY_USAGE;
    } else if (tagNumber == BASIC_CONSTRAINTS.tagNumber) {
      return BASIC_CONSTRAINTS;
    } else if (tagNumber == CERTIFICATE_POLICY.tagNumber) {
      return CERTIFICATE_POLICY;
    } else if (tagNumber == SUBJECT_ALTERNATE_NAME.tagNumber) {
      return SUBJECT_ALTERNATE_NAME;
    } else if (tagNumber == ISSUER_ALTERNATE_NAME.tagNumber) {
      return ISSUER_ALTERNATE_NAME;
    } else if (tagNumber == EXTENDED_KEY_USAGE.tagNumber) {
      return EXTENDED_KEY_USAGE;
    } else if (tagNumber == AUTHENTICATION_INFO_ACCESS_OCSP.tagNumber) {
      return AUTHENTICATION_INFO_ACCESS_OCSP;
    } else if (tagNumber == CRL_DISTRIBUTION_POINT_URI.tagNumber) {
      return CRL_DISTRIBUTION_POINT_URI;
    } else if (tagNumber == EXTENSIONS.tagNumber) {
      return EXTENSIONS;
    } else {
      throw new IllegalArgumentException("unknown TBS certificate field number: " + tagNumber);
    }
  }
}
