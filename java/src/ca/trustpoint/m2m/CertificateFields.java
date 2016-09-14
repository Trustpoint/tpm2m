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
 * Enumeration of the fields and associated tag numbers in a M2M Certificate. Package visible only.
 */
enum CertificateFields {
  TBS_CERTIFICATE(0), CA_CALC_VALUE(1);

  private int tagNumber;

  CertificateFields(int tagNumber) {
    this.tagNumber = tagNumber;
  }

  public int getTagNumber() {
    return tagNumber;
  }

  public static CertificateFields getInstance(int tagNumber) throws IllegalArgumentException {
    if (tagNumber == TBS_CERTIFICATE.tagNumber) {
      return TBS_CERTIFICATE;
    } else if (tagNumber == CA_CALC_VALUE.tagNumber) {
      return CA_CALC_VALUE;
    } else {
      throw new IllegalArgumentException("unknown certificate field number: " + tagNumber);
    }
  }
}
