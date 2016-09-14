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

import java.security.cert.CRL;
import java.security.cert.Certificate;

/**
 * This class represents of a M2M certificate revocation lists (CRLs).
 */
public class M2mCrl extends CRL {
  /**
   * Creates a M2mCrl.
   */
  public M2mCrl() {
    super("M2M");
  }

  /**
   * Returns a string representation of this CRL.
   *
   * @return a string representation of this CRL.
   */
  @Override
  public String toString() {
    return new String("M2M CRL");
  }

  /**
   * Checks whether the given certificate is on this CRL.
   *
   * @param cert the certificate to check for.
   * @return true if the given certificate is on this CRL, false otherwise.
   */
  @Override
  public boolean isRevoked(Certificate cert) {
    return false;
  }
}
