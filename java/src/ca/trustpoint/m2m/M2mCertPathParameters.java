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

import java.security.cert.CertPathParameters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Contains parameters to be used when verifying M2M certificate chains.
 *
 * @see M2mCertPathValidator
 */
public class M2mCertPathParameters implements CertPathParameters {
  private final List<M2mTrustAnchor> anchors;
  private final Date validityDate;
  private final boolean allowSelfSignedRoot;

  /**
   * Creates an empty instance. Default values are:
   * <ul>
   * <li>No trust anchors.</li>
   * <li>Validity for certificates is current time.</li>
   * <li>Self-signed root is permitted.</li>
   * </ul>
   */
  public M2mCertPathParameters() {
    anchors = null;
    validityDate = null;
    allowSelfSignedRoot = true;
  }

  /**
   * Creates a new instance containing the given list of trust anchors.
   *
   * @param anchors Trust anchors for verifying M2M certificate chains.
   * @param validityDate Date on which certificates in the chain should be valid.
   * @param allowSelfSignedRoot True if an untrusted self-signed root is permitted.
   */
  public M2mCertPathParameters(List<M2mTrustAnchor> anchors, Date validityDate,
      boolean allowSelfSignedRoot) {
    if (anchors != null) {
      ArrayList<M2mTrustAnchor> newList = new ArrayList<M2mTrustAnchor>(anchors);
      this.anchors = Collections.unmodifiableList(newList);
    } else {
      this.anchors = null;
    }

    this.validityDate = (Date) validityDate.clone();
    this.allowSelfSignedRoot = allowSelfSignedRoot;
  }

  public List<M2mTrustAnchor> getAnchors() {
    return anchors;
  }

  public Date getValidityDate() {
    return validityDate;
  }

  public boolean getAllowSelfSignedRoot() {
    return allowSelfSignedRoot;
  }

  @Override
  public Object clone() {
    return new M2mCertPathParameters(anchors, validityDate, allowSelfSignedRoot);
  }
}
