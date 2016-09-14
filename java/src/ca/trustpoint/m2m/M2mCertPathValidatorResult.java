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

import java.security.PublicKey;
import java.security.cert.CertPathValidatorResult;

/**
 * This class represents the successful result of the M2M certification path validation algorithm.
 *
 * <p>
 * Instances of {@code M2mCertPathValidatorResult} are returned by the
 * {@link java.security.cert.CertPathValidator#validate validate()} method of
 * {@link M2mCertPathValidator} objects.
 *
 * <p>
 * All {@code M2mCertPathValidatorResult} objects contain the subject public key resulting from the
 * validation algorithm, as well as a {@link M2mTrustAnchor} describing the certification authority
 * (CA) that served as a trust anchor for the certification path.
 * <p>
 * <b>Concurrent Access</b>
 * <p>
 * Unless otherwise specified, the methods defined in this class are not thread-safe. Multiple
 * threads that need to access a single object concurrently should synchronize amongst themselves
 * and provide the necessary locking. Multiple threads each manipulating separate objects need not
 * synchronize.
 *
 * @see M2mCertPathValidator
 * @see CertPathValidatorResult
 */
public class M2mCertPathValidatorResult implements CertPathValidatorResult {
  private M2mTrustAnchor trustAnchor;
  private PublicKey subjectPublicKey;

  /**
   * Creates a new instance containing the specified parameters.
   *
   * @param trustAnchor a {@link M2mTrustAnchor} describing the CA that served as a trust anchor for
   *        the certification path
   * @param subjectPublicKey the public key of the subject
   * @throws NullPointerException if the {@code subjectPublicKey} or {@code trustAnchor} parameters
   *         are {@code null}
   */
  public M2mCertPathValidatorResult(M2mTrustAnchor trustAnchor, PublicKey subjectPublicKey) {
    if (subjectPublicKey == null) {
      throw new NullPointerException("subjectPublicKey must be non-null");
    } else if (trustAnchor == null) {
      throw new NullPointerException("trustAnchor must be non-null");
    }
    this.trustAnchor = trustAnchor;
    this.subjectPublicKey = subjectPublicKey;
  }

  /**
   * Returns the {@link M2mTrustAnchor} describing the CA that served as a trust anchor for the
   * certification path.
   *
   * @return The {@link M2mTrustAnchor} for the certification path. Should not be null.
   */
  public M2mTrustAnchor getTrustAnchor() {
    return trustAnchor;
  }

  /**
   * Returns the public key of the subject (end entity) of the certification path, including any
   * inherited public key parameters if applicable.
   *
   * @return The {@link java.security.PublicKey PublicKey} of the subject. Should not be null.
   */
  public PublicKey getPublicKey() {
    return subjectPublicKey;
  }

  /**
   * Returns a copy of this object.
   *
   * @return the copy
   */
  @Override
  public Object clone() {
    try {
      return super.clone();
    } catch (CloneNotSupportedException e) {
      /* Cannot happen */
      throw new InternalError(e.toString());
    }
  }

  /**
   * Returns a printable representation of this {@code M2mCertPathValidatorResult}.
   *
   * @return a {@code String} describing the contents of this {@code M2MCertPathValidatorResult}
   */
  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();
    sb.append("M2MCertPathValidatorResult: [\n");
    sb.append("  Trust Anchor: " + trustAnchor.toString() + "\n");
    sb.append("  Subject Public Key: " + subjectPublicKey + "\n");
    sb.append("]");
    return sb.toString();
  }
}
