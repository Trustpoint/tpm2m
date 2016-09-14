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

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

/**
 * This class implements the M2M validation algorithm for certification paths consisting exclusively
 * of {@link M2mCertificate} objects. It uses the specified input parameter set (which must be a
 * {@link M2mCertPathParameters} object).
 */
public final class M2mCertPathValidator extends CertPathValidatorSpi {
  /**
   * Validates a certification path consisting exclusively of <code>M2MCertificate</code>s using the
   * M2M validation algorithm, which uses the specified input parameter set. The input parameter set
   * must be a {@link M2mCertPathParameters} object.
   *
   * @param certPath The M2M certification path
   * @param params The input M2M parameter set
   * @return The result
   * @throws CertPathValidatorException if cert path does not validate.
   * @throws InvalidAlgorithmParameterException if the specified parameters are inappropriate for
   *         this CertPathValidator
   */
  @Override
  public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params)
      throws CertPathValidatorException, InvalidAlgorithmParameterException {
    if (certPath == null) {
      throw new InvalidAlgorithmParameterException("certPath cannot be null.");
    } else if (!(certPath instanceof M2mCertPath)) {
      throw new InvalidAlgorithmParameterException("certPath must be an instance of M2mCertPath.");
    } else if ((params != null) && (!(params instanceof M2mCertPathParameters))) {
      throw new InvalidAlgorithmParameterException(
          "params must be a M2MCertPathParameters object.");
    }

    List<? extends Certificate> certificateChain = certPath.getCertificates();
    M2mCertificate previousCertificate = null;
    M2mTrustAnchor trustAnchor = null;
    PublicKey endEntityPublicKey = null;
    List<M2mTrustAnchor> anchors = null;
    Date validityDate = null;
    boolean allowSelfSignedRoot = true;

    if (params != null) {
      M2mCertPathParameters certPathParameters = (M2mCertPathParameters) params;
      anchors = certPathParameters.getAnchors();
      validityDate = (certPathParameters.getValidityDate() != null)
          ? certPathParameters.getValidityDate() : new Date();
      allowSelfSignedRoot = certPathParameters.getAllowSelfSignedRoot();
    }

    for (int i = certificateChain.size() - 1; i >= 0; i--) {
      M2mCertificate certificate = (M2mCertificate) certificateChain.get(i);

      if (previousCertificate == null) {
        // This is the root of the chain.
        if (allowSelfSignedRoot && (certificate.getSubject() != null)
            && (certificate.getSubject().equals(certificate.getIssuer()))) {
          // This is a self-signed certificate.
          trustAnchor = new M2mTrustAnchor(certificate);
          previousCertificate = certificate;
        } else if (anchors != null) { // Try to chain to one of the given trust anchors.
          for (M2mTrustAnchor anchor : anchors) {
            if (certificate.getIssuer().equals(anchor.getCaName())) {
              trustAnchor = anchor;

              if (anchor.getCertificate() != null) {
                previousCertificate = anchor.getCertificate();
              } else {
                // Create a dummy certificate for the trust anchor so the rest of the method can
                // do its work.
                previousCertificate = new M2mCertificate();
                previousCertificate.setSubject(anchor.getCaName());
                previousCertificate.setPublicKey(anchor.getPublicKey());
              }

              break;
            }
          }

          if (trustAnchor == null) {
            throw new CertPathValidatorException("Unable to verify root of this chain.");
          }
        } else {
          throw new CertPathValidatorException("Unable to verify root of this chain.");
        }
      }

      // Step 1. Verify validity dates.
      try {
        certificate.checkValidity(validityDate);
      } catch (Exception ex) {
        throw new CertPathValidatorException("Certificate expired or not yet valid.", ex, certPath,
            i);
      }

      // Step 2. Reconstruct inherited values as required.

      /*
       * From the M2M specification...
       *
       * cAAlgorithm OBJECT IDENTIFIER OPTIONAL
       *     Identifies algorithm, hash function & (optional) curve. Required for signature
       *     verification but may be omitted from the transmitted certificate and filled in from the
       *     pkAlgorithm of the superior certificate (but not root certificate)
       *
       *
       * cAAlgParams OCTET STRING OPTIONAL
       *     Required for signature verification unless absent in both the transmitted certificate
       *     and the superior certificate pKAlgParams field. Fill in from superior certificate
       *     pKAlgParams field if needed (but not root certificate)
       */
      if (certificate.getCaKeyDefinition() == null) {
        certificate.setCaKeyDefinition(previousCertificate.getPublicKeyDefinition());
      }

      /*
       * issuer Name OPTIONAL
       *     Required for signature verification but may be omitted from the transmitted certificate
       *     and filled in from the subject field of the superior certificate (but not root
       *     certificate)
       */
      if (certificate.getIssuer() == null) {
        certificate.setIssuer(previousCertificate.getSubject());
      }

      /*
       * Step 3. Reconstruct public key (implicit certificate) or verify signature (explicit
       * certificate).
       */
      try {
        certificate.verify(previousCertificate.getPublicKey());
      } catch (Exception ex) {
        throw new CertPathValidatorException("Signature verification failed.", ex, certPath, i);
      }

      endEntityPublicKey = certificate.getPublicKey();
      previousCertificate = certificate;
    }

    return (new M2mCertPathValidatorResult(trustAnchor, endEntityPublicKey));
  }
}
