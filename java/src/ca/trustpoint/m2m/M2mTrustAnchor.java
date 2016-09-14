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
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;

/**
 * Represents a trust anchor, or most-trusted CA for M2M certificate chains.
 */
public class M2mTrustAnchor {
  private final EntityName caName;
  private final PublicKey publicKey;
  private final M2mCertificate certificate;

  /**
   * Creates a new instance.
   *
   * @param caName Subject name of the CA.
   * @param publicKey Public key of the CA.
   * @throws IllegalArgumentException if caName is null/invalid or publicKey is null.
   */
  public M2mTrustAnchor(EntityName caName, PublicKey publicKey) throws IllegalArgumentException {
    if ((caName == null) || (!caName.isValid())) {
      throw new IllegalArgumentException("caName cannot be null or invalid.");
    } else if (publicKey == null) {
      throw new IllegalArgumentException("publicKey cannot be null.");
    }

    this.caName = caName;
    this.publicKey = publicKey;
    certificate = null;
  }

  /**
   * Creates a new instance from the given certificate.
   *
   * @param certificate CA certificate.
   * @throws IllegalArgumentException if certificate is null or either the subject or public key are
   *         null or invalid.
   */
  public M2mTrustAnchor(M2mCertificate certificate) throws IllegalArgumentException {
    if (certificate == null) {
      throw new IllegalArgumentException("certificate cannot be null.");
    } else if ((certificate.getSubject() == null) || (!certificate.getSubject().isValid())) {
      throw new IllegalArgumentException("certificate subject cannot be null or invalid.");
    } else if (certificate.getPublicKey() == null) {
      throw new IllegalArgumentException("certificate public key cannot be null.");
    }

    caName = certificate.getSubject();
    publicKey = certificate.getPublicKey();
    this.certificate = certificate;
  }

  /**
   * Creates a new instance.
   *
   * @param x509Certificate X.509 certificate to use as trust anchor.
   * @throws IllegalArgumentException if x509Certificate is null.
   */
  public M2mTrustAnchor(X509Certificate x509Certificate) throws IllegalArgumentException {
    if (x509Certificate == null) {
      throw new IllegalArgumentException("x509Certificate cannot be null.");
    }

    X500Name x500Name = JcaX500NameUtil.getSubject(x509Certificate);
    EntityName caName = new EntityName();
    int attributeCount = 0;

    for (RDN rdn : x500Name.getRDNs()) {
      AttributeTypeAndValue attr = rdn.getFirst();
      EntityNameAttributeId attributeId;

      if (BCStyle.C.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.Country;
      } else if (BCStyle.O.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.Organization;
      } else if (BCStyle.OU.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.OrganizationalUnit;
      } else if (BCStyle.DN_QUALIFIER.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.DistinguishedNameQualifier;
      } else if (BCStyle.ST.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.StateOrProvince;
      } else if (BCStyle.L.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.Locality;
      } else if (BCStyle.CN.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.CommonName;
      } else if (BCStyle.SN.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.SerialNumber;
      } else if (BCStyle.DC.equals(attr.getType())) {
        attributeId = EntityNameAttributeId.DomainComponent;
      } else {
        // Unsupported attribute.
        continue;
      }

      caName.addAttribute(
          new EntityNameAttribute(attributeId, IETFUtils.valueToString(attr.getValue())));
      attributeCount++;

      if (attributeCount == EntityName.MAXIMUM_ATTRIBUTES) {
        // We have reached the maximum number of attributes for an EntityName, so stop here.
        break;
      }
    }

    this.caName = caName;
    this.publicKey = x509Certificate.getPublicKey();
    certificate = null;
  }

  public EntityName getCaName() {
    return caName;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Returns the M2M certificate for this trust anchor if it was provided at instantiation.
   */
  public M2mCertificate getCertificate() {
    return certificate;
  }
}
