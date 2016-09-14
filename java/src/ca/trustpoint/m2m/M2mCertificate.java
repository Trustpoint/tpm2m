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
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Extension;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import ca.trustpoint.m2m.ecqv.EcqvProvider;
import ca.trustpoint.m2m.util.FormattingUtils;
import ca.trustpoint.m2m.util.KeyConversionUtils;
import ca.trustpoint.m2m.util.ValidationUtils;

/**
 * Represents a M2M Certificate object and extends the {@link java.security.cert.Certificate} class.
 *
 * This file is typically not used to build certificates.
 *
 * The leading <code>[APPLICATION 20]</code> tag is intended to make the M2M format apparent by
 * inspecting the first byte of the encoding.
 *
 * <pre>
 *  Certificate ::= [APPLICATION 20] IMPLICIT SEQUENCE {
 *      tbsCertificate      TBSCertificate,
 *      cACalcValue         OCTET STRING    -- Contains signature for a signed certificate or public
 *                                          -- key derivation value for an ECQV certificate
 *  }
 *
 * TBSCertificate ::= SEQUENCE {
 *      version                 INTEGER {v1(0)} DEFAULT v1,
 *      serialNumber            OCTET STRING (SIZE (1..20)),
 *      cAAlgorithm             OBJECT IDENTIFIER OPTIONAL,
 *                              -- Identifies CA algorithm, hash function &amp; optionally other
 *                              -- required parameters (e.g. for ECC, the curve).
 *                              -- Required for signature verification but may be omitted from the
 *                              -- transmitted certificate and filled in from the pkAlgorithm of the
 *                              -- superior certificate, (provided this is not a root certificate.)
 *                              -- prior to signature verification.
 *      cAAlgParams             OCTET STRING OPTIONAL,
 *                              -- Identifies CA algorithm parameters.
 *                              -- This specification does not provide for omitting this field in
 *                              -- transmission and subsequently replacing it from the superior
 *                              -- certificate for signature verification.
 *      issuer                  Name OPTIONAL,   -- Required for signature verification but may be
 *                                               -- omitted from the transmitted certificate and
 *                                               -- filled in from the subject field of the superior
 *                                               -- certificate, (provided this is not a root
 *                                               -- certificate,) prior to signature verification.
 *      validFrom               OCTET STRING (SIZE (4..5)) OPTIONAL,
 *                                               -- Unix time. If omitted no validity specified.
 *      validDuration           OCTET STRING (SIZE (1..4)) OPTIONAL,
 *                                               -- # of seconds. If omitted no expiry specified.
 *      subject                 Name,
 *      pubKeyAlgorithm         OBJECT IDENTIFIER OPTIONAL,
 *                              -- Default is same as caAlgorithm in this certificate.
 *      pKAlgParams             OCTET STRING OPTIONAL,
 *      pubKey                  OCTET STRING OPTIONAL,      -- Omit for an ECQV certificate.
 *      authKeyId               OCTET STRING OPTIONAL,
 *      subjKeyId               OCTET STRING OPTIONAL,
 *      keyUsage                OCTET STRING (SIZE (1)) OPTIONAL,
 *                              -- Critical. One byte containing a bit string, as described below.
 *      basicConstraints        INTEGER (0..7) OPTIONAL,
 *                              -- If absent this is an end-entity certificate; otherwise, this is
 *                              -- the maximum intermediate path length for a CA certificate.
 *      certificatePolicy       OBJECT IDENTIFIER OPTIONAL,
 *      subjectAltName          GeneralName OPTIONAL,
 *      issuerAltName           GeneralName OPTIONAL,
 *      extendedKeyUsage        OBJECT IDENTIFIER OPTIONAL,
 *      authInfoAccessOCSP      IA5String OPTIONAL,         -- OCSP responder URI
 *      cRLDistribPointURI      IA5String OPTIONAL,         -- CRL distribution point URI
 *      x509extensions          X509Extensions OPTIONAL
 *  }
 * </pre>
 *
 * @see java.security.cert.Certificate
 */
public class M2mCertificate extends Certificate implements X509Extension {
  /**
   * Represents an X.509 extension. Only used internally within M2MCertificate.
   */
  private static class Extension {
    public String oid = null;
    public boolean isCritical = false;
    public byte[] value = null;

    public ASN1EncodableVector getEncoded() {
      ASN1EncodableVector sequenceValues = new ASN1EncodableVector();
      sequenceValues.add(new DERTaggedObject(false, 0, new ASN1ObjectIdentifier(oid)));

      if (isCritical) { // Default value is false, so only encode the field if true.
        sequenceValues.add(new DERTaggedObject(false, 1, ASN1Boolean.getInstance(isCritical)));
      }

      sequenceValues.add(new DERTaggedObject(false, 2, new DEROctetString(value)));

      return sequenceValues;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == null) {
        return false;
      } else if (!(obj instanceof Extension)) {
        return false;
      }

      Extension other = (Extension) obj;

      if (oid == null) {
        if (other.oid != null) {
          return false;
        }
      } else if (!oid.equals(other.oid)) {
        return false;
      }

      if (isCritical != other.isCritical) {
        return false;
      }

      if (!Arrays.equals(value, other.value)) {
        return false;
      }

      return true;
    }

    @Override
    public int hashCode() {
      int hashCode = 0;

      if (oid != null) {
        hashCode += 31 * oid.hashCode();
      }

      hashCode += (new Boolean(isCritical)).hashCode();

      if (value != null) {
        for (byte b : value) {
          hashCode += 57 * (new Byte(b)).hashCode();
        }
      }

      return hashCode;
    }
  }

  private static final long serialVersionUID = 1L;
  private static final int VERSION = 0; // v1

  /**
   * The first byte of an M2M Certificate is an APPLICATION tag.
   *
   * This is not simply the number twenty. The APPLICATION tag has a spec (X.690 section 8.1.2.2) It
   * consists of 8 bits: [ 8 7 6 5 4 3 2 1 ] [ 8 7 ] = [ 0 1 ] - Specifies the APPLICATION type
   * (there are other types) [ 6 ] = [ 1 ] - We are not encoding a primitive object [ 5 4 3 2 1 ] =
   * [ 1 0 1 0 0 ] - integer 20 in binary
   *
   * The result is [ 0 1 1 1 0 1 0 0 ] = 0x74
   *
   * However since Bouncy Castle takes care of the top three bits we only have to pass in the number
   * 20.
   */
  public static final byte APPLICATION_TAG_NUMBER = 0x14; // Integer 20

  private byte[] serialNumber;
  private KeyAlgorithmDefinition caKeyDefinition;
  private EntityName issuer;
  private Date validFrom;
  private Integer validDuration;
  private EntityName subject;
  private KeyAlgorithmDefinition publicKeyDefinition;
  private PublicKey publicKey;
  private boolean isPublicKeyCompressed;
  private AuthorityKeyIdentifier authorityKeyIdentifier;
  private byte[] subjectKeyIdentifier;
  private KeyUsage keyUsage;
  private Integer basicConstraints;
  private String certificatePolicy;
  private GeneralName subjectAlternativeName;
  private GeneralName issuerAlternativeName;
  private String extendedKeyUsage;
  private URI authenticationInfoAccessOcsp;
  private URI crlDistributionPointUri;
  private List<Extension> extensions;
  private byte[] caCalcValue;

  /**
   * If this is an ECQV certificate, then the reconstructed public key will be stored here.
   */
  private PublicKey reconstructedPublicKey = null;

  /**
   * Creates a new empty M2M certificate.
   */
  public M2mCertificate() {
    super("M2M");

    serialNumber = null;
    caKeyDefinition = null;
    issuer = null;
    validFrom = null;
    validDuration = null;
    subject = null;
    publicKeyDefinition = null;
    publicKey = null;
    isPublicKeyCompressed = false;
    authorityKeyIdentifier = null;
    subjectKeyIdentifier = null;
    keyUsage = null;
    basicConstraints = null;
    certificatePolicy = null;
    subjectAlternativeName = null;
    issuerAlternativeName = null;
    extendedKeyUsage = null;
    authenticationInfoAccessOcsp = null;
    crlDistributionPointUri = null;
    extensions = new ArrayList<Extension>();
    caCalcValue = null;
  }

  public int getVersion() {
    return VERSION;
  }

  public byte[] getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(byte[] serialNumber) {
    this.serialNumber = serialNumber;
  }

  public KeyAlgorithmDefinition getCaKeyDefinition() {
    return caKeyDefinition;
  }

  public void setCaKeyDefinition(KeyAlgorithmDefinition caKeyDefinition) {
    this.caKeyDefinition = caKeyDefinition;
  }

  public EntityName getIssuer() {
    return issuer;
  }

  public void setIssuer(EntityName issuer) {
    this.issuer = issuer;
  }

  public Date getValidFrom() {
    return validFrom;
  }

  public void setValidFrom(Date validFrom) {
    this.validFrom = validFrom;
  }

  public Integer getValidDuration() {
    return validDuration;
  }

  public void setValidDuration(Integer validDuration) {
    this.validDuration = validDuration;
  }

  public EntityName getSubject() {
    return subject;
  }

  public void setSubject(EntityName subject) {
    this.subject = subject;
  }

  public KeyAlgorithmDefinition getPublicKeyDefinition() {
    return publicKeyDefinition;
  }

  public void setPublicKeyDefinition(KeyAlgorithmDefinition publicKeyDefinition) {
    this.publicKeyDefinition = publicKeyDefinition;
  }

  public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public void setAuthorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyIdentifier) {
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

  public byte[] getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public void setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

  public void setKeyUsage(KeyUsage keyUsage) {
    this.keyUsage = keyUsage;
  }

  public Integer getBasicConstraints() {
    return basicConstraints;
  }

  public void setBasicConstraints(Integer basicConstraints) {
    this.basicConstraints = basicConstraints;
  }

  public String getCertificatePolicy() {
    return certificatePolicy;
  }

  public void setCertificatePolicy(String certificatePolicy) {
    this.certificatePolicy = certificatePolicy;
  }

  public GeneralName getSubjectAlternativeName() {
    return subjectAlternativeName;
  }

  public void setSubjectAlternativeName(GeneralName subjectAlternativeName) {
    this.subjectAlternativeName = subjectAlternativeName;
  }

  public GeneralName getIssuerAlternativeName() {
    return issuerAlternativeName;
  }

  public void setIssuerAlternativeName(GeneralName issuerAlternativeName) {
    this.issuerAlternativeName = issuerAlternativeName;
  }

  public String getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public void setExtendedKeyUsage(String extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public URI getAuthenticationInfoAccessOcsp() {
    return authenticationInfoAccessOcsp;
  }

  public void setAuthenticationInfoAccessOcsp(URI authenticationInfoAccessOcsp) {
    this.authenticationInfoAccessOcsp = authenticationInfoAccessOcsp;
  }

  public URI getCrlDistributionPointUri() {
    return crlDistributionPointUri;
  }

  public void setCrlDistributionPointUri(URI crlDistributionPointUri) {
    this.crlDistributionPointUri = crlDistributionPointUri;
  }

  @Override
  public PublicKey getPublicKey() {
    if (publicKey != null) {
      return publicKey;
    } else if (reconstructedPublicKey != null) {
      return reconstructedPublicKey;
    }

    return null;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public boolean getIsPublicKeyCompressed() {
    return isPublicKeyCompressed;
  }

  public void setIsPublicKeyCompressed(boolean isCompressed) {
    isPublicKeyCompressed = isCompressed;
  }

  /**
   * Adds an X.509 extension to this certificate instance.
   *
   * @param oid Object ID of the extension. See the X.509 specification for more details.
   * @param isCritical True if the extension is critical. False otherwise.
   * @param value The value of the extension.
   * @throws IllegalArgumentException If the OID provided is not valid or null.
   */
  public void addExtension(String oid, boolean isCritical, byte[] value)
      throws IllegalArgumentException {
    if ((oid == null) || (!ValidationUtils.isValidOid(oid))) {
      throw new IllegalArgumentException("oid is invalid.");
    }

    Extension ext = null;

    for (Extension currentExt : extensions) {
      if (oid.equals(currentExt.oid)) {
        ext = currentExt;
        break;
      }
    }

    if (ext == null) {
      ext = new Extension();
      ext.oid = oid;
      extensions.add(ext);
    }

    ext.isCritical = isCritical;
    ext.value = value;
  }

  @Override
  public Set<String> getCriticalExtensionOIDs() {
    return getExtensionOids(true);
  }

  @Override
  public byte[] getExtensionValue(String oid) {
    byte[] value = null;

    for (Extension ext : extensions) {
      if (oid.equals(ext.oid)) {
        value = ext.value;
        break;
      }
    }

    return value;
  }

  @Override
  public Set<String> getNonCriticalExtensionOIDs() {
    return getExtensionOids(false);
  }

  @Override
  public boolean hasUnsupportedCriticalExtension() {
    return false;
  }

  public byte[] getCaCalcValue() {
    return caCalcValue;
  }

  public void setCaCalcValue(byte[] caCalcValue) {
    this.caCalcValue = caCalcValue;
  }

  /**
   * Returns the DER encoded to be signed certificate data. This is what would be sent to a CA for
   * signing, or the data that will be verified with the signature.
   *
   * @return The DER encoded to be signed certificate data.
   * @throws IOException if the encoding fails.
   */
  public byte[] getTBSCertificate() throws IOException {
    if (!isTbsCertificateValid()) {
      throw new IOException("One or more TBS certificate fields are invalid.");
    }

    ASN1EncodableVector elements = new ASN1EncodableVector();

    /*
     * Since the default is v1 (0), we do not need to explicitly add this to the ASN.1 output.
     *
     * elements.add( new DERTaggedObject( false, TbsCertificateFields.VERSION.getTagNumber(), new
     * ASN1Integer(VERSION)));
     */
    elements.add(new DERTaggedObject(false, TbsCertificateFields.SERIAL_NUMBER.getTagNumber(),
        new DEROctetString(serialNumber)));

    if (caKeyDefinition != null) {
      if (caKeyDefinition.getAlgorithm() != null) {
        elements.add(new DERTaggedObject(false, TbsCertificateFields.CA_ALGORITHM.getTagNumber(),
            ASN1Primitive.fromByteArray(caKeyDefinition.getEncodedAlgorithm())));
      }

      if (caKeyDefinition.getParameters() != null) {
        elements.add(
            new DERTaggedObject(false, TbsCertificateFields.CA_ALGORITHM_PARAMETERS.getTagNumber(),
                ASN1Primitive.fromByteArray(caKeyDefinition.getEncodedParameters())));
      }
    }

    if (issuer != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.ISSUER.getTagNumber(),
          DERSequence.getInstance(issuer.getEncoded())));
    }

    if (validFrom != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.VALID_FROM.getTagNumber(),
          // We record seconds, not milliseconds, hence the / 1000
          new DEROctetString(BigInteger.valueOf(validFrom.getTime() / 1000).toByteArray())));
    }

    if (validDuration != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.VALID_DURATION.getTagNumber(),
          new DEROctetString(BigInteger.valueOf(validDuration.intValue()).toByteArray())));
    }

    elements.add(new DERTaggedObject(false, TbsCertificateFields.SUBJECT.getTagNumber(),
        DERSequence.getInstance(subject.getEncoded())));

    if (publicKeyDefinition != null) {
      if (publicKeyDefinition.getAlgorithm() != null) {
        elements.add(
            new DERTaggedObject(false, TbsCertificateFields.PUBLIC_KEY_ALGORITHM.getTagNumber(),
                ASN1Primitive.fromByteArray(publicKeyDefinition.getEncodedAlgorithm())));
      }

      if (publicKeyDefinition.getParameters() != null) {
        elements.add(new DERTaggedObject(false,
            TbsCertificateFields.PUBLIC_KEY_ALGORITHM_PARAMETERS.getTagNumber(),
            ASN1Primitive.fromByteArray(publicKeyDefinition.getEncodedParameters())));
      }
    }

    if (publicKey != null) {
      byte[] publicKeyBytes =
          KeyConversionUtils.convertEcPublicKeyToRawBytes(publicKey, isPublicKeyCompressed);

      elements.add(new DERTaggedObject(false, TbsCertificateFields.PUBLIC_KEY.getTagNumber(),
          new DEROctetString(publicKeyBytes)));
    }

    if (authorityKeyIdentifier != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.AUTHORITY_KEY_ID.getTagNumber(),
          ASN1Primitive.fromByteArray(authorityKeyIdentifier.getEncoded())));
    }

    if (subjectKeyIdentifier != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.SUBJECT_KEY_ID.getTagNumber(),
          new DEROctetString(subjectKeyIdentifier)));
    }

    if (keyUsage != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.KEY_USAGE.getTagNumber(),
          ASN1Primitive.fromByteArray(keyUsage.getEncoded())));
    }

    if (basicConstraints != null) {
      elements.add(new DERTaggedObject(false, TbsCertificateFields.BASIC_CONSTRAINTS.getTagNumber(),
          new ASN1Integer(basicConstraints.intValue())));
    }

    if (certificatePolicy != null) {
      elements
          .add(new DERTaggedObject(false, TbsCertificateFields.CERTIFICATE_POLICY.getTagNumber(),
              new ASN1ObjectIdentifier(certificatePolicy)));
    }

    if (subjectAlternativeName != null) {
      elements
          .add(new DERTaggedObject(true, TbsCertificateFields.SUBJECT_ALTERNATE_NAME.getTagNumber(),
              DERTaggedObject.getInstance(subjectAlternativeName.getEncoded())));
    }

    if (issuerAlternativeName != null) {
      elements
          .add(new DERTaggedObject(true, TbsCertificateFields.ISSUER_ALTERNATE_NAME.getTagNumber(),
              DERTaggedObject.getInstance(issuerAlternativeName.getEncoded())));
    }

    if (extendedKeyUsage != null) {
      elements
          .add(new DERTaggedObject(false, TbsCertificateFields.EXTENDED_KEY_USAGE.getTagNumber(),
              new ASN1ObjectIdentifier(extendedKeyUsage)));
    }

    if (authenticationInfoAccessOcsp != null) {
      elements.add(new DERTaggedObject(false,
          TbsCertificateFields.AUTHENTICATION_INFO_ACCESS_OCSP.getTagNumber(),
          new DERIA5String(authenticationInfoAccessOcsp.toString())));
    }

    if (crlDistributionPointUri != null) {
      elements.add(
          new DERTaggedObject(false, TbsCertificateFields.CRL_DISTRIBUTION_POINT_URI.getTagNumber(),
              new DERIA5String(crlDistributionPointUri.toString())));
    }

    if (!extensions.isEmpty()) {
      ASN1EncodableVector toBeEncodedExtensions = new ASN1EncodableVector();

      for (Extension extension : extensions) {
        toBeEncodedExtensions.add(new DERSequence(extension.getEncoded()));
      }

      elements.add(new DERTaggedObject(false, TbsCertificateFields.EXTENSIONS.getTagNumber(),
          new DERSequence(toBeEncodedExtensions)));
    }

    return ((new DERSequence(elements)).getEncoded());
  }

  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    ASN1EncodableVector elements = new ASN1EncodableVector();

    if (!isTbsCertificateValid()) {
      throw new CertificateEncodingException("TBS certificate is invalid.");
    } else if ((caCalcValue == null) || (caCalcValue.length == 0)) {
      throw new CertificateEncodingException("Signature or reconstruction value must be present.");
    }

    try {
      elements.add(new DERTaggedObject(false, CertificateFields.TBS_CERTIFICATE.getTagNumber(),
          DERSequence.fromByteArray(getTBSCertificate())));
    } catch (IOException ex) {
      throw new CertificateEncodingException("Could not encode TBS certificate fields.", ex);
    }

    elements.add(new DERTaggedObject(false, CertificateFields.CA_CALC_VALUE.getTagNumber(),
        new DEROctetString(caCalcValue)));

    DERApplicationSpecific certificate = null;

    try {
      certificate =
          new DERApplicationSpecific(false, APPLICATION_TAG_NUMBER, new DERSequence(elements));
    } catch (IOException ex) {
      throw new CertificateEncodingException("Could not construct ASN.1 certificate.", ex);
    }

    byte[] encodedBytes = null;

    try {
      encodedBytes = certificate.getEncoded();
    } catch (IOException ex) {
      throw new CertificateEncodingException("Could not encode certificate.", ex);
    }

    return encodedBytes;
  }

  @Override
  public String toString() {
    return toString(0);
  }

  /**
   * Converts this instance to its string representation using the given indentation level.
   *
   * @param depth Indentation level.
   * @return String representation of this instance at the given indentation level.
   */
  public String toString(int depth) {
    StringBuffer buffer = new StringBuffer();

    final String LINE_SEPARATOR = System.getProperty("line.separator");

    FormattingUtils.indent(buffer, depth).append("M2MCertificate [APPLICATION 20] SEQUENCE {")
        .append(LINE_SEPARATOR);
    FormattingUtils.indent(buffer, depth + 1).append("[0] tbsCertificate TBSCertificate: ")
        .append(LINE_SEPARATOR);

    FormattingUtils.indent(buffer, depth + 2).append("TBSCertificate SEQUENCE {")
        .append(LINE_SEPARATOR);
    FormattingUtils.indent(buffer, depth + 3).append("[ 0] version INTEGER:               ");
    buffer.append(VERSION).append(LINE_SEPARATOR);

    if (serialNumber != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[ 1] serialNumber OCTET STRING:     ");
      buffer.append(Hex.toHexString(serialNumber)).append(LINE_SEPARATOR);
    }

    if (caKeyDefinition != null) {
      if (caKeyDefinition.getAlgorithm() != null) {
        FormattingUtils.indent(buffer, depth + 3).append("[ 2] cAAlgorithm OBJECT IDENTIFIER: ");
        buffer.append(caKeyDefinition.getAlgorithm().getOid()).append(LINE_SEPARATOR);
      }

      if (caKeyDefinition.getParameters() != null) {
        FormattingUtils.indent(buffer, depth + 3).append("[ 3] cAAlgParams OCTET STRING:      ");
        buffer.append(Hex.toHexString(caKeyDefinition.getParameters())).append(LINE_SEPARATOR);
      }
    }

    if (issuer != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[ 4] issuer Name: ").append(LINE_SEPARATOR);
      buffer.append(issuer.toString(depth + 4));
    }

    if (validFrom != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[ 5] validFrom OCTET STRING: ");
      buffer.append(Hex.toHexString(BigInteger.valueOf(validFrom.getTime() / 1000).toByteArray()))
          .append(LINE_SEPARATOR);
    }

    if (validDuration != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[ 6] validDuration OCTET STRING: ");
      buffer.append(validDuration).append(LINE_SEPARATOR);
    }

    if (subject != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[ 7] subject Name: ")
          .append(LINE_SEPARATOR);
      buffer.append(subject.toString(depth + 4));
    }

    if (publicKeyDefinition != null) {
      if (publicKeyDefinition.getAlgorithm() != null) {
        FormattingUtils.indent(buffer, depth + 3).append("[ 8] pKAlgorithm OBJECT IDENTIFIER: ");
        buffer.append(publicKeyDefinition.getAlgorithm()).append(LINE_SEPARATOR);
      }

      if (publicKeyDefinition.getParameters() != null) {
        FormattingUtils.indent(buffer, depth + 3).append("[ 9] pKAlgParams OCTET STRING: ");
        buffer.append(Hex.toHexString(publicKeyDefinition.getParameters())).append(LINE_SEPARATOR);
      }
    }

    if (publicKey != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[10] pubKey OCTET STRING: ");
      buffer.append(Hex.toHexString(publicKey.getEncoded())).append(LINE_SEPARATOR);
    }

    if (authorityKeyIdentifier != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[11] authKeyId OCTET STRING: ")
          .append(LINE_SEPARATOR);
      buffer.append(authorityKeyIdentifier.toString(depth + 4)).append(LINE_SEPARATOR);
    }

    if (subjectKeyIdentifier != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[12] subjKeyId OCTET STRING: ");
      buffer.append(Hex.toHexString(subjectKeyIdentifier)).append(LINE_SEPARATOR);
    }

    if (keyUsage != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[13] keyUsage OCTET STRING: ");
      buffer.append(keyUsage.toString(depth + 4)).append(LINE_SEPARATOR);
    }

    if (basicConstraints != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[14] basicConstraints INTEGER: ");
      buffer.append(basicConstraints).append(LINE_SEPARATOR);
    }

    if (certificatePolicy != null) {
      FormattingUtils.indent(buffer, depth + 3)
          .append("[15] certificatePolicy OBJECT IDENTIFIER: ");
      buffer.append(certificatePolicy).append(LINE_SEPARATOR);
    }

    if (subjectAlternativeName != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[16] subjectAltName GeneralName: ");
      buffer.append(subjectAlternativeName.toString(depth + 4)).append(LINE_SEPARATOR);
    }

    if (issuerAlternativeName != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[17] issuerAltName GeneralName: ");
      buffer.append(issuerAlternativeName.toString(depth + 4)).append(LINE_SEPARATOR);
    }

    if (extendedKeyUsage != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[18] extendedKeyUsage OBJECT IDENTIFIER: ");
      buffer.append(extendedKeyUsage).append(LINE_SEPARATOR);
    }

    if (authenticationInfoAccessOcsp != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[19] authInfoAccess IA5String: ");
      buffer.append(authenticationInfoAccessOcsp.toString()).append(LINE_SEPARATOR);
    }

    if (crlDistributionPointUri != null) {
      FormattingUtils.indent(buffer, depth + 3).append("[20] cRLDistribPoint IA5String: ");
      buffer.append(crlDistributionPointUri.toString()).append(LINE_SEPARATOR);
    }

    if (!extensions.isEmpty()) {
      FormattingUtils.indent(buffer, depth + 3).append("[21] x509extensions:")
          .append(LINE_SEPARATOR);
      FormattingUtils.indent(buffer, depth + 4).append("X509Extensions SEQUENCE {")
          .append(LINE_SEPARATOR);

      for (int i = 0; i < extensions.size(); i++) {
        Extension e = extensions.get(i);

        FormattingUtils.indent(buffer, depth + 5).append("[").append(i)
            .append("] Extension SEQUENCE {").append(LINE_SEPARATOR);
        FormattingUtils.indent(buffer, depth + 6).append("extnId OBJECT IDENTIFIER: ");
        buffer.append(e.oid).append(LINE_SEPARATOR);

        FormattingUtils.indent(buffer, depth + 6).append("criticality BOOLEAN: ");
        buffer.append((e.isCritical ? "TRUE" : "FALSE")).append(LINE_SEPARATOR);

        if (e.value != null) {
          FormattingUtils.indent(buffer, depth + 6).append("extnValue OCTET STRING: ");
          buffer.append(Hex.toHexString(e.value)).append(LINE_SEPARATOR);
        }

        FormattingUtils.indent(buffer, depth + 5).append("}").append(LINE_SEPARATOR);
      }

      FormattingUtils.indent(buffer, depth + 4).append("}").append(LINE_SEPARATOR);
    }

    if (caCalcValue != null) {
      ASN1Sequence caCalcValueSequence = null;
      // The caCalcValue is an ASN1Sequence for non-ECQV certificate but not for ECQV
      // certificate, so exception may be encountered
      try {
        caCalcValueSequence = ASN1Sequence.getInstance(caCalcValue);
      } catch (Exception e) {
        // Not an ASN1Sequence
        caCalcValueSequence = null;
      }

      if (caCalcValueSequence != null) {
        FormattingUtils.indent(buffer, depth + 1)
            .append("[1] cACalcValue OCTET STRING representing: ").append(LINE_SEPARATOR);
        FormattingUtils.indent(buffer, depth + 2).append("SEQUENCE {").append(LINE_SEPARATOR);

        for (int i = 0; i < caCalcValueSequence.size(); i++) {
          try {
            FormattingUtils.indent(buffer, depth + 3).append("INTEGER: ")
                .append(Hex
                    .toHexString(caCalcValueSequence.getObjectAt(i).toASN1Primitive().getEncoded()))
                .append(LINE_SEPARATOR);
          } catch (IOException ex) {
            // Do nothing.
          }
        }

        FormattingUtils.indent(buffer, depth + 2).append("}").append(LINE_SEPARATOR);
      } else {
        FormattingUtils.indent(buffer, depth + 1).append("[1] cACalcValue OCTET STRING: ");
        buffer.append(Hex.toHexString(caCalcValue)).append(LINE_SEPARATOR);
      }
    }

    FormattingUtils.indent(buffer, depth).append("}").append(LINE_SEPARATOR);

    return buffer.toString();
  }

  @Override
  public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
      InvalidKeyException, NoSuchProviderException, SignatureException {
    verify(key, BouncyCastleProvider.PROVIDER_NAME);
  }

  @Override
  public void verify(PublicKey key, String sigProvider) throws CertificateException,
      NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    if (key == null) {
      throw new InvalidKeyException("key cannot be null.");
    }

    if (isEcqvCertificate()) { // Implicit certificate.
      if (subject.equals(issuer)) {
        throw new SignatureException("Self-signed ECQV certificates are not supported.");
      }

      try {
        reconstructPublicKey(key);
      } catch (Exception ex) {
        throw new SignatureException("Unable to reconstruct public key.", ex);
      }
    } else {
      SignatureAlgorithms signatureAlgorithm = null;

      // We need the signature algorithm that was used to sign this certificate. If not specified,
      // then throw an exception.
      if ((caKeyDefinition != null) && (caKeyDefinition.getAlgorithm() != null)) {
        signatureAlgorithm = SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm());
      } else {
        throw new InvalidKeyException("unable to determine signature algorithm.");
      }

      Signature sigVerifier =
          Signature.getInstance(signatureAlgorithm.getBouncyCastleName(), sigProvider);
      sigVerifier.initVerify(key);

      try {
        sigVerifier.update(getTBSCertificate());
      } catch (IOException ex) {
        throw new SignatureException("unable to generate TBS certificate for verification.", ex);
      }

      if (!sigVerifier.verify(caCalcValue)) {
        throw new SignatureException("signature verification failed.");
      }
    }
  }

  /**
   * Checks that the certificate is currently valid. It is if the current date and time are within
   * the validity period given in the certificate.
   *
   * @throws CertificateExpiredException if the certificate has expired.
   * @throws CertificateNotYetValidException if the certificate is not yet valid.
   */
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    checkValidity(new Date(System.currentTimeMillis()));
  }

  /**
   * Checks that the certificate is currently valid. It is if the current date and time are within
   * the validity period given in the certificate.
   *
   * @param date The Date to check against to see if this certificate is valid at that date/time.
   * @throws CertificateExpiredException if the certificate has expired.
   * @throws CertificateNotYetValidException if the certificate is not yet valid.
   */
  public void checkValidity(Date date)
      throws CertificateExpiredException, CertificateNotYetValidException {
    if (validFrom != null) {
      if (validFrom.after(date)) {
        throw new CertificateNotYetValidException(
            "Certificate is not valid until " + DateFormat.getInstance().format(validFrom) + ".");
      }

      if (validDuration != null) {
        Date notAfter = new Date(validFrom.getTime() + (validDuration.longValue() * 1000));

        if (notAfter.before(date)) {
          throw new CertificateExpiredException(
              "Certificate expired on " + DateFormat.getInstance().format(notAfter) + ".");
        }
      }
    }
  }

  public boolean isEcqvCertificate() {
    try {
      checkIfEcqvCertificate();
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return true;
  }

  /**
   * Reconstruct the users public key using the public key recovery data and the CA public key.
   *
   * @param caPublicKey The issuers public key
   * @return Reconstructed ECQV public key
   * @throws IllegalArgumentException if caPublicKey is null.
   * @throws InvalidKeyException if the public key could not be reconstructed.
   * @throws NoSuchAlgorithmException if the CA key algorithm is undefined or not ECQV based.
   */
  public PublicKey reconstructPublicKey(PublicKey caPublicKey)
      throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {
    if (reconstructedPublicKey != null) {
      return reconstructedPublicKey;
    }

    if (caPublicKey == null) {
      throw new IllegalArgumentException("caPublicKey cannot be null.");
    }

    checkIfEcqvCertificate();

    SignatureAlgorithms caAlgorithm =
        SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

    try {
      EcqvProvider provider = new EcqvProvider(caAlgorithm, caKeyDefinition.getParameters());
      reconstructedPublicKey =
          provider.reconstructPublicKey(getTBSCertificate(), caCalcValue, caPublicKey);
    } catch (Exception ex) {
      throw new InvalidKeyException("Unable to reconstruct public key.", ex);
    }

    return reconstructedPublicKey;
  }

  /**
   * Reconstruct the users private key using the private key recovery data and the users ephemeral
   * private key.
   *
   * @param ephemeralPrivateKey The requesters ephemeral private key
   * @return ecqv certificate owners private key
   * @throws InvalidKeyException if the public key could not be reconstructed.
   * @throws IOException if the encoding of the TBS certificate data fails.
   * @throws NoSuchAlgorithmException if the CA key algorithm is undefined or not ECQV based.
   */
  public PrivateKey reconstructPrivateKey(PrivateKey ephemeralPrivateKey,
      byte[] privateKeyReconstructionData)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    if (ephemeralPrivateKey == null) {
      throw new IllegalArgumentException("ephemeralPrivateKey cannot be null.");
    } else if (privateKeyReconstructionData == null) {
      throw new IllegalArgumentException("privateKeyReconstructionData cannot be null.");
    }

    checkIfEcqvCertificate();

    SignatureAlgorithms caAlgorithm =
        SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());
    PrivateKey reconstructedKey = null;

    try {
      EcqvProvider provider = new EcqvProvider(caAlgorithm, caKeyDefinition.getParameters());
      reconstructedKey = provider.reconstructPrivateKey(getTBSCertificate(), caCalcValue,
          privateKeyReconstructionData, ephemeralPrivateKey);
    } catch (Exception ex) {
      throw new InvalidKeyException("Unable to reconstruct private key.", ex);
    }

    return reconstructedKey;
  }

  /**
   * Pare down the fields to the bare minimum allowed by the spec. Removes *most of* optional
   * fields.
   *
   * In a certificate chain, the certificate issued by a root certificate must contain the issuer
   * field. This is since the root cert is usually not part of the certificate chain when
   * transmitted. Actually it must not be part of the certificate chain as in the case of NFC
   * Signature RTD.
   *
   * The omitIssuer flag should be set to false by caller, typically the CA when creating the
   * certificate chain, if the certificate is issued by root, otherwise should be set to true.
   *
   * @param omitIssuer A flag to show if the issuer field should be removed or not.
   */
  public void clearOptionalFields(boolean omitIssuer) {
    // serialNumber = null; //non-optional
    caKeyDefinition = null;

    if (omitIssuer) {
      issuer = null;
    }

    validFrom = null;
    validDuration = null;
    // subject = null; //non-optional

    publicKeyDefinition = null;
    publicKey = null;
    authorityKeyIdentifier = null;

    subjectKeyIdentifier = null;
    keyUsage = null;
    basicConstraints = null;
    certificatePolicy = null;

    subjectAlternativeName = null;
    issuerAlternativeName = null;
    extendedKeyUsage = null;
    authenticationInfoAccessOcsp = null;

    crlDistributionPointUri = null;
    extensions = null;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    } else if (!(other instanceof M2mCertificate)) {
      return false;
    }

    M2mCertificate otherCertificate = (M2mCertificate) other;

    if (!Arrays.equals(serialNumber, otherCertificate.getSerialNumber())) {
      return false;
    }

    if (caKeyDefinition == null) {
      if (otherCertificate.getCaKeyDefinition() != null) {
        return false;
      }
    } else if (!caKeyDefinition.equals(otherCertificate.getCaKeyDefinition())) {
      return false;
    }

    if (issuer == null) {
      if (otherCertificate.getIssuer() != null) {
        return false;
      }
    } else if (!issuer.equals(otherCertificate.getIssuer())) {
      return false;
    }

    if (validFrom == null) {
      if (otherCertificate.getValidFrom() != null) {
        return false;
      }
    } else if (!validFrom.equals(otherCertificate.getValidFrom())) {
      return false;
    }

    if (validDuration == null) {
      if (otherCertificate.getValidDuration() != null) {
        return false;
      }
    } else if (!validDuration.equals(otherCertificate.getValidDuration())) {
      return false;
    }

    if (subject == null) {
      if (otherCertificate.getSubject() != null) {
        return false;
      }
    } else if (!subject.equals(otherCertificate.getSubject())) {
      return false;
    }

    if (publicKeyDefinition == null) {
      if (otherCertificate.getPublicKeyDefinition() != null) {
        return false;
      }
    } else if (!publicKeyDefinition.equals(otherCertificate.getPublicKeyDefinition())) {
      return false;
    }

    if (publicKey == null) {
      if (otherCertificate.getPublicKey() != null) {
        return false;
      }
    } else if (otherCertificate.getPublicKey() == null) {
      return false;
    } else if (!Arrays.equals(publicKey.getEncoded(),
        otherCertificate.getPublicKey().getEncoded())) {
      return false;
    }

    if (authorityKeyIdentifier == null) {
      if (otherCertificate.getAuthorityKeyIdentifier() != null) {
        return false;
      }
    } else if (!authorityKeyIdentifier.equals(otherCertificate.getAuthorityKeyIdentifier())) {
      return false;
    }

    if (!Arrays.equals(subjectKeyIdentifier, otherCertificate.getSubjectKeyIdentifier())) {
      return false;
    }

    if (keyUsage == null) {
      if (otherCertificate.getKeyUsage() != null) {
        return false;
      }
    } else if (!keyUsage.equals(otherCertificate.getKeyUsage())) {
      return false;
    }

    if (basicConstraints == null) {
      if (otherCertificate.getBasicConstraints() != null) {
        return false;
      }
    } else if (!basicConstraints.equals(otherCertificate.getBasicConstraints())) {
      return false;
    }

    if (certificatePolicy == null) {
      if (otherCertificate.getCertificatePolicy() != null) {
        return false;
      }
    } else if (!certificatePolicy.equals(otherCertificate.getCertificatePolicy())) {
      return false;
    }

    if (subjectAlternativeName == null) {
      if (otherCertificate.getSubjectAlternativeName() != null) {
        return false;
      }
    } else if (!subjectAlternativeName.equals(otherCertificate.getSubjectAlternativeName())) {
      return false;
    }

    if (issuerAlternativeName == null) {
      if (otherCertificate.getIssuerAlternativeName() != null) {
        return false;
      }
    } else if (!issuerAlternativeName.equals(otherCertificate.getIssuerAlternativeName())) {
      return false;
    }

    if (extendedKeyUsage == null) {
      if (otherCertificate.getExtendedKeyUsage() != null) {
        return false;
      }
    } else if (!extendedKeyUsage.equals(otherCertificate.getExtendedKeyUsage())) {
      return false;
    }

    if (authenticationInfoAccessOcsp == null) {
      if (otherCertificate.getAuthenticationInfoAccessOcsp() != null) {
        return false;
      }
    } else if (!authenticationInfoAccessOcsp
        .equals(otherCertificate.getAuthenticationInfoAccessOcsp())) {
      return false;
    }

    if (crlDistributionPointUri == null) {
      if (otherCertificate.getCrlDistributionPointUri() != null) {
        return false;
      }
    } else if (!crlDistributionPointUri.equals(otherCertificate.getCrlDistributionPointUri())) {
      return false;
    }

    if (extensions == null) {
      if (otherCertificate.extensions != null) {
        return false;
      }
    } else if (!extensions.equals(otherCertificate.extensions)) {
      return false;
    }

    if (!Arrays.equals(caCalcValue, otherCertificate.getCaCalcValue())) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 0;

    if (serialNumber != null) {
      for (byte b : serialNumber) {
        hashCode += 7 * (new Byte(b)).hashCode();
      }
    }

    if (caKeyDefinition != null) {
      hashCode += 13 * caKeyDefinition.hashCode();
    }

    if (issuer != null) {
      hashCode += 17 * issuer.hashCode();
    }

    if (validFrom != null) {
      hashCode += 19 * validFrom.hashCode();
    }

    if (validDuration != null) {
      hashCode += 23 * validDuration.hashCode();
    }

    if (subject != null) {
      hashCode += 29 * subject.hashCode();
    }

    if (publicKeyDefinition != null) {
      hashCode += 31 * publicKeyDefinition.hashCode();
    }

    if (publicKey != null) {
      for (byte b : publicKey.getEncoded()) {
        hashCode += 37 * (new Byte(b)).hashCode();
      }
    }

    if (authorityKeyIdentifier != null) {
      hashCode += 41 * authorityKeyIdentifier.hashCode();
    }

    if (subjectKeyIdentifier != null) {
      for (byte b : subjectKeyIdentifier) {
        hashCode += 43 * (new Byte(b)).hashCode();
      }
    }

    if (keyUsage != null) {
      hashCode += 47 * keyUsage.hashCode();
    }

    if (basicConstraints != null) {
      hashCode += 53 * basicConstraints.hashCode();
    }

    if (certificatePolicy != null) {
      hashCode += 59 * certificatePolicy.hashCode();
    }

    if (subjectAlternativeName != null) {
      hashCode += 61 * subjectAlternativeName.hashCode();
    }

    if (issuerAlternativeName != null) {
      hashCode += 67 * issuerAlternativeName.hashCode();
    }

    if (extendedKeyUsage != null) {
      hashCode += 71 * extendedKeyUsage.hashCode();
    }

    if (authenticationInfoAccessOcsp != null) {
      hashCode += 73 * authenticationInfoAccessOcsp.hashCode();
    }

    if (crlDistributionPointUri != null) {
      hashCode += 79 * crlDistributionPointUri.hashCode();
    }

    if (extensions != null) {
      for (Extension ext : extensions) {
        hashCode += 83 * ext.hashCode();
      }
    }

    if (caCalcValue != null) {
      for (byte b : caCalcValue) {
        hashCode += 97 * (new Byte(b)).hashCode();
      }
    }

    return hashCode;
  }

  /**
   * Returns true if the to-be-signed (TBS) certificate fields are valid. This method only checks
   * basic formatting constraints on the fields and any mandatory/optional constraints. The validity
   * of the data stored in these fields would normally be checked by a Certificate Authority (CA)
   * when processing a certificate signing request (CSR).
   *
   * @return Returns true if the TBS certificate fields are valid.
   */
  private boolean isTbsCertificateValid() {
    if ((serialNumber == null) || (serialNumber.length < 1) || (serialNumber.length > 20)) {
      return false;
    }

    if ((caKeyDefinition != null) && (!caKeyDefinition.isValid())) {
      return false;
    }

    if ((issuer != null) && (!issuer.isValid())) {
      return false;
    }

    byte[] testBytes;

    if (validFrom != null) {
      testBytes = BigInteger.valueOf(validFrom.getTime() / 1000).toByteArray();

      if ((testBytes.length < 4) || (testBytes.length > 5)) {
        return false;
      }
    }

    if (validDuration != null) {
      if (validFrom == null) {
        return false;
      }

      testBytes = BigInteger.valueOf(validDuration.intValue()).toByteArray();

      if ((testBytes.length < 1) || (testBytes.length > 4)) {
        return false;
      }
    }

    if ((subject == null) || (!subject.isValid())) {
      return false;
    }

    if ((publicKeyDefinition != null) && (!publicKeyDefinition.isValid())) {
      return false;
    }

    if ((authorityKeyIdentifier != null) && (!authorityKeyIdentifier.isValid())) {
      return false;
    }

    if ((basicConstraints != null)
        && ((basicConstraints.intValue() < 1) || (basicConstraints.intValue() > 7))) {
      return false;
    }

    if ((certificatePolicy != null) && (!ValidationUtils.isValidOid(certificatePolicy))) {
      return false;
    }

    if ((subjectAlternativeName != null) && (!subjectAlternativeName.isValid())) {
      return false;
    }

    if ((issuerAlternativeName != null) && (!issuerAlternativeName.isValid())) {
      return false;
    }

    if ((extendedKeyUsage != null) && (!ValidationUtils.isValidOid(extendedKeyUsage))) {
      return false;
    }

    return true;
  }

  /**
   * Returns true if the certificate fields are valid. This method only checks basic formatting
   * constraints on the fields and any mandatory/optional constraints. The validity of the data
   * stored in these fields would normally be checked by a Certificate Authority (CA) when
   * processing a certificate signing request (CSR).
   *
   * @return Returns true if the certificate fields are valid.
   */
  public boolean isValid() {
    return (isTbsCertificateValid() && (caCalcValue != null));
  }

  /**
   * Returns the set of extensions defined for this instance that are or are not marked as critical.
   *
   * @param isCritical If true, then the set of extensions defined for this instance that are marked
   *        critical are returned. If false, then the set of extensions marked non-critical are
   *        returned.
   * @return The set of extensions that are or are not marked as critical as appropriate.
   */
  private Set<String> getExtensionOids(boolean isCritical) {
    HashSet<String> oids = new HashSet<String>();

    for (Extension ext : extensions) {
      if (ext.isCritical == isCritical) {
        oids.add(ext.oid);
      }
    }

    return oids;
  }

  /**
   * Checks if this certificate is ECQV based. Throws an exception if it is not.
   *
   * @throws NoSuchAlgorithmException if this certificate is not ECQV based.
   */
  private void checkIfEcqvCertificate() throws NoSuchAlgorithmException {
    if (caKeyDefinition != null) {
      if (caKeyDefinition.getAlgorithm() != null) {
        try {
          if (!SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid()).isEcqv()) {
            throw new NoSuchAlgorithmException("This is not an ECQV certificate.");
          }

          // At this point we know that this in an ECQV certificate.
        } catch (IllegalArgumentException ex) {
          throw new NoSuchAlgorithmException("Unknown signature algorithm.");
        }
      } else {
        throw new NoSuchAlgorithmException("CA signature algorithm not defined.");
      }
    } else {
      throw new NoSuchAlgorithmException("CA signature algorithm not defined.");
    }
  }
}
