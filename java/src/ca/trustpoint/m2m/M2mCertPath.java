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
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;

/**
 * A {@link java.security.cert.CertPath CertPath} (certification path) consisting exclusively of
 * {@link ca.trustpoint.m2m.M2mCertificate M2MCertificate}s.
 * <p>
 * By convention, M2M {@link java.security.cert.CertPath CertPath}s are stored from target to trust
 * anchor. That is, the issuer of one certificate is the subject of the following one. However,
 * unvalidated M2M {@link java.security.cert.CertPath CertPath}s may not follow this convention.
 * PKIX {@link java.security.cert.CertPathValidator CertPathValidator}s will detect any departure
 * from this convention and throw a {@link java.security.cert.CertPathValidatorException
 * CertPathValidatorException}.
 *
 * @see CertPath
 * @see M2mCertificate
 */
public class M2mCertPath extends CertPath {
  /**
   * List of supported certificate path encodings.
   */
  public static enum SupportedEncodings {
    /** Order from root to signer */
    PKIPATH("PkiPath"),

    /** Order from signer to root */
    PKCS7("PKCS7");

    /**
     * List of the supported encoding values. This is needed for the
     * {@link java.security.cert.CertPath CertPath} interface. We construct this statically to save
     * work.
     */
    private static final List<String> VALUES;

    static {
      SupportedEncodings[] encodings = SupportedEncodings.values();
      List<String> values = new ArrayList<String>(encodings.length);

      for (SupportedEncodings encoding : encodings) {
        values.add(encoding.getId());
      }

      VALUES = Collections.unmodifiableList(values);
    }

    private final String id;

    SupportedEncodings(String id) {
      this.id = id;
    }

    public String getId() {
      return id;
    }

    public static List<String> getSupportedEncodings() {
      return (VALUES);
    }

    /**
     * Returns the enumeration value corresponding to the given ID string.
     *
     * @param id ID string of the desired enumeration member.
     * @return The enumeration value corresponding to the given ID string.
     * @throws IllegalArgumentException If the given ID string does not match an enumeration value.
     */
    public static SupportedEncodings getInstance(String id) throws IllegalArgumentException {
      if (PKIPATH.getId().equals(id)) {
        return PKIPATH;
      } else if (PKCS7.getId().equals(id)) {
        return PKCS7;
      } else {
        throw new IllegalArgumentException("Unknown encoding " + id);
      }
    }
  }

  private static final long serialVersionUID = 2L;

  /**
   * List of certificates in this chain stored in order of from signer to root.
   */
  private final List<M2mCertificate> certificates;

  /**
   * Creates a new instance containing the given list of certificates. Certificates should be
   * ordered from end entity to trust anchor. (Partial paths are acceptable.) The list provided
   * should only contain {@link M2mCertificate M2MCertificate} objects. Duplicates are not permitted
   * within the chain.
   *
   * @param certificates List of certificates to include in the chain.
   * @throws IllegalArgumentException If the provided list is null or contains
   *         non-{@link M2mCertificate M2MCertificate} objects.
   */
  public M2mCertPath(List<? extends Certificate> certificates) throws IllegalArgumentException {
    // Replace the hardcoded "M2M" with the type constant in M2MCertificate
    super("M2M");

    if (certificates == null) {
      throw new IllegalArgumentException("certificates cannot be null.");
    }

    ArrayList<M2mCertificate> castedList = new ArrayList<M2mCertificate>(certificates.size());

    for (Certificate c : certificates) {
      if (!(c instanceof M2mCertificate)) {
        throw new IllegalArgumentException("Only M2MCertificate objects are supported.");
      }

      castedList.add((M2mCertificate) c);
    }

    // The resulting List is thread-safe because it cannot be modified after construction and
    // the methods in the Sun JDK 1.4 implementation of ArrayList that allow read-only access
    // are thread-safe.
    this.certificates = Collections.unmodifiableList(castedList);
  }

  /**
   * Returns the encoded form of this certification path, using the default encoding.
   *
   * @return the encoded bytes
   * @exception CertificateEncodingException if an encoding error occurs
   */
  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    return getEncoded(SupportedEncodings.PKIPATH);
  }

  /**
   * Returns the encoded form of this certification path, using the specified encoding.
   *
   * @param encoding The name of the encoding to use
   * @return the encoded bytes
   * @exception CertificateEncodingException if an encoding error occurs or the encoding requested
   *            is not supported
   */
  @Override
  public byte[] getEncoded(String encoding) throws CertificateEncodingException {
    SupportedEncodings encodingValue;

    try {
      encodingValue = SupportedEncodings.getInstance(encoding);
    } catch (Exception ex) {
      throw new CertificateEncodingException("unsupported encoding: " + encoding, ex);
    }

    return getEncoded(encodingValue);
  }

  /**
   * Returns the encoded form of this certification path, using the specified encoding.
   *
   * @param encoding The encoding to use
   * @return the encoded bytes
   * @exception CertificateEncodingException if an encoding error occurs or the encoding requested
   *            is not supported
   */
  public byte[] getEncoded(SupportedEncodings encoding) throws CertificateEncodingException {
    switch (encoding) {
      case PKIPATH:
        return encodePkiPath();
      case PKCS7:
        return encodePkcs7();
      default:
        throw new CertificateEncodingException("unsupported encoding: " + encoding);
    }
  }

  /**
   * Encode the CertPath using PKIPATH format.
   *
   * @return a byte array containing the binary encoding of the PkiPath object
   * @exception CertificateEncodingException if an exception occurs
   */
  private byte[] encodePkiPath() throws CertificateEncodingException {
    ListIterator<M2mCertificate> li = certificates.listIterator(certificates.size());
    ASN1EncodableVector encodedList = new ASN1EncodableVector();

    // Get an encodable certificate vector. The certificates are encoded in reverse order (trust
    // anchor to target) according to PkiPath format.
    while (li.hasPrevious()) {
      M2mCertificate certificate = li.previous();

      if (isDuplicateCertificate(certificate)) {
        throw new CertificateEncodingException("Duplicate certificate detected in path.");
      }

      try {
        encodedList.add(ASN1Primitive.fromByteArray(certificate.getEncoded()));
      } catch (IOException ex) {
        throw new CertificateEncodingException("Error encoding certificate data.", ex);
      }
    }

    // Wrap the data in a SEQUENCE
    DERSequence sequence = new DERSequence(encodedList);

    try {
      return sequence.getEncoded();
    } catch (IOException ex) {
      throw new CertificateEncodingException("Error encoding certificate path.", ex);
    }
  }

  /**
   * Encode the CertPath using PKCS#7 format.
   *
   * @return a byte array containing the binary encoding of the PKCS#7 object
   * @exception CertificateEncodingException if an exception occurs
   */
  private byte[] encodePkcs7() throws CertificateEncodingException {
    ASN1EncodableVector encodedList = new ASN1EncodableVector();

    for (M2mCertificate certificate : certificates) {
      if (isDuplicateCertificate(certificate)) {
        throw new CertificateEncodingException("Duplicate certificate detected in path.");
      }

      try {
        encodedList.add(ASN1Primitive.fromByteArray(certificate.getEncoded()));
      } catch (IOException ex) {
        throw new CertificateEncodingException("Error encoding certificate data.", ex);
      }
    }

    SignedData sd = new SignedData(new ASN1Integer(BigInteger.ONE), // version
        new DERSet(), // digestAlgorithmIds
        new ContentInfo(PKCSObjectIdentifiers.data, null), // contentInfo
        new DERSet(encodedList), // certificates (optional)
        null, // CRLs (optional)
        new DERSet() // signerInfos
    );

    // make it a content info sequence
    ContentInfo ci = new ContentInfo(PKCSObjectIdentifiers.data, sd);

    try {
      return ci.getEncoded();
    } catch (IOException ex) {
      throw new CertificateEncodingException("Error encoding certificate path.", ex);
    }
  }

  /**
   * Checks if the given certificate has a duplicate in the certificate list.
   *
   * @param cert A M2MCertificate object for check.
   * @return True if there is a duplicated certificate in the certificate list and false if not.
   */
  private boolean isDuplicateCertificate(M2mCertificate cert) {
    // check for duplicate cert
    return (certificates.lastIndexOf(cert) != certificates.indexOf(cert));
  }

  /**
   * Returns an iteration of the encodings supported by this certification path, with the default
   * encoding first.
   * <p>
   * Attempts to modify the returned <code>Iterator</code> via its <code>remove</code> method result
   * in an <code>UnsupportedOperationException</code>.
   *
   * @return an <code>Iterator</code> over the names of the supported encodings (as Strings)
   */
  @Override
  public Iterator<String> getEncodings() {
    return (SupportedEncodings.getSupportedEncodings().iterator());
  }

  /**
   * Returns the list of certificates in this certification path. The <code>List</code> returned
   * must be immutable and thread-safe.
   *
   * @return an immutable <code>List</code> of <code>M2MCertificate</code>s (may be empty, but not
   *         null)
   */
  @Override
  public List<? extends Certificate> getCertificates() {
    return certificates;
  }
}
