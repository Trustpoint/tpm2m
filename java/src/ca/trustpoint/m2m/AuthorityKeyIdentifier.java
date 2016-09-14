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
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;

import ca.trustpoint.m2m.util.FormattingUtils;

/**
 * Represents an AuthKeyId object. It is defined in the M2M spec as:
 *
 * <pre>
 *  AuthKeyId ::= SEQUENCE {
 *      keyIdentifier      OCTET STRING OPTIONAL,
 *      authCertIssuer     GeneralName OPTIONAL,
 *      authCertSerialNum  OCTET STRING (SIZE(1..20)) OPTIONAL
 *  }
 * </pre>
 */
public class AuthorityKeyIdentifier {
  // Index Constants
  public static final int INDEX_KEY_IDENTIFIER = 0;
  public static final int INDEX_AUTH_CERT_ISSUER = 1;
  public static final int INDEX_AUTH_CERT_SERIAL_NUM = 2;

  private byte[] keyIdentifier;
  private GeneralName certificateIssuer;
  private BigInteger certificateSerialNumber;

  /**
   * Creates a new empty instance.
   */
  public AuthorityKeyIdentifier() {
    keyIdentifier = null;
    certificateIssuer = null;
    certificateSerialNumber = null;
  }

  /**
   * Creates a new instance with the given values.
   *
   * @param keyIdentifier Identifier of the public key used to sign this certificate.
   * @param certificateIssuer Name of the certificate issuer.
   * @param certificateSerialNumber Serial number of the issuer certificate.
   */
  public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralName certificateIssuer,
      BigInteger certificateSerialNumber) {
    this.keyIdentifier = keyIdentifier;
    this.certificateIssuer = certificateIssuer;
    this.certificateSerialNumber = certificateSerialNumber;
  }

  public byte[] getKeyIdentifier() {
    return keyIdentifier;
  }

  public void setKeyIdentifier(byte[] identifier) {
    keyIdentifier = identifier;
  }

  public GeneralName getCertificateIssuer() {
    return certificateIssuer;
  }

  public void setCertificateIssuer(GeneralName issuer) {
    certificateIssuer = issuer;
  }

  public BigInteger getCertificateSerialNumber() {
    return certificateSerialNumber;
  }

  public void setCertificateSerialNumber(BigInteger serialNumber) {
    certificateSerialNumber = serialNumber;
  }

  /**
   * Returns true if the current instance is a valid AuthKeyId object.
   *
   * @return True if the current instance is a valid AuthKeyId object.
   */
  public boolean isValid() {
    boolean valid = true;

    if ((keyIdentifier == null) && (certificateIssuer == null)
        && (certificateSerialNumber == null)) {
      valid = false;
    } else if ((keyIdentifier != null) && (keyIdentifier.length == 0)) {
      valid = false;
    } else if ((certificateIssuer != null) && (!certificateIssuer.isValid())) {
      valid = false;
    } else if (certificateSerialNumber != null) {
      byte[] serialNumberBytes = certificateSerialNumber.toByteArray();

      if ((serialNumberBytes.length < 1) || (serialNumberBytes.length > 20)) {
        valid = false;
      }
    }

    return valid;
  }

  /**
   * Returns the DER encoding of this instance.
   *
   * @return The DER encoding of this instance.
   * @throws IOException if this instance cannot be encoded.
   */
  public byte[] getEncoded() throws IOException {
    if (!isValid()) {
      throw new IOException("AuthKeyId is not valid.");
    }

    ASN1EncodableVector values = new ASN1EncodableVector();

    if (keyIdentifier != null) {
      DEROctetString idOctets = new DEROctetString(keyIdentifier);
      values.add(new DERTaggedObject(false, INDEX_KEY_IDENTIFIER, idOctets));
    }

    if (certificateIssuer != null) {
      ASN1TaggedObject encodedIssuer = DERTaggedObject.getInstance(certificateIssuer.getEncoded());
      values.add(new DERTaggedObject(true, INDEX_AUTH_CERT_ISSUER, encodedIssuer));
    }

    if (certificateSerialNumber != null) {
      DEROctetString serialOctets = new DEROctetString(certificateSerialNumber.toByteArray());
      values.add(new DERTaggedObject(false, INDEX_AUTH_CERT_SERIAL_NUM, serialOctets));
    }

    return (new DERSequence(values).getEncoded());
  }

  @Override
  public String toString() {
    return (toString(0));
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

    FormattingUtils.indent(buffer, depth).append("AuthKeyId SEQUENCE {").append(LINE_SEPARATOR);

    if (keyIdentifier != null) {
      FormattingUtils.indent(buffer, depth + 1).append("[0] keyIdentifier OCTET STRING: ");
      buffer.append(Hex.toHexString(keyIdentifier)).append(LINE_SEPARATOR);
    }

    if (certificateIssuer != null) {
      FormattingUtils.indent(buffer, depth + 1).append("[1] authCertIssuer GeneralName: ")
          .append(LINE_SEPARATOR);
      buffer.append(certificateIssuer.toString(depth + 2));
    }

    if (certificateSerialNumber != null) {
      FormattingUtils.indent(buffer, depth + 1).append("[2] authCertSerialNum OCTET STRING: ");
      buffer.append(Hex.toHexString(certificateSerialNumber.toByteArray())).append(LINE_SEPARATOR);
    }

    FormattingUtils.indent(buffer, depth).append("}").append(LINE_SEPARATOR);

    return buffer.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (!(obj instanceof AuthorityKeyIdentifier)) {
      return false;
    }

    AuthorityKeyIdentifier other = (AuthorityKeyIdentifier) obj;

    if (!Arrays.equals(keyIdentifier, other.getKeyIdentifier())) {
      return false;
    }

    if (certificateIssuer == null) {
      if (other.getCertificateIssuer() != null) {
        return false;
      }
    } else if (!certificateIssuer.equals(other.getCertificateIssuer())) {
      return false;
    }

    if (certificateSerialNumber == null) {
      if (other.getCertificateSerialNumber() != null) {
        return false;
      }
    } else if (!certificateSerialNumber.equals(other.getCertificateSerialNumber())) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 0;

    if (keyIdentifier != null) {
      for (byte b : keyIdentifier) {
        hashCode += 7 * (new Byte(b)).hashCode();
      }
    }

    if (certificateIssuer != null) {
      hashCode += 31 * certificateIssuer.hashCode();
    }

    if (certificateSerialNumber != null) {
      hashCode += 57 * certificateSerialNumber.hashCode();
    }

    return hashCode;
  }
}
