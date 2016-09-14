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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;

import ca.trustpoint.m2m.util.FormattingUtils;

/**
 * Represents the permitted usages (as defined in the M2M specification) for a key pair. See RFC
 * 5280 section 4.2.1.3 for more details regarding the values here.
 */
public class KeyUsage {
  /**
   * The digitalSignature bit is asserted when the subject public key is used for verifying digital
   * signatures, other than signatures on certificates (bit 5) and CRLs (bit 6), such as those used
   * in an entity authentication service, a data origin authentication service, and/or an integrity
   * service.
   */
  public static final byte DIGITAL_SIGNATURE = (byte) 0x80;

  /**
   * The nonRepudiation bit is asserted when the subject public key is used to verify digital
   * signatures, other than signatures on certificates (bit 5) and CRLs (bit 6), used to provide a
   * non-repudiation service that protects against the signing entity falsely denying some action.
   * In the case of later conflict, a reliable third party may determine the authenticity of the
   * signed data. (Note that recent editions of X.509 have renamed the nonRepudiation bit to
   * contentCommitment.)
   */
  public static final byte NON_REPUDIATION = 0x40;

  /**
   * The keyEncipherment bit is asserted when the subject public key is used for enciphering private
   * or secret keys, i.e., for key transport. For example, this bit shall be set when an RSA public
   * key is to be used for encrypting a symmetric content-decryption key or an asymmetric private
   * key.
   */
  public static final byte KEY_ENCIPHERMENT = 0x20;

  /**
   * The dataEncipherment bit is asserted when the subject public key is used for directly
   * enciphering raw user data without the use of an intermediate symmetric cipher. Note that the
   * use of this bit is extremely uncommon; almost all applications use key transport or key
   * agreement to establish a symmetric key.
   */
  public static final byte DATA_ENCIPHERMENT = 0x10;

  /**
   * The keyAgreement bit is asserted when the subject public key is used for key agreement. For
   * example, when a Diffie-Hellman key is to be used for key management, then this bit is set.
   */
  public static final byte KEY_AGREEMENT = 0x08;

  /**
   * The keyCertSign bit is asserted when the subject public key is used for verifying signatures on
   * public key certificates. If the keyCertSign bit is asserted, then the cA bit in the basic
   * constraints extension (RFC 5280 Section 4.2.1.9) MUST also be asserted.
   */
  public static final byte KEY_CERT_SIGN = 0x04;

  /**
   * The cRLSign bit is asserted when the subject public key is used for verifying signatures on
   * certificate revocation lists (e.g., CRLs, delta CRLs, or ARLs).
   */
  public static final byte CRL_SIGN = 0x02;

  private byte value;

  /**
   * Create a new instance with all flags cleared.
   */
  public KeyUsage() {
    value = 0;
  }

  /**
   * Create a new instance with the given flags set.
   *
   * @param digitalSignature True if the digitalSignature bit should be set.
   * @param nonRepudiation True if the nonRepudiation bit should be set.
   * @param keyEncipherment True if the keyEncipherment bit should be set.
   * @param dataEncipherment True if the dataEncipherment bit should be set.
   * @param keyAgreement True if the keyAgreement bit should be set.
   * @param keyCertSign True if the keyCertSign bit should be set.
   * @param crlSign True if the cRLSign bit should be set.
   */
  public KeyUsage(boolean digitalSignature, boolean nonRepudiation, boolean keyEncipherment,
      boolean dataEncipherment, boolean keyAgreement, boolean keyCertSign, boolean crlSign) {
    this();

    if (digitalSignature) {
      value |= DIGITAL_SIGNATURE;
    }

    if (nonRepudiation) {
      value |= NON_REPUDIATION;
    }

    if (keyEncipherment) {
      value |= KEY_ENCIPHERMENT;
    }

    if (dataEncipherment) {
      value |= DATA_ENCIPHERMENT;
    }

    if (keyAgreement) {
      value |= KEY_AGREEMENT;
    }

    if (keyCertSign) {
      value |= KEY_CERT_SIGN;
    }

    if (crlSign) {
      value |= CRL_SIGN;
    }
  }

  /**
   * Create a new instance that matches the given flags.
   *
   * @param usage Flags to set.
   * @throws IllegalArgumentException if the given flags are not valid.
   */
  public KeyUsage(byte usage) throws IllegalArgumentException {
    if (!isValidKeyUsageByte(usage)) {
      throw new IllegalArgumentException("usage must be a valid value.");
    }

    value = usage;
  }

  /**
   * Create a new instance from the given ASN.1 octet string.
   *
   * @param octets ASN.1 octet string to parse.
   * @throws IllegalArgumentException if the given octet string is not valid.
   */
  public KeyUsage(byte[] octets) throws IllegalArgumentException {
    ASN1OctetString octetString = ASN1OctetString.getInstance(octets);
    byte[] contentBytes = octetString.getOctets();

    if (contentBytes.length != 1) {
      throw new IllegalArgumentException("octets is not a valid keyUsage value.");
    }

    if (!isValidKeyUsageByte(contentBytes[0])) {
      throw new IllegalArgumentException("octets is not a valid keyUsage value.");
    }

    value = contentBytes[0];
  }

  public boolean getDigitalSignature() {
    return ((value & DIGITAL_SIGNATURE) != 0);
  }

  public void setDigitalSignature(boolean digitalSignature) {
    if (digitalSignature) {
      value |= DIGITAL_SIGNATURE;
    } else {
      value &= (0xFF & (~DIGITAL_SIGNATURE));
    }
  }

  public boolean getNonRepudiation() {
    return ((value & NON_REPUDIATION) != 0);
  }

  public void setNonRepudiation(boolean nonRepudiation) {
    if (nonRepudiation) {
      value |= NON_REPUDIATION;
    } else {
      value &= (0xFF & (~NON_REPUDIATION));
    }
  }

  public boolean getKeyEncipherment() {
    return ((value & KEY_ENCIPHERMENT) != 0);
  }

  public void setKeyEncipherment(boolean keyEncipherment) {
    if (keyEncipherment) {
      value |= KEY_ENCIPHERMENT;
    } else {
      value &= (0xFF & (~KEY_ENCIPHERMENT));
    }
  }

  public boolean getDataEncipherment() {
    return ((value & DATA_ENCIPHERMENT) != 0);
  }

  public void setDataEncipherment(boolean dataEncipherment) {
    if (dataEncipherment) {
      value |= DATA_ENCIPHERMENT;
    } else {
      value &= (0xFF & (~DATA_ENCIPHERMENT));
    }
  }

  public boolean getKeyAgreement() {
    return ((value & KEY_AGREEMENT) != 0);
  }

  public void setKeyAgreement(boolean keyAgreement) {
    if (keyAgreement) {
      value |= KEY_AGREEMENT;
    } else {
      value &= (0xFF & (~KEY_AGREEMENT));
    }
  }

  public boolean getKeyCertSign() {
    return ((value & KEY_CERT_SIGN) != 0);
  }

  public void setKeyCertSign(boolean keyCertSign) {
    if (keyCertSign) {
      value |= KEY_CERT_SIGN;
    } else {
      value &= (0xFF & (~KEY_CERT_SIGN));
    }
  }

  public boolean getCrlSign() {
    return ((value & CRL_SIGN) != 0);
  }

  public void setCrlSign(boolean crlSign) {
    if (crlSign) {
      value |= CRL_SIGN;
    } else {
      value &= (0xFF & (~CRL_SIGN));
    }
  }

  /**
   * Returns the DER encoding of this instance.
   *
   * @return The DER encoding of this instance.
   */
  public byte[] getEncoded() throws IOException {
    return (new DEROctetString(new byte[] {value}).getEncoded());
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

    FormattingUtils.indent(buffer, depth).append("KeyUsage BIT STRING {").append(LINE_SEPARATOR);

    if (getDigitalSignature()) {
      FormattingUtils.indent(buffer, depth + 1).append("digitalSignature,").append(LINE_SEPARATOR);
    }

    if (getNonRepudiation()) {
      FormattingUtils.indent(buffer, depth + 1).append("nonRepudiation,").append(LINE_SEPARATOR);
    }

    if (getKeyEncipherment()) {
      FormattingUtils.indent(buffer, depth + 1).append("keyEncipherment,").append(LINE_SEPARATOR);
    }

    if (getDataEncipherment()) {
      FormattingUtils.indent(buffer, depth + 1).append("dataEncipherment,").append(LINE_SEPARATOR);
    }

    if (getKeyAgreement()) {
      FormattingUtils.indent(buffer, depth + 1).append("keyAgreement,").append(LINE_SEPARATOR);
    }

    if (getKeyCertSign()) {
      FormattingUtils.indent(buffer, depth + 1).append("keyCertSign,").append(LINE_SEPARATOR);
    }

    if (getCrlSign()) {
      FormattingUtils.indent(buffer, depth + 1).append("cRLSign,").append(LINE_SEPARATOR);
    }

    FormattingUtils.indent(buffer, depth).append("}").append(LINE_SEPARATOR);

    return buffer.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (obj instanceof KeyUsage) {
      KeyUsage other = (KeyUsage) obj;

      return (value == other.value);
    } else {
      return false;
    }
  }

  @Override
  public int hashCode() {
    return (new Byte(value).hashCode());
  }

  /**
   * Tests if the given byte represents a valid KeyUsage value.
   *
   * @param keyUsage Value to test.
   * @return True if the given byte represents a valid KeyUsage value.
   */
  private static boolean isValidKeyUsageByte(byte keyUsage) {
    // The least significant bit should not be set, so test if it is.
    return ((keyUsage & ((byte) ~(DIGITAL_SIGNATURE | NON_REPUDIATION | KEY_ENCIPHERMENT
        | DATA_ENCIPHERMENT | KEY_AGREEMENT | KEY_CERT_SIGN | CRL_SIGN))) == 0);
  }
}
