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
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

/**
 * <p>
 * Represents the definition of a key algorithm. It contains the OID of the algorithm and any
 * parameter data needed for using that algorithm with a given key pair. For example the parameter
 * data might be a curve point for and ECC key pair.
 * </p>
 *
 * <p>
 * Note that this object does not represent a distinct ASN.1 object, but rather is an abstraction
 * that is used to represent fields in an ASN.1 sequence such as the TBSCertificate in the M2M spec.
 * </p>
 */
public class KeyAlgorithmDefinition {
  private SignatureAlgorithmOids algorithm;
  private byte[] parameters;

  /**
   * Creates a new instance.
   */
  public KeyAlgorithmDefinition() {
    algorithm = null;
    parameters = null;
  }

  /**
   * Creates a new instance.
   *
   * @param algorithm Signature algorithm.
   * @param parameters Algorithm parameters.
   */
  public KeyAlgorithmDefinition(SignatureAlgorithmOids algorithm, byte[] parameters) {
    this.algorithm = algorithm;
    this.parameters = parameters;
  }

  public SignatureAlgorithmOids getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(SignatureAlgorithmOids algorithm) {
    this.algorithm = algorithm;
  }

  public byte[] getParameters() {
    return parameters;
  }

  public void setParameters(byte[] parameters) {
    this.parameters = parameters;
  }

  /**
   * Returns the DER encoding of the signature algorithm OID.
   *
   * @return The DER encoding of the signature algorithm OID.
   * @throws IOException if the signature algorithm OID cannot be encoded.
   */
  public byte[] getEncodedAlgorithm() throws IOException {
    if (algorithm == null) {
      throw new IOException("algorithm must be defined.");
    }

    return ((new ASN1ObjectIdentifier(algorithm.getOid())).getEncoded());
  }

  /**
   * Returns the DER encoding of the signature parameters.
   *
   * @return The DER encoding of the signature parameters.
   * @throws IOException if the signature parameters cannot be encoded.
   */
  public byte[] getEncodedParameters() throws IOException {
    if (parameters == null) {
      throw new IOException("parameters must be defined.");
    }

    return ((new DEROctetString(parameters)).getEncoded());
  }

  /**
   * Returns true if this instance is valid.
   *
   * @return True if this instance is valid.
   */
  public boolean isValid() {
    return (algorithm != null);
  }

  /**
   * Returns the string representation of the signature algorithm OID.
   *
   * @return The string representation of the signature algorithm OID.
   */
  public String toStringAlgorithm() {
    if (algorithm != null) {
      return ("OBJECT IDENTIFIER: " + algorithm.getOid());
    }

    return null;
  }

  /**
   * Returns the string representation of the signature algorithm parameters.
   *
   * @return The string representation of the signature algorithm parameters.
   */
  public String toStringParameters() {
    if (algorithm != null) {
      return ("OCTET STRING: " + Hex.toHexString(parameters));
    }

    return null;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    } else if (!(obj instanceof KeyAlgorithmDefinition)) {
      return false;
    }

    KeyAlgorithmDefinition other = (KeyAlgorithmDefinition) obj;

    if (algorithm != other.algorithm) {
      return false;
    }

    if (!Arrays.equals(parameters, other.parameters)) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashcode = 0;

    if (algorithm != null) {
      hashcode = 7 * algorithm.hashCode();
    }

    if (parameters != null) {
      for (byte b : parameters) {
        hashcode += 31 * (new Byte(b)).hashCode();
      }
    }

    return (hashcode);
  }
}
