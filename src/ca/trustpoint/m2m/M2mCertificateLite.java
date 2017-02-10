/*
 * Copyright (C) 2016 TrustPoint Innovation Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ca.trustpoint.m2m;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import javax.security.auth.x500.X500Principal;

/**
 * An ASN.1 Encodable Object representing an M2mCertificateLite object
 *
 * This file is typically not used to build certificates.
 *
 * Normally you would use the M2MCertificate to set all the individual fields and then create a
 * M2MCertificateLite.
 */
public class M2mCertificateLite extends Certificate {
    private byte[] encoded;
    private byte[] tbsEncoded;
    private byte[] signature;
    private X500Principal issuer;
    private String stringCert;
    private String sigAlgorithmBcName;
    private String sigAlgorithmOid;
    private byte[] sigParameters;
    private String sigProvider;
    private PublicKey pubKey;
    private PublicKey reconstructedPubKey = null;
    private boolean isEcqvCertificate;

    /**
     * Create a M2mCertificateLite object.
     */
    M2mCertificateLite() {
        super("M2M");
        encoded = null;
        tbsEncoded = null;
        signature = null;
        issuer = null;
        stringCert = null;
        sigAlgorithmBcName = null;
        sigAlgorithmOid = null;
        sigParameters = null;
        sigProvider = null;
        pubKey = null;
        isEcqvCertificate = false;
    }

    /**
     * Returns the encoded form of this certificate. It is assumed that each certificate type would
     * have only a single form of encoding; for example, X.509 certificates would be encoded as
     * ASN.1 DER.
     *
     * @return the encoded form of this certificate.
     *
     * @exception CertificateEncodingException if an encoding error occurs.
     */
    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        if (encoded == null) {
            throw new CertificateEncodingException("encoded certificate is null.");
        }
        return encoded;
    }

    /**
     * Sets encoded certificate by M2mCertificate.
     *
     * @param encoded Encoded M2mCertificate.
     */
    void setEncoded(byte[] encoded) {
        this.encoded = encoded;
    }

    /**
     * Sets encoded TBS certificate by M2MCertificate.
     *
     * @param tbsEncoded Encoded TBS M2MCertificate.
     */
    void setTbsEncoded(byte[] tbsEncoded) {
        this.tbsEncoded = tbsEncoded;
    }

    /**
     * Sets certificate signature.
     *
     * @param signature The signature of this certificate.
     */
    void setSignature(byte[] signature) {
        this.signature = signature;
    }

    /**
     * Sets X500Principal encoded issuer of this certificate.
     *
     * @param issuer X500Principal encoded issuer of this certificate.
     */
    void setIssuerX500Principal(X500Principal issuer) {
        this.issuer = issuer;
    }

    /**
     * Returns the issuer (issuer distinguished name) value from the
     * certificate as an {@code X500Principal}.
     * <p>
     * It is recommended that subclasses override this method.
     *
     * @return an {@code X500Principal} representing the issuer
     *         distinguished name
     * @since 1.4
     */
    public X500Principal getIssuerX500Principal() {
        return issuer;
    }

    /**
     * Sets the Bouncy Castle name of signature algorithm.
     *
     * @param sigAlgorithmBcName The Bouncy Castle name of signature algorithm.
     */
    void setSignatureAlogorithmBcName(String sigAlgorithmBcName) {
        this.sigAlgorithmBcName = sigAlgorithmBcName;
    }

    /**
     * Sets the OID of signature algorithm.
     *
     * @param sigAlgorithmOid The OID of signature algorithm.
     */
    void setSignatureAlogorithmOid(String sigAlgorithmOid) {
        this.sigAlgorithmOid = sigAlgorithmOid;
    }

    /**
     * Sets the parameters of signature.
     *
     * @param sigParameters The parameters of signature.
     */
    void setSignatureParameters(byte[] sigParameters) {
        this.sigParameters = sigParameters;
    }

    /**
     * Sets the name of signature provider.
     *
     * @param sigProvider The name of signature provider.
     */
    void setSignatureProvider(String sigProvider) {
        this.sigProvider = sigProvider;
    }

    /**
     * Gets the public key from this certificate.
     *
     * @return the public key.
     */
    @Override
    public PublicKey getPublicKey() {
        return ((pubKey != null) ? pubKey : reconstructedPubKey);
    }

    /**
     * Sets M2M certificate public key.
     *
     * @param pubKey M2M certificate public key.
     */
    void setPublicKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    /**
     * Sets a flag to show if the M2M certificate is an ECQV certificate or not.
     *
     * @param isEcqvCertificate True if the certificate is an ECQV certificate, false otherwise.
     */
    void setIsEcqvCertificate(boolean isEcqvCertificate) {
        this.isEcqvCertificate = isEcqvCertificate;
    }

    /**
     * Sets string M2mCertificate by M2mCertificate.
     *
     * @param stringCert A string representing of the M2MCertificate.
     */
    void setStringCert(String stringCert) {
        this.stringCert = stringCert;
    }

    /**
     * Verifies that this certificate was signed using the private key that corresponds to the
     * specified public key.
     *
     * @param key The PublicKey used to carry out the verification.
     *
     * @exception NoSuchAlgorithmException on unsupported signature algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @Override
    public void verify(PublicKey key)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException {
        verify(key, sigProvider);
    }

    /**
     * Verifies that this certificate was signed using the private key that corresponds to the
     * specified public key. This method uses the signature verification engine supplied by the
     * specified provider.
     *
     * @param key The PublicKey used to carry out the verification.
     * @param sigProvider The name of the signature provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @Override
    public void verify(PublicKey key, String sigProvider)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException {
        if (tbsEncoded == null) {
            throw new CertificateException("encoded certificate is null.");
        }

        if (isEcqvCertificate) {
            // For ECQV certificate, the signature data is a combination of TBS certificate hash and
            // public key, so the verification is done by reconstructing publickey from signaure
            // data and TBS certificate data.
            try {
                Class c = Class.forName("com.android.ca.trustpoint.m2m.ecqv.EcqvProvider");
                Constructor cons = c.getConstructor(String.class, byte[].class);
                Object o = cons.newInstance(sigAlgorithmOid, sigParameters);
                Method m = c.getDeclaredMethod(
                        "reconstructPublicKey", byte[].class, byte[].class, PublicKey.class);
                reconstructedPubKey = (PublicKey)m.invoke(o, tbsEncoded, signature, key);
            } catch (Exception e) {
                throw new SignatureException("invalid signature");
            }
        } else {
            Signature engine = null;
            try {
                engine = Signature.getInstance(sigAlgorithmBcName, sigProvider);
            } catch (Exception e) {
                engine = Signature.getInstance(sigAlgorithmBcName);
            }

            engine.initVerify(key);
            engine.update(tbsEncoded);
            if (!engine.verify(signature)) {
                throw new SignatureException("invalid signature");
            }
        }
    }

    /**
     * Returns a string representation of this certificate.
     *
     * @return a string representation of this certificate.
     */
    @Override
    public String toString() {
        return stringCert;
    }
}
