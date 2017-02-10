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

package ca.trustpoint.m2m.ecqv;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import ca.trustpoint.m2m.SignatureAlgorithms;

/**
 * Provides functionality to support Elliptic Curve Qu-Vanstone (ECQV) key reconstruction.
 */
public class EcqvProvider {
    /** Random number generator to be used for key generation. */
    private static final SecureRandom random = new SecureRandom();

    private MessageDigest digest;
    private ECParameterSpec curveParameters;
    private AlgorithmIdentifier algorithmId;

    /**
     * Create a new instance.
     *
     * @param algorithm Required. Signature algorithm OID.
     * @param parameters Optional. Algorithm parameters. (not currently used)
     */
    public EcqvProvider(SignatureAlgorithms algorithm, byte[] parameters)
            throws IllegalArgumentException, UnsupportedOperationException,
            NoSuchAlgorithmException, NoSuchProviderException {
        if (algorithm == null) {
            throw new IllegalArgumentException("Missing algorithm OID");
        } else if (!algorithm.isEcqv()) {
            throw new UnsupportedOperationException(
                    "This provider can only be used with ECQV-based signature types");
        }

        X962Parameters x9params =
                new X962Parameters(new ASN1ObjectIdentifier(algorithm.getSecOid()));

        digest = MessageDigest.getInstance(
                algorithm.getDigestAlgorithm().getDigestName(), BouncyCastleProvider.PROVIDER_NAME);
        curveParameters =
                ECNamedCurveTable.getParameterSpec(
                        algorithm.getCryptoAlgorithm().getAlgorithmName());
        algorithmId =
                new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_ecPublicKey, x9params.toASN1Primitive());
    }

    /**
     * Create a new instance.
     *
     * @param algorithm Required. Signature algorithm OID.
     * @param parameters Optional. Algorithm parameters. (not currently used)
     */
    public EcqvProvider(String algorithmOid, byte[] parameters)
            throws IllegalArgumentException, UnsupportedOperationException,
            NoSuchAlgorithmException, NoSuchProviderException {
        this(SignatureAlgorithms.getInstance(algorithmOid), parameters);
    }

    /**
     * Generate reconstruction data for an implicit certificate In the terminology of sec4,
     * ephemeralPublicKey is referenced as Ru
     *
     * @param identifyingInfo the identity portion of the implicit certificate
     * @param ephemeralPublicKey the requesters ephemeral public key
     * @param issuerPrivateKey the issuers private key
     *
     * @return reconstruction data associated with the implicit certificate
     *
     * @throws NoSuchAlgorithmException From Bouncy Castle
     * @throws InvalidAlgorithmParameterException From Bouncy Castle
     * @throws NoSuchProviderException From Bouncy Castle
     * @throws IOException
     */
    public KeyReconstructionData genReconstructionData(
            byte[] identifyingInfo, PublicKey ephemeralPublicKey, PrivateKey issuerPrivateKey)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, IOException {
        // Reconstruction point, in point and byte format
        ECPoint p;
        byte[] reconstructionPoint;

        // CA's ephemeral key pair (k, kG)
        BCECPublicKey caEphemeralPublicKey;
        BCECPrivateKey caEphemeralPrivateKey;

        BigInteger n = curveParameters.getN(); // get the order of the curve group
        BigInteger r; // private key recovery data and CA ephemeral private key, respectively.
        BigInteger e; // Integer representation of H(Certu)
        BigInteger dCa = ((BCECPrivateKey) issuerPrivateKey).getD(); // Private key (point
                                                                     // multiplier) of the issuer.
        ECPoint infinity = curveParameters.getCurve().getInfinity(); // The identity point.

        do {
            // create ephemeral key pair (k, kG)
            KeyPairGenerator keyGen =
                    KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(curveParameters, random);

            KeyPair caEphemeralKeyPair = keyGen.generateKeyPair();
            caEphemeralPrivateKey = (BCECPrivateKey) caEphemeralKeyPair.getPrivate();
            caEphemeralPublicKey = (BCECPublicKey) caEphemeralKeyPair.getPublic();

            // Compute Pu = Ru + kG
            // this is the reconstruction point
            p = ((BCECPublicKey) ephemeralPublicKey).getQ().add(caEphemeralPublicKey.getQ());

            reconstructionPoint = p.getEncoded(true);

            // Update the digest with the implicit certificate Certu
            for (byte b : identifyingInfo) {
                digest.update(b);
            }

            // Update digest with reconstruction point data.
            for (byte b : reconstructionPoint) {
                digest.update(b);
            }

            // hash the implicit certificate Certu and compute the integer e from H(Certu)
            e = calculateE(n, digest.digest()).mod(n);

            // from sec4 S3.4
        } while (p.multiply(e).add(curveParameters.getG().multiply(dCa)).equals(infinity));

        // compute r = ek + dCA (mod n)
        r = e.multiply(caEphemeralPrivateKey.getD()).add(dCa).mod(n);

        return new KeyReconstructionData(reconstructionPoint, integerToOctetString(r, n));
    }

    /**
     * Reconstruct the public key from the implicit certificate and the CA's public key
     *
     * @param identifyingInfo the identity portion of the implicit certificate
     * @param reconstructionPoint the reconstruction point for the implicit certificate
     * @param qCa the CA's public key
     *
     * @return the public key reconstructed from the implicit certificate
     *
     * @throws IOException errors in provided data
     */
    public PublicKey reconstructPublicKey(
            byte[] identifyingInfo, byte[] reconstructionPoint, PublicKey qCa) throws IOException {
        // Reconstruct the point Pu from the reconstruction point
        ECPoint rPoint =
                ((BCECPublicKey) BouncyCastleProvider.getPublicKey(
                        new SubjectPublicKeyInfo(algorithmId, reconstructionPoint))).getQ();
        BigInteger n = curveParameters.getN(); // curve point order
        ECPoint caPoint = ((BCECPublicKey) qCa).getQ(); // Massage caPublicKey bytes into ECPoint

        // Calculate H(Certu)
        for (byte b : identifyingInfo) {
            digest.update(b);
        }

        for (byte b : reconstructionPoint) {
            digest.update(b);
        }

        // Hash the implicit certificate Certu and compute the integer e from H(Certu)
        BigInteger e = calculateE(n, digest.digest()).mod(n);

        // compute the point Qu = ePu + Qca
        SubjectPublicKeyInfo publicKeyInfo =
                new SubjectPublicKeyInfo(
                        algorithmId, rPoint.multiply(e).add(caPoint).getEncoded(false));

        return BouncyCastleProvider.getPublicKey(publicKeyInfo);
    }

    /**
     * Reconstruct the private key from the reconstruction data
     *
     * @param identifyingInfo the identity portion of the implicit certificate
     * @param reconstructionPoint the reconstruction point for the implicit certificate
     * @param privateKeyReconstructionData the private key reconstruction data associated with the
     *        implicit certificate
     * @param ephemeralPrivateKey the requesters ephemeral private key
     *
     * @return the private key associated with the implicit certificate
     *
     * @throws IOException when there are errors with, or malformed provided data
     */
    public PrivateKey reconstructPrivateKey(
            byte[] identifyingInfo, byte[] reconstructionPoint, byte[] privateKeyReconstructionData,
            PrivateKey ephemeralPrivateKey) throws IOException {
        // curve point order
        BigInteger n = curveParameters.getN();

        // calculate H(Certu)
        for (byte b : identifyingInfo) {
            digest.update(b);
        }

        for (byte b : reconstructionPoint) {
            digest.update(b);
        }

        // compute the integer e from H(Certu)
        BigInteger e = calculateE(n, digest.digest()).mod(n);

        // compute the private Key dU = r + e*kU (mod n)
        BigInteger r = octetStringToInteger(privateKeyReconstructionData);

        // Check that the 'r' is less than 'n'
        if (n.compareTo(r) != 1) {
            throw new IOException("Octet String value is larger than modulus");
        }

        // Private key dU.
        BigInteger dU = ((BCECPrivateKey) ephemeralPrivateKey).getD();
        dU = e.multiply(dU);
        dU = r.add(dU);
        dU = dU.mod(n);

        return BouncyCastleProvider.getPrivateKey(
                new PrivateKeyInfo(algorithmId, new ASN1Integer(dU.toByteArray())));
    }

    /**
     * Confirm that derived public Key qU and derived private key dU satisfy: qU = dU*G where G is
     * the base point for the curve.
     *
     * @param derivedPublicKey the recovered public key
     * @param derivedPrivateKey the recovered private key
     *
     * @return true for successful confirmation, false otherwise
     */
    public boolean verifyKeyPair(PublicKey derivedPublicKey, PrivateKey derivedPrivateKey) {
        // confirm equality
        return (((BCECPublicKey) derivedPublicKey).getQ().equals(
                curveParameters.getG().multiply(((BCECPrivateKey) derivedPrivateKey).getD())));
    }

    /**
     * Compute the integer e from H(Certu)
     *
     * @param n Curve order.
     * @param messageDigest Message digest.
     * @return e value.
     */
    private BigInteger calculateE(BigInteger n, byte[] messageDigest) {
        // n.bitLength() == ceil(log2(n < 0 ? -n : n+1)
        // we actually want floor(log_2(n)) which is n.bitLength()-1
        int log2n = n.bitLength() - 1;
        int messageBitLength = messageDigest.length * 8;

        if (log2n >= messageBitLength) {
            return new BigInteger(1, messageDigest);
        } else {
            BigInteger trunc = new BigInteger(1, messageDigest);

            trunc = trunc.shiftRight(messageBitLength - log2n);

            return trunc;
        }
    }

    /**
     * Convert an octet string to a {@link java.math.BigInteger BigInteger}.
     *
     * @param os the octet string
     * @return The {@link java.math.BigInteger BigInteger} value.
     */
    private BigInteger octetStringToInteger(byte[] os) {
        int osLen = os.length;
        byte[] osSigned;

        // Always prepend 0x00 byte to make it positive signed integer
        // (instead of checking the length of 'os' & 'modulus')
        osSigned = new byte[osLen + 1];
        System.arraycopy(os, 0, osSigned, 1, osLen);
        return new BigInteger(osSigned);
    }

    /**
     * Converts the given integer value and the given modulus to an octet string.
     *
     * @param r Integer value to convert.
     * @param modulus Modulus to convert.
     * @return Octet string representing r and modulus.
     * @throws IOException if r is greater than modulus.
     */
    private byte[] integerToOctetString(BigInteger r, BigInteger modulus) throws IOException {
        byte[] modulusBytes = modulus.toByteArray();
        int modulusLen = modulusBytes.length;
        byte[] rBytes = r.toByteArray();
        int rLen = rBytes.length;
        int rMSB = rBytes[0] & 0xFF;

        if (modulusBytes[0] == 0x00) {
            modulusLen -= 1;
        }

        // for arrays that are more than one byte longer
        if ((rLen == modulusLen + 1 && rMSB != 0x00) || rLen > modulusLen + 1) {
            throw new IOException("Integer value is larger than modulus");
        }

        byte[] rUnsigned = new byte[modulusLen];
        System.arraycopy(rBytes, ((rLen > modulusLen) ? (rLen - modulusLen) : 0),
                         rUnsigned, ((modulusLen > rLen) ? (modulusLen - rLen) : 0),
                         ((modulusLen > rLen) ? rLen : modulusLen));

        return rUnsigned;
    }
}
