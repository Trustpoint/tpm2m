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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;

/**
 * Enumerates the signature algorithm names for the supported signature algorithms.
 */
public enum SignatureAlgorithms {
    /**
     * Algorithm for ECDSA SHA256 SECP192R1.
     */
    ECDSA_SHA256_SECP192R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP192R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP192R1,
        CryptoAlgorithms.CURVE_SECP192R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA256,
        SECObjectIdentifiers.secp192r1),
    /**
     * Algorithm for ECDSA SHA256 SECP224R1.
     */
    ECDSA_SHA256_SECP224R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP224R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP224R1,
        CryptoAlgorithms.CURVE_SECP224R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA256,
        SECObjectIdentifiers.secp224r1),
    /**
     * Algorithm for ECDSA SHA256 SECT233K1.
     */
    ECDSA_SHA256_SECT233K1(
        M2mSignatureAlgorithmOids.ECDSA_SHA256_SECT233K1,
        NfcSignatureAlgorithmOids.ECDSA_SHA256_SECT233K1,
        CryptoAlgorithms.CURVE_SECT233K1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA256,
        SECObjectIdentifiers.sect233k1),
    /**
     * Algorithm for ECDSA SHA256 SECT233R1.
     */
    ECDSA_SHA256_SECT233R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA256_SECT233R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA256_SECT233R1,
        CryptoAlgorithms.CURVE_SECT233R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA256,
        SECObjectIdentifiers.sect233r1),
    /**
     * Algorithm for ECQV SHA256 SECP192R1.
     */
    ECQV_SHA256_SECP192R1(
        M2mSignatureAlgorithmOids.ECQV_SHA256_SECP192R1,
        NfcSignatureAlgorithmOids.ECQV_SHA256_SECP192R1,
        CryptoAlgorithms.CURVE_SECP192R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECQV_SHA256,
        SECObjectIdentifiers.secp192r1),
    /**
     * Algorithm for ECQV SHA256 SECP224R1.
     */
    ECQV_SHA256_SECP224R1(
        M2mSignatureAlgorithmOids.ECQV_SHA256_SECP224R1,
        NfcSignatureAlgorithmOids.ECQV_SHA256_SECP224R1,
        CryptoAlgorithms.CURVE_SECP224R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECQV_SHA256,
        SECObjectIdentifiers.secp224r1),
    /**
     * Algorithm for ECQV SHA256 SECT233K1.
     */
    ECQV_SHA256_SECT233K1(
        M2mSignatureAlgorithmOids.ECQV_SHA256_SECT233K1,
        NfcSignatureAlgorithmOids.ECQV_SHA256_SECT233K1,
        CryptoAlgorithms.CURVE_SECT233K1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECQV_SHA256,
        SECObjectIdentifiers.sect233k1),
    /**
     * Algorithm for ECQV SHA256 SECT233R1.
     */
    ECQV_SHA256_SECT233R1(
        M2mSignatureAlgorithmOids.ECQV_SHA256_SECT233R1,
        NfcSignatureAlgorithmOids.ECQV_SHA256_SECT233R1,
        CryptoAlgorithms.CURVE_SECT233R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECQV_SHA256,
        SECObjectIdentifiers.sect233r1),
    /**
     * Algorithm for RSA SHA256 RSA.
     */
    RSA_SHA256_RSA(
        M2mSignatureAlgorithmOids.RSA_SHA256_RSA,
        NfcSignatureAlgorithmOids.RSA_SHA256_RSA,
        CryptoAlgorithms.RSA,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.RSA_SHA256,
        null),
    /**
     * Algorithm for ECDSA SHA256 SECP256R1.
     */
    ECDSA_SHA256_SECP256R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1,
        CryptoAlgorithms.CURVE_SECP256R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA256,
        SECObjectIdentifiers.secp256r1),
    /**
     * Algorithm for ECQV SHA256 SECP256R1.
     */
    ECQV_SHA256_SECP256R1(
        M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1,
        NfcSignatureAlgorithmOids.ECQV_SHA256_SECP256R1,
        CryptoAlgorithms.CURVE_SECP256R1,
        DigestAlgorithms.SHA256,
        BouncyCastleSignatureAlgorithms.ECQV_SHA256,
        SECObjectIdentifiers.secp256r1),
    /**
     * Algorithm for ECDSA SHA384 SECP384R1.
     */
    ECDSA_SHA384_SECP384R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA384_SECP384R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA384_SECP384R1,
        CryptoAlgorithms.CURVE_SECP384R1,
        DigestAlgorithms.SHA384,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA384,
        SECObjectIdentifiers.secp384r1),
    /**
     * Algorithm for ECQV SHA384 SECP384R1.
     */
    ECQV_SHA384_SECP384R1(
        M2mSignatureAlgorithmOids.ECQV_SHA384_SECP384R1,
        NfcSignatureAlgorithmOids.ECQV_SHA384_SECP384R1,
        CryptoAlgorithms.CURVE_SECP384R1,
        DigestAlgorithms.SHA384,
        BouncyCastleSignatureAlgorithms.ECQV_SHA384,
        SECObjectIdentifiers.secp384r1),
    /**
     * Algorithm for ECDSA SHA512 SECP521R1.
     */
    ECDSA_SHA512_SECP521R1(
        M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1,
        NfcSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1,
        CryptoAlgorithms.CURVE_SECP521R1,
        DigestAlgorithms.SHA512,
        BouncyCastleSignatureAlgorithms.ECDSA_SHA512,
        SECObjectIdentifiers.secp521r1),
    /**
     * Algorithm for ECQV SHA512 SECP521R1.
     */
    ECQV_SHA512_SECP521R1(
        M2mSignatureAlgorithmOids.ECQV_SHA512_SECP521R1,
        NfcSignatureAlgorithmOids.ECQV_SHA512_SECP521R1,
        CryptoAlgorithms.CURVE_SECP521R1,
        DigestAlgorithms.SHA512,
        BouncyCastleSignatureAlgorithms.ECQV_SHA512,
        SECObjectIdentifiers.secp521r1);

    private final M2mSignatureAlgorithmOids m2mOid;
    private final NfcSignatureAlgorithmOids nfcOid;
    private final CryptoAlgorithms cryptoAlgorithm;
    private final DigestAlgorithms digestAlgorithm;
    private final BouncyCastleSignatureAlgorithms bouncyCastleName;
    private final ASN1ObjectIdentifier secOid;

    /**
     * Constructor.
     */
    SignatureAlgorithms(
            M2mSignatureAlgorithmOids m2mOid, NfcSignatureAlgorithmOids nfcOid,
            CryptoAlgorithms cryptoAlgorithm, DigestAlgorithms digestAlgorithm,
            BouncyCastleSignatureAlgorithms bouncyCastleName, ASN1ObjectIdentifier secOid) {
        this.m2mOid = m2mOid;
        this.nfcOid = nfcOid;
        this.cryptoAlgorithm = cryptoAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.bouncyCastleName = bouncyCastleName;
        this.secOid = secOid;
    }

    /**
     * Returns M2M signature algorithm object identifier.
     *
     * @return M2M signature algorithm object identifier.
     */
    public M2mSignatureAlgorithmOids getM2mOid() {
        return m2mOid;
    }

    /**
     * Returns NFC signature algorithm object identifier.
     *
     * @return NFC signature algorithm object identifier.
     */
    public NfcSignatureAlgorithmOids getNfcOid() {
        return nfcOid;
    }

    /**
     * Returns crypto algorithm name.
     *
     * @return crypto algorithm name.
     */
    public CryptoAlgorithms getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    /**
     * Returns digest algorithm name.
     *
     * @return digest algorithm name.
     */
    public DigestAlgorithms getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns BouncyCastle algorithm name.
     *
     * @return BouncyCastle algorithm name.
     */
    public String getBouncyCastleName() {
        return bouncyCastleName.getBouncyCastleName();
    }

    /**
     * Returns SEC object identifier.
     *
     * @return SEC object identifier.
     */
    public String getSecOid() {
        return secOid.getId();
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid A M2MSignatureAlgorithmOids value.
     *
     * @return An instance of object in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static SignatureAlgorithms getInstance(M2mSignatureAlgorithmOids oid)
            throws IllegalArgumentException {
        if (oid.equals(ECDSA_SHA256_SECP192R1.m2mOid)) {
            return ECDSA_SHA256_SECP192R1;
        } else if (oid.equals(ECDSA_SHA256_SECP224R1.m2mOid)) {
            return ECDSA_SHA256_SECP224R1;
        } else if (oid.equals(ECDSA_SHA256_SECT233K1.m2mOid)) {
            return ECDSA_SHA256_SECT233K1;
        } else if (oid.equals(ECDSA_SHA256_SECT233R1.m2mOid)) {
            return ECDSA_SHA256_SECT233R1;
        } else if (oid.equals(ECQV_SHA256_SECP192R1.m2mOid)) {
            return ECQV_SHA256_SECP192R1;
        } else if (oid.equals(ECQV_SHA256_SECP224R1.m2mOid)) {
            return ECQV_SHA256_SECP224R1;
        } else if (oid.equals(ECQV_SHA256_SECT233K1.m2mOid)) {
            return ECQV_SHA256_SECT233K1;
        } else if (oid.equals(ECQV_SHA256_SECT233R1.m2mOid)) {
            return ECQV_SHA256_SECT233R1;
        } else if (oid.equals(RSA_SHA256_RSA.m2mOid)) {
            return RSA_SHA256_RSA;
        } else if (oid.equals(ECDSA_SHA256_SECP256R1.m2mOid)) {
            return ECDSA_SHA256_SECP256R1;
        } else if (oid.equals(ECQV_SHA256_SECP256R1.m2mOid)) {
            return ECQV_SHA256_SECP256R1;
        } else if (oid.equals(ECDSA_SHA384_SECP384R1.m2mOid)) {
            return ECDSA_SHA384_SECP384R1;
        } else if (oid.equals(ECQV_SHA384_SECP384R1.m2mOid)) {
            return ECQV_SHA384_SECP384R1;
        } else if (oid.equals(ECDSA_SHA512_SECP521R1.m2mOid)) {
            return ECDSA_SHA512_SECP521R1;
        } else if (oid.equals(ECQV_SHA512_SECP521R1.m2mOid)) {
            return ECQV_SHA512_SECP521R1;
        }

        throw new IllegalArgumentException("unknown M2M algorithm oid: " + oid);
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid A NFCSignatureAlgorithmOids value.
     *
     * @return An instance of object in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static SignatureAlgorithms getInstance(NfcSignatureAlgorithmOids oid)
            throws IllegalArgumentException {
        if (oid.equals(ECDSA_SHA256_SECP192R1.nfcOid)) {
            return ECDSA_SHA256_SECP192R1;
        } else if (oid.equals(ECDSA_SHA256_SECP224R1.nfcOid)) {
            return ECDSA_SHA256_SECP224R1;
        } else if (oid.equals(ECDSA_SHA256_SECT233K1.nfcOid)) {
            return ECDSA_SHA256_SECT233K1;
        } else if (oid.equals(ECDSA_SHA256_SECT233R1.nfcOid)) {
            return ECDSA_SHA256_SECT233R1;
        } else if (oid.equals(ECQV_SHA256_SECP192R1.nfcOid)) {
            return ECQV_SHA256_SECP192R1;
        } else if (oid.equals(ECQV_SHA256_SECP224R1.nfcOid)) {
            return ECQV_SHA256_SECP224R1;
        } else if (oid.equals(ECQV_SHA256_SECT233K1.nfcOid)) {
            return ECQV_SHA256_SECT233K1;
        } else if (oid.equals(ECQV_SHA256_SECT233R1.nfcOid)) {
            return ECQV_SHA256_SECT233R1;
        } else if (oid.equals(RSA_SHA256_RSA.nfcOid)) {
            return RSA_SHA256_RSA;
        } else if (oid.equals(ECDSA_SHA256_SECP256R1.nfcOid)) {
            return ECDSA_SHA256_SECP256R1;
        } else if (oid.equals(ECQV_SHA256_SECP256R1.nfcOid)) {
            return ECQV_SHA256_SECP256R1;
        } else if (oid.equals(ECDSA_SHA384_SECP384R1.nfcOid)) {
            return ECDSA_SHA384_SECP384R1;
        } else if (oid.equals(ECQV_SHA384_SECP384R1.nfcOid)) {
            return ECQV_SHA384_SECP384R1;
        } else if (oid.equals(ECDSA_SHA512_SECP521R1.nfcOid)) {
            return ECDSA_SHA512_SECP521R1;
        } else if (oid.equals(ECQV_SHA512_SECP521R1.nfcOid)) {
            return ECQV_SHA512_SECP521R1;
        }

        throw new IllegalArgumentException("unknown NFC algorithm oid: " + oid);
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid A SignatureAlgorithmOids value.
     *
     * @return An instance of object in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static SignatureAlgorithms getInstance(SignatureAlgorithmOids oid)
            throws IllegalArgumentException {
        if (oid instanceof M2mSignatureAlgorithmOids) {
            return getInstance((M2mSignatureAlgorithmOids) oid);
        } else if (oid instanceof NfcSignatureAlgorithmOids) {
            return getInstance((NfcSignatureAlgorithmOids) oid);
        }

        throw new IllegalArgumentException("unknown algorithm oid: " + oid);
    }

    private boolean match(byte[] oidBytes) {
        String oid = null;

        try {
            oid = ASN1ObjectIdentifier.getInstance(oidBytes).getId();
        } catch (IllegalArgumentException ex) {
            return false;
        }

        return match(oid);
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid A M2M or NFC signature algorithm oid in byte array format.
     *
     * @return An instance of object in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static SignatureAlgorithms getInstance(byte[] oid) throws IllegalArgumentException {
        if (ECDSA_SHA256_SECP192R1.match(oid)) {
            return ECDSA_SHA256_SECP192R1;
        } else if (ECDSA_SHA256_SECP224R1.match(oid)) {
            return ECDSA_SHA256_SECP224R1;
        } else if (ECDSA_SHA256_SECT233K1.match(oid)) {
            return ECDSA_SHA256_SECT233K1;
        } else if (ECDSA_SHA256_SECT233R1.match(oid)) {
            return ECDSA_SHA256_SECT233R1;
        } else if (ECQV_SHA256_SECP192R1.match(oid)) {
            return ECQV_SHA256_SECP192R1;
        } else if (ECQV_SHA256_SECP224R1.match(oid)) {
            return ECQV_SHA256_SECP224R1;
        } else if (ECQV_SHA256_SECT233K1.match(oid)) {
            return ECQV_SHA256_SECT233K1;
        } else if (ECQV_SHA256_SECT233R1.match(oid)) {
            return ECQV_SHA256_SECT233R1;
        } else if (RSA_SHA256_RSA.match(oid)) {
            return RSA_SHA256_RSA;
        } else if (ECDSA_SHA256_SECP256R1.match(oid)) {
            return ECDSA_SHA256_SECP256R1;
        } else if (ECQV_SHA256_SECP256R1.match(oid)) {
            return ECQV_SHA256_SECP256R1;
        } else if (ECDSA_SHA384_SECP384R1.match(oid)) {
            return ECDSA_SHA384_SECP384R1;
        } else if (ECQV_SHA384_SECP384R1.match(oid)) {
            return ECQV_SHA384_SECP384R1;
        } else if (ECDSA_SHA512_SECP521R1.match(oid)) {
            return ECDSA_SHA512_SECP521R1;
        } else if (ECQV_SHA512_SECP521R1.match(oid)) {
            return ECQV_SHA512_SECP521R1;
        }

        throw new IllegalArgumentException(
            "unknown M2M/NFC algorithm oid: " + ASN1ObjectIdentifier.getInstance(oid).getId());
    }

    private boolean match(String oid) {
        if (oid.equals(getM2mOid().getOid()) || oid.equals(getNfcOid().getOid())) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid A M2M or NFC signature algorithm oid in String format.
     *
     * @return An instance of object in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static SignatureAlgorithms getInstance(String oid) throws IllegalArgumentException {
        if (ECDSA_SHA256_SECP192R1.match(oid)) {
            return ECDSA_SHA256_SECP192R1;
        } else if (ECDSA_SHA256_SECP224R1.match(oid)) {
            return ECDSA_SHA256_SECP224R1;
        } else if (ECDSA_SHA256_SECT233K1.match(oid)) {
            return ECDSA_SHA256_SECT233K1;
        } else if (ECDSA_SHA256_SECT233R1.match(oid)) {
            return ECDSA_SHA256_SECT233R1;
        } else if (ECQV_SHA256_SECP192R1.match(oid)) {
            return ECQV_SHA256_SECP192R1;
        } else if (ECQV_SHA256_SECP224R1.match(oid)) {
            return ECQV_SHA256_SECP224R1;
        } else if (ECQV_SHA256_SECT233K1.match(oid)) {
            return ECQV_SHA256_SECT233K1;
        } else if (ECQV_SHA256_SECT233R1.match(oid)) {
            return ECQV_SHA256_SECT233R1;
        } else if (RSA_SHA256_RSA.match(oid)) {
            return RSA_SHA256_RSA;
        } else if (ECDSA_SHA256_SECP256R1.match(oid)) {
            return ECDSA_SHA256_SECP256R1;
        } else if (ECQV_SHA256_SECP256R1.match(oid)) {
            return ECQV_SHA256_SECP256R1;
        } else if (ECDSA_SHA384_SECP384R1.match(oid)) {
            return ECDSA_SHA384_SECP384R1;
        } else if (ECQV_SHA384_SECP384R1.match(oid)) {
            return ECQV_SHA384_SECP384R1;
        } else if (ECDSA_SHA512_SECP521R1.match(oid)) {
            return ECDSA_SHA512_SECP521R1;
        } else if (ECQV_SHA512_SECP521R1.match(oid)) {
            return ECQV_SHA512_SECP521R1;
        }

        throw new IllegalArgumentException("unknown M2M/NFC algorithm oid: " + oid);
    }

    /**
     * Returns the enumeration value that corresponds to the given SEC oid and implicit/explicit
     * flag.
     *
     * @param oid SEC Object Identifier.
     * @param implicit True if the implicit signature algorithm should be returned. False if the
     *                 explicit signature algorithm should be returned.
     *
     * @return An instance of object in the enum associated with the given SEC oid and
     *         implicit/explicit flag.
     * @throws IllegalArgumentException if a matching signature algorithm cannot be found.
     */
    public static SignatureAlgorithms getInstance(String oid, boolean implicit)
            throws IllegalArgumentException {
        if(implicit) {
            if (ECQV_SHA256_SECP192R1.match(oid)) {
                return ECQV_SHA256_SECP192R1;
            } else if (ECQV_SHA256_SECP224R1.secOid.getId().equals(oid)) {
                return ECQV_SHA256_SECP224R1;
            } else if (ECQV_SHA256_SECT233K1.secOid.getId().equals(oid)) {
                return ECQV_SHA256_SECT233K1;
            } else if (ECQV_SHA256_SECT233R1.secOid.getId().equals(oid)) {
                return ECQV_SHA256_SECT233R1;
            } else if (ECQV_SHA256_SECP256R1.secOid.getId().equals(oid)) {
                return ECQV_SHA256_SECP256R1;
            } else if (ECQV_SHA384_SECP384R1.secOid.getId().equals(oid)) {
                return ECQV_SHA384_SECP384R1;
            } else if (ECQV_SHA512_SECP521R1.secOid.getId().equals(oid)) {
                return ECQV_SHA512_SECP521R1;
            }
        } else {
            if (ECDSA_SHA256_SECP192R1.match(oid)) {
                return ECDSA_SHA256_SECP192R1;
            } else if (ECDSA_SHA256_SECP224R1.secOid.getId().equals(oid)) {
                return ECDSA_SHA256_SECP224R1;
            } else if (ECDSA_SHA256_SECT233K1.secOid.getId().equals(oid)) {
                return ECDSA_SHA256_SECT233K1;
            } else if (ECDSA_SHA256_SECT233R1.secOid.getId().equals(oid)) {
                return ECDSA_SHA256_SECT233R1;
            } else if (ECDSA_SHA256_SECP256R1.secOid.getId().equals(oid)) {
                return ECDSA_SHA256_SECP256R1;
            } else if (ECDSA_SHA384_SECP384R1.secOid.getId().equals(oid)) {
                return ECDSA_SHA384_SECP384R1;
            } else if (ECDSA_SHA512_SECP521R1.secOid.getId().equals(oid)) {
                return ECDSA_SHA512_SECP521R1;
            }
        }

        throw new IllegalArgumentException("No match found for SEC OID: " + oid);
    }

    /**
     * Returns true if this signature algorithm is based on the Elliptic Curve Qu-Vanstone (ECQV)
     * scheme.
     *
     * @return True if this signature algorithm is based on ECQV.
     */
    public boolean isEcqv() {
        switch (m2mOid) {
            case ECQV_SHA256_SECP192R1:
            case ECQV_SHA256_SECP224R1:
            case ECQV_SHA256_SECP256R1:
            case ECQV_SHA256_SECT233K1:
            case ECQV_SHA256_SECT233R1:
            case ECQV_SHA384_SECP384R1:
            case ECQV_SHA512_SECP521R1:
                return true;

            default:
                return false;
        }
    }
}
