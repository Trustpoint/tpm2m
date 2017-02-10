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

/**
 * Enumerates the ASN.1 object identifiers contained in the NFC Signature RTD version 2.0 for the
 * supported signature algorithms.
 */
public enum NfcSignatureAlgorithmOids implements SignatureAlgorithmOids {
    /**
     * Algorithm ECDSA SHA256 SECP192R1.
     */
    ECDSA_SHA256_SECP192R1("2.16.840.1.114513.1.0"),
    /**
     * Algorithm ECDSA SHA256 SECP224R1.
     */
    ECDSA_SHA256_SECP224R1("2.16.840.1.114513.1.1"),
    /**
     * Algorithm ECDSA SHA256 SECT233K1.
     */
    ECDSA_SHA256_SECT233K1("2.16.840.1.114513.1.2"),
    /**
     * Algorithm ECDSA SHA256 SECT233R1.
     */
    ECDSA_SHA256_SECT233R1("2.16.840.1.114513.1.3"),
    /**
     * Algorithm ECQV SHA256 SECP192R1.
     */
    ECQV_SHA256_SECP192R1("2.16.840.1.114513.1.4"),
    /**
     * Algorithm ECQV SHA256 SECP224R1.
     */
    ECQV_SHA256_SECP224R1("2.16.840.1.114513.1.5"),
    /**
     * Algorithm ECQV SHA256 SECT233K1.
     */
    ECQV_SHA256_SECT233K1("2.16.840.1.114513.1.6"),
    /**
     * Algorithm ECQV SHA256 SECT233R1.
     */
    ECQV_SHA256_SECT233R1("2.16.840.1.114513.1.7"),
    /**
     * Algorithm RSA SHA256 RSA.
     */
    RSA_SHA256_RSA("2.16.840.1.114513.1.8"),
    /**
     * Algorithm ECDSA SHA256 SECP256R1.
     */
    ECDSA_SHA256_SECP256R1("2.16.840.1.114513.1.9"),
    /**
     * Algorithm ECQV SHA256 SECP256R1.
     */
    ECQV_SHA256_SECP256R1("2.16.840.1.114513.1.10"),
    /**
     * Algorithm ECDSA SHA384 SECP384R1.
     */
    ECDSA_SHA384_SECP384R1("2.16.840.1.114513.1.11"),
    /**
     * Algorithm ECQV SHA384 SECP384R1.
     */
    ECQV_SHA384_SECP384R1("2.16.840.1.114513.1.12"),
    /**
     * Algorithm ECDSA SHA512 SECP521R1.
     */
    ECDSA_SHA512_SECP521R1("2.16.840.1.114513.1.13"),
    /**
     * Algorithm ECQV SHA512 SECP521R1.
     */
    ECQV_SHA512_SECP521R1("2.16.840.1.114513.1.14");

    private final String oid;

    /**
     * Constructor.
     */
    NfcSignatureAlgorithmOids(String oid) {
        this.oid = oid;
    }

    /**
     * Returns object ID
     *
     * @return Object ID.
     */
    @Override
    public String getOid() {
        return oid;
    }

    /**
     * Returns the enumeration value that corresponds to the given oid.
     *
     * @param oid Object ID of an object in the enum.
     *
     * @return An instance of Object ID in the enum associated with the given oid.
     * @throws IllegalArgumentException if oid is invalid.
     */
    public static NfcSignatureAlgorithmOids getInstance(String oid)
            throws IllegalArgumentException {
        if (oid.equals(ECDSA_SHA256_SECP192R1.oid)) {
            return ECDSA_SHA256_SECP192R1;
        } else if (oid.equals(ECDSA_SHA256_SECP224R1.oid)) {
            return ECDSA_SHA256_SECP224R1;
        } else if (oid.equals(ECDSA_SHA256_SECT233K1.oid)) {
            return ECDSA_SHA256_SECT233K1;
        } else if (oid.equals(ECDSA_SHA256_SECT233R1.oid)) {
            return ECDSA_SHA256_SECT233R1;
        } else if (oid.equals(ECQV_SHA256_SECP192R1.oid)) {
            return ECQV_SHA256_SECP192R1;
        } else if (oid.equals(ECQV_SHA256_SECP224R1.oid)) {
            return ECQV_SHA256_SECP224R1;
        } else if (oid.equals(ECQV_SHA256_SECT233K1.oid)) {
            return ECQV_SHA256_SECT233K1;
        } else if (oid.equals(ECQV_SHA256_SECT233R1.oid)) {
            return ECQV_SHA256_SECT233R1;
        } else if (oid.equals(RSA_SHA256_RSA.oid)) {
            return RSA_SHA256_RSA;
        } else if (oid.equals(ECDSA_SHA256_SECP256R1.oid)) {
            return ECDSA_SHA256_SECP256R1;
        } else if (oid.equals(ECQV_SHA256_SECP256R1.oid)) {
            return ECQV_SHA256_SECP256R1;
        } else if (oid.equals(ECDSA_SHA384_SECP384R1.oid)) {
            return ECDSA_SHA384_SECP384R1;
        } else if (oid.equals(ECQV_SHA384_SECP384R1.oid)) {
            return ECQV_SHA384_SECP384R1;
        } else if (oid.equals(ECDSA_SHA512_SECP521R1.oid)) {
            return ECDSA_SHA512_SECP521R1;
        } else if (oid.equals(ECQV_SHA512_SECP521R1.oid)) {
            return ECQV_SHA512_SECP521R1;
        } else {
            throw new IllegalArgumentException("unknown oid: " + oid);
        }
    }
}
