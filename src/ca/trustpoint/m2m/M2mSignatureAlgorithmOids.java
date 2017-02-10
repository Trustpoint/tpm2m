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
 * Enumerates the ASN.1 object identifiers contained in the M2M spec for the supported signature
 * algorithms.
 */
public enum M2mSignatureAlgorithmOids implements SignatureAlgorithmOids {
    /**
     * Algorithm ECDSA SHA256 SECP192R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA256_SECP192R1("1.3.186.1.0"),
    /**
     * Algorithm ECDAS SHA256 SECP224R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA256_SECP224R1("1.3.186.1.1"),
    /**
     * Algorithm ECDSA SH256 SECT233K1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA256_SECT233K1("1.3.186.1.2"),
    /**
     * Algorithm ECDSA SHA256 SECT233R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA256_SECT233R1("1.3.186.1.3"),
    /**
     * Algorithm ECQV SHA256 SECP192R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA256_SECP192R1("1.3.186.1.4"),
    /**
     * Algorithm ECQV SHA256 SECP224R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA256_SECP224R1("1.3.186.1.5"),
    /**
     * Algorithm ECQV SHA256 SECT233K1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA256_SECT233K1("1.3.186.1.6"),
    /**
     * Algorithm ECQV SHA256 SECT233R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA256_SECT233R1("1.3.186.1.7"),
    /**
     * Algorithm RSA SHA256 RSA.
     *
     * See <a href="https://www.ietf.org/rfc/rfc6594.txt">https://www.ietf.org/rfc/rfc6594.txt</a>
     * for details.
     */
    RSA_SHA256_RSA("1.3.186.1.8"),
    /**
     * Algorithm ECDSA SHA256 SECP256R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA256_SECP256R1("1.3.186.1.9"),
    /**
     * Algorithm ECQV SHA256 SECP256R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA256_SECP256R1("1.3.186.1.10"),
    /**
     * Algorithm ECDSA SHA384 SECP384R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA384_SECP384R1("1.3.186.1.11"),
    /**
     * Algorithm ECQV SHA384 SECP384R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA384_SECP384R1("1.3.186.1.12"),
    /**
     * Algorithm ECDSA SHA512 SECP521R1.
     *
     * See <a href="https://www.ietf.org/rfc/rfc5480.txt">https://www.ietf.org/rfc/rfc5480.txt</a>
     * for details.
     */
    ECDSA_SHA512_SECP521R1("1.3.186.1.13"),
    /**
     * Algorithm ECQV SHA512 SECP521R1.
     *
     * See <a href="http://www.secg.org/draft-sec4-1.1.pdf">http://www.secg.org/draft-sec4-1.1.pdf
     * </a> for details.
     */
    ECQV_SHA512_SECP521R1("1.3.186.1.14");

    private final String oid;

    /**
     * Constructor.
     */
    M2mSignatureAlgorithmOids(String oid) {
        this.oid = oid;
    }

    /**
     * Returns object ID.
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
    public static M2mSignatureAlgorithmOids getInstance(String oid)
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
