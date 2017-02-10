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
 * Enumerates the cryptographic algorithms for the supported signature algorithms.
 */
public enum CryptoAlgorithms {
    /**
     * Algorithm name for CURVE SECP192R1.
     */
    CURVE_SECP192R1("secp192r1"),
    /**
     * Algorithm name for CURVE SECP224R1.
     */
    CURVE_SECP224R1("secp224r1"),
    /**
     * Algorithm name for CURVE SECT233K1.
     */
    CURVE_SECT233K1("sect233k1"),
    /**
     * Algorithm name for CURVE SECT233R1.
     */
    CURVE_SECT233R1("sect233r1"),
    /**
     * Algorithm name for CURVE SECP256R1.
     */
    CURVE_SECP256R1("secp256r1"),
    /**
     * Algorithm name for CURVE SECP384R1.
     */
    CURVE_SECP384R1("secp384r1"),
    /**
     * Algorithm name for CURVE SECP521R1.
     */
    CURVE_SECP521R1("secp521r1"),
    /**
     * Algorithm name for RSA.
     */
    RSA("RSA");

    private final String algorithmName;

    /**
     * Constructor.
     */
    CryptoAlgorithms(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns algorithm name.
     *
     * @return Algorithm name.
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Returns the enumeration value that corresponds to the given algorithmName.
     *
     * @param algorithmName Algorithm name of an object in the enum.
     *
     * @return An instance of object in the enum associated with the given algorithmName.
     * @throws IllegalArgumentException if algorithmName is invalid.
     */
    public static CryptoAlgorithms getInstance(String algorithmName)
            throws IllegalArgumentException {
        if (algorithmName.equals(CURVE_SECP192R1.algorithmName)) {
            return CURVE_SECP192R1;
        }

        if (algorithmName.equals(CURVE_SECP224R1.algorithmName)) {
            return CURVE_SECP224R1;
        }

        if (algorithmName.equals(CURVE_SECT233K1.algorithmName)) {
            return CURVE_SECT233K1;
        }

        if (algorithmName.equals(CURVE_SECT233R1.algorithmName)) {
            return CURVE_SECT233R1;
        }

        if (algorithmName.equals(CURVE_SECP256R1.algorithmName)) {
            return CURVE_SECP256R1;
        }

        if (algorithmName.equals(CURVE_SECP384R1.algorithmName)) {
            return CURVE_SECP384R1;
        }

        if (algorithmName.equals(CURVE_SECP521R1.algorithmName)) {
            return CURVE_SECP521R1;
        }

        if (algorithmName.equals(RSA.algorithmName)) {
            return RSA;
        }

        throw new IllegalArgumentException("unknown algorithm name: " + algorithmName);
    }
}
