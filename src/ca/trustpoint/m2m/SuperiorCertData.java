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

import java.security.PublicKey;

import org.bouncycastle.util.encoders.Hex;

/**
 * M2mCertificates may require data from the superior certificate in order to be signed/verified
 * properly. This class encapsulates that data, to help avoid having to re-parse a certificate
 */
public class SuperiorCertData {
    PublicKey pubKey;
    EntityName subject;
    KeyAlgorithmDefinition pubKeyDef;

    public SuperiorCertData() {
    }

    public void setSubject(EntityName subject) {
        this.subject = subject;
    }

    public EntityName getSubject() {
        return subject;
    }

    public void setPublicKeyDefinition(KeyAlgorithmDefinition pubKeyDef) {
        this.pubKeyDef = pubKeyDef;
    }

    public KeyAlgorithmDefinition getPublicKeyDefinition() {
        return pubKeyDef;
    }

    public PublicKey getPublicKey() {
        return pubKey;
    }

    public void setPublicKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        final String LINE_SEPARATOR = System.getProperty("line.separator");

        builder.append("pubkey: ");
        if (pubKey != null) {
            builder.append(Hex.toHexString(pubKey.getEncoded()));
        } else {
            builder.append("null");
        }
        builder.append(LINE_SEPARATOR);

        builder.append("subject: ");
        if (subject != null) {
            builder.append(subject.toString());
        } else {
            builder.append("null");
        }
        builder.append(LINE_SEPARATOR);

        builder.append("pubKeyDef: ");
        if (pubKeyDef != null) {
            builder.append(pubKeyDef.toString());
        } else {
            builder.append("null");
        }

        return builder.toString();
    }
}
