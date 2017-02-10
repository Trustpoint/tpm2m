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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.style.BCStyle;

import ca.trustpoint.m2m.util.FormattingUtils;

/**
 * Represents a Name object.
 *
 * An EntityName is composed of between 1 and 4 (inclusive) {@link EntityNameAttribute} objects. It
 * is defined in the M2M spec as:
 *
 * <pre>
 *     Name ::= SEQUENCE SIZE (1..4) OF AttributeValue
 * </pre>
 *
 * @see EntityNameAttribute
 */
public class EntityName {
    /** Minimum number of attributes that must be defined for an EntityName instance. */
    public static final int MINIMUM_ATTRIBUTES = 1;

    /** Maximum number of attributes that may be defined for an EntityName instance. */
    public static final int MAXIMUM_ATTRIBUTES = 4;

    private ArrayList<EntityNameAttribute> attributes = new ArrayList<EntityNameAttribute>(4);

    /** Create a new instance. */
    public EntityName() {
    }

    public List<EntityNameAttribute> getAttributes() {
        return attributes;
    }

    /**
     * Adds the given {@link EntityNameAttribute} to this instance.
     *
     * @param attribute The {@link EntityNameAttribute} to add.
     * @throws IllegalArgumentException if the given {@link EntityNameAttribute} is invalid or if
     *         this instance already contains {@link EntityName#MAXIMUM_ATTRIBUTES MAX_ATTRIBUTES}
     *         attributes.
     */
    public void addAttribute(EntityNameAttribute attribute) throws IllegalArgumentException {
        if ((attributes == null) || (!attribute.isValid())) {
            throw new IllegalArgumentException("attribute not valid.");
        } else if (attributes.size() >= MAXIMUM_ATTRIBUTES) {
            throw new IllegalArgumentException("too many attributes.");
        }

        attributes.add(attribute);
    }

    /**
     * Return true if this instance is a valid EntityName, per the M2M spec.
     *
     * @return True if this instance is valid.
     */
    public boolean isValid() {
        if ((attributes.size() < MINIMUM_ATTRIBUTES) || (attributes.size() > MAXIMUM_ATTRIBUTES)) {
            return false;
        }

        for (EntityNameAttribute attribute : attributes) {
            if (!attribute.isValid()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the DER encoding of this instance.
     *
     * @return The DER encoding of this instance.
     * @throws IOException if this instance cannot be encoded.
     */
    public byte[] getEncoded() throws IOException {
        if (!isValid()) {
            throw new IOException("EntityName is not valid.");
        }

        ASN1EncodableVector attrVector = new ASN1EncodableVector();

        for(EntityNameAttribute attribute : attributes) {
            attrVector.add(DERTaggedObject.getInstance(attribute.getEncoded()));
        }

        return new DERSequence(attrVector).getEncoded();
    }

    /**
     * Returns a <code>X500Principal</code> object representing the name entity. The object is
     * encoded in ASN.1 DER encoded form as the following ASN.1 notation:
     * <pre><code>
     * Name ::= CHOICE {
     *   RDNSequence
     * }
     *
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     *
     * RelativeDistinguishedName ::=
     *   SET SIZE (1 .. MAX) OF AttributeTypeAndValue
     *
     * AttributeTypeAndValue ::= SEQUENCE {
     *   type     AttributeType,
     *   value    AttributeValue
     * }
     *
     * AttributeType ::= OBJECT IDENTIFIER
     *
     * AttributeValue ::= ANY DEFINED BY AttributeType
     * ....
     * DirectoryString ::= CHOICE {
     *       teletexString           TeletexString (SIZE (1..MAX)),
     *       printableString         PrintableString (SIZE (1..MAX)),
     *       universalString         UniversalString (SIZE (1..MAX)),
     *       utf8String              UTF8String (SIZE (1.. MAX)),
     *       bmpString               BMPString (SIZE (1..MAX))
     * }
     * </code></pre>
     *
     * This data is used to construct an <code>X500Principal</code> object in
     * <code>M2MCertificateLite</code> for fiding TrustPoint's M2M root certificate in AOSP
     * trusted certificate store.
     *
     * @return X500Pricipal object in ASN.1 DER format.
     * @throws IllegalArgumentException if attributes for the name are invalid.
     * @throws IOException if IO error is encountered during encoding.
     */
    X500Principal getX500Principal() throws IllegalArgumentException, IOException {
        if (!isValid()) {
            throw new IOException("EntityName is not valid.");
        }

        ASN1EncodableVector attrVector = new ASN1EncodableVector();

        // Get attribute OID and value
        for(EntityNameAttribute attribute : attributes) {
            ASN1Encodable[] attrArray = new ASN1Encodable[2];
            switch(attribute.getId()) {
                case Country:
                    attrArray[0] = BCStyle.C;
                    break;

                case Organization:
                    attrArray[0] = BCStyle.O;
                    break;

                case OrganizationalUnit:
                    attrArray[0] = BCStyle.OU;
                    break;

                case DistinguishedNameQualifier:
                    attrArray[0] = BCStyle.DN_QUALIFIER;
                    break;

                case StateOrProvince:
                    attrArray[0] = BCStyle.ST;
                    break;

                case Locality:
                    attrArray[0] = BCStyle.L;
                    break;

                case CommonName:
                    attrArray[0] = BCStyle.CN;
                    break;

                case SerialNumber:
                    attrArray[0] = BCStyle.SN;
                    break;

                case DomainComponent:
                    attrArray[0] = BCStyle.DC;
                    break;

                case RegisteredId:
                    attrArray[0] = BCStyle.UID;
                    break;

                case OctetsName:
                    attrArray[0] = BCStyle.UNIQUE_IDENTIFIER;
                    break;

                default:
                    throw new IOException("Unknown attribute type ID: " + attribute.getId());
            }
            attrArray[1] = attribute.getEncodedValue();
            attrVector.add(new DERSequence(attrArray));
        }

        return new X500Principal(new DERSequence(new DERSet(attrVector)).getEncoded());
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

        FormattingUtils.indent(buffer, depth).append("Name SEQUENCE {").append(LINE_SEPARATOR);

        for (EntityNameAttribute attribute : attributes) {
            buffer.append(attribute.toString(depth + 1));
        }

        FormattingUtils.indent(buffer, depth).append("}").append(LINE_SEPARATOR);

        return buffer.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        } else if (obj instanceof EntityName) {
            EntityName other = (EntityName) obj;

            return (attributes.equals(other.attributes));
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return (attributes.hashCode());
    }
}
