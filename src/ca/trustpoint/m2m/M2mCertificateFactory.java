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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.util.encoders.Hex;

import ca.trustpoint.m2m.M2mCertPath.SupportedEncodings;
import ca.trustpoint.m2m.util.KeyConversionUtils;

/**
 * This class defines a certificate factory for M2M certificates & certification paths, and M2M
 * certificate revocation lists (CRLs).
 *
 * @see java.security.cert.CertificateFactorySpi
 * @see M2mCertificate
 */
public class M2mCertificateFactory extends CertificateFactorySpi {
    /**
     * Generates a certificate object and initializes it with the data read from the {@link
     * java.io.InputStream InputStream} {@code inStream}.
     *
     * <p>
     * The returned certificate object can be casted to the {@link M2mCertificate M2MCertificate}
     * class.
     *
     * <p>
     * The certificate provided in {@code inStream} must be DER-encoded and may be supplied in
     * binary or printable (Base64) encoding. If the certificate is provided in Base64 encoding, it
     * must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be bounded at the
     * end by -----END CERTIFICATE-----.
     *
     * <p>
     * Note that if the given input stream does not support
     * {@link java.io.InputStream#mark(int) mark} and {@link java.io.InputStream#reset() reset},
     * this method will consume the entire input stream. Otherwise, each call to this method
     * consumes one certificate and the read position of the input stream is positioned to the next
     * available byte after the inherent end-of-certificate marker. If the data in the input stream
     * does not contain an inherent end-of-certificate marker (other than EOF) and there is trailing
     * data after the certificate is parsed, a {@link java.security.cert.CertificateException
     * CertificateException} is thrown.
     *
     * @param inStream an input stream with the certificate data.
     *
     * @return a certificate object initialized with the data from the input stream.
     *
     * @exception CertificateException on parsing errors.
     */
    @Override
    public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
        if (inStream == null) {
            throw new IllegalArgumentException("input stream is null");
        }

        try {
            ASN1InputStream aIn = new ASN1InputStream(inStream);
            ASN1ApplicationSpecific app = ASN1ApplicationSpecific.getInstance(aIn.readObject());

            aIn.close();

            int appTag = app.getApplicationTag();

            if (appTag != M2mCertificate.APPLICATION_TAG_NUMBER) {
                throw new IOException("not M2M certificate application tag: " + appTag);
            }

            ASN1Sequence seq = (ASN1Sequence)app.getObject(BERTags.SEQUENCE);
            if (seq.size() != 2) {
                throw new IOException("sequence wrong size for a M2M certificate");
            }

            // Construct M2M certificate
            M2mCertificate cert = new M2mCertificate();
            for (int i = 0; i < seq.size(); i++) {
                ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(i);
                CertificateFields tag = CertificateFields.getInstance(obj.getTagNo());

                switch (tag) {
                    case TBS_CERTIFICATE:
                        ASN1Sequence tbsCertificate = ASN1Sequence.getInstance(obj, false);
                        parseTbsCertificate(tbsCertificate, cert);
                        break;

                    case CA_CALC_VALUE:
                        ASN1OctetString cACalcValue = ASN1OctetString.getInstance(obj, false);
                        cert.setCaCalcValue(cACalcValue.getOctets());
                        break;

                    default:
                        throw new IOException(
                            "unknown M2M data field number: " + tag.getTagNumber());
                }
            }

            return cert;
        } catch (Exception e) {
            // Catch all exceptions and convert it to a CertificateException
            throw new CertificateException("exception on parsing certificate data", e);
        }
    }

    /**
     * Parses the given ASN.1 sequence and return the corresponding {@link M2mCertificate
     * M2MCertificate} object.
     *
     * @param seq ASN.1 sequence containing TBS data.
     * @param cert A M2MCertificate object.
     * @throw InvalidKeyException if public key is invalid.
     * @throw IOException if parsing error.
     * @throw URISyntaxException if URI field is invalid.
     */
    private void parseTbsCertificate(ASN1Sequence seq, M2mCertificate cert)
            throws InvalidKeyException, IOException, URISyntaxException {
        if (seq.size() < 2) {
          throw new IOException("no enough data for TBS certificate in sequence");
        }

        // Set tbsCertificate
        for (int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(i);
            TbsCertificateFields tag = TbsCertificateFields.getInstance(obj.getTagNo());

            switch (tag) {
                case SERIAL_NUMBER:
                    ASN1OctetString serialNumber = ASN1OctetString.getInstance(obj, false);
                    cert.setSerialNumber(serialNumber.getOctets());
                    break;

                case CA_ALGORITHM:
                    ASN1ObjectIdentifier cAAlgorithm = ASN1ObjectIdentifier.getInstance(obj, false);

                    if (cert.getCaKeyDefinition() == null) {
                        cert.setCaKeyDefinition(new KeyAlgorithmDefinition());
                    }
                    cert.getCaKeyDefinition().setAlgorithm(
                            parseKeyAlgorithmDefinitionAlgorithm(cAAlgorithm));
                    break;

                case CA_ALGORITHM_PARAMETERS:
                    ASN1OctetString cAAlgParams = ASN1OctetString.getInstance(obj, false);

                    if (cert.getCaKeyDefinition() == null) {
                        cert.setCaKeyDefinition(new KeyAlgorithmDefinition());
                    }

                    cert.getCaKeyDefinition().setParameters(cAAlgParams.getOctets());
                    break;

                case ISSUER:
                    ASN1Sequence issuerSeq = ASN1Sequence.getInstance(obj, false);
                    cert.setIssuer(parseEntityName(issuerSeq));
                    break;

                case VALID_FROM:
                    ASN1OctetString validFrom = ASN1OctetString.getInstance(obj, false);
                    BigInteger dateTimeBInt = new BigInteger(validFrom.getOctets());

                    // date in sequence is second, converts to millisecond for constructing Date
                    long dateTime = dateTimeBInt.longValue() * 1000;

                    cert.setValidFrom(new Date(dateTime));
                    break;

                case VALID_DURATION:
                    ASN1OctetString validDuration = ASN1OctetString.getInstance(obj, false);
                    BigInteger duration = new BigInteger(validDuration.getOctets());

                    cert.setValidDuration(new Integer(duration.intValue()));
                    break;

                case SUBJECT:
                    ASN1Sequence subjectSeq = ASN1Sequence.getInstance(obj, false);
                    cert.setSubject(parseEntityName(subjectSeq));
                    break;

                case PUBLIC_KEY_ALGORITHM:
                    ASN1ObjectIdentifier pKAlgorithm = ASN1ObjectIdentifier.getInstance(obj, false);

                    if (cert.getPublicKeyDefinition() == null) {
                        cert.setPublicKeyDefinition(new KeyAlgorithmDefinition());
                    }

                    cert.getPublicKeyDefinition().setAlgorithm(
                            parseKeyAlgorithmDefinitionAlgorithm(pKAlgorithm));
                    break;

                case PUBLIC_KEY_ALGORITHM_PARAMETERS:
                    ASN1OctetString pKAlgParams = ASN1OctetString.getInstance(obj, false);

                    if (cert.getPublicKeyDefinition() == null) {
                        cert.setPublicKeyDefinition(new KeyAlgorithmDefinition());
                    }

                    cert.getPublicKeyDefinition().setParameters(pKAlgParams.getOctets());
                    break;

                case PUBLIC_KEY:
                    ASN1OctetString pubKey = ASN1OctetString.getInstance(obj, false);
                    byte[] rawPublicKey = pubKey.getOctets();
                    cert.setIsPublicKeyCompressed(
                        KeyConversionUtils.isCompressedEcPoint(rawPublicKey));
                    PublicKey publicKey =
                        KeyConversionUtils.convertRawBytestoEcPublicKey(rawPublicKey);
                    cert.setPublicKey(publicKey);
                    break;

                case AUTHORITY_KEY_ID:
                    ASN1Sequence authKeyIdSeq = ASN1Sequence.getInstance(obj, false);
                    cert.setAuthorityKeyIdentifier(parseAuthorityKeyIdentifier(authKeyIdSeq));
                    break;

                case SUBJECT_KEY_ID:
                    ASN1OctetString subjKeyId = ASN1OctetString.getInstance(obj, false);
                    cert.setSubjectKeyIdentifier(subjKeyId.getOctets());
                    break;

                case KEY_USAGE:
                    ASN1OctetString keyUsageObj = ASN1OctetString.getInstance(obj, false);
                    KeyUsage keyUsage = new KeyUsage(keyUsageObj.getEncoded());
                    cert.setKeyUsage(keyUsage);
                    break;

                case BASIC_CONSTRAINTS:
                    ASN1Integer basicConstraints = ASN1Integer.getInstance(obj, false);
                    cert.setBasicConstraints(basicConstraints.getValue().intValue());
                    break;

                case CERTIFICATE_POLICY:
                    ASN1ObjectIdentifier certPolicy = ASN1ObjectIdentifier.getInstance(obj, false);
                    cert.setCertificatePolicy(certPolicy.getId());
                    break;

                case SUBJECT_ALTERNATE_NAME:
                    ASN1TaggedObject subjectAltNameObj = ASN1TaggedObject.getInstance(obj, true);
                    cert.setSubjectAlternativeName(parseGeneralName(subjectAltNameObj));
                    break;

                case ISSUER_ALTERNATE_NAME:
                    ASN1TaggedObject issuerAltNameObj = ASN1TaggedObject.getInstance(obj, true);
                    cert.setIssuerAlternativeName(parseGeneralName(issuerAltNameObj));
                    break;

                case EXTENDED_KEY_USAGE:
                    ASN1ObjectIdentifier extendedKeyUsage =
                        ASN1ObjectIdentifier.getInstance(obj, false);
                    cert.setExtendedKeyUsage(extendedKeyUsage.getId());
                    break;

                case AUTHENTICATION_INFO_ACCESS_OCSP:
                    DERIA5String authInfoAccessOCSPObj = DERIA5String.getInstance(obj, false);
                    URI authInfoAccessOCSP = new URI(authInfoAccessOCSPObj.getString());
                    cert.setAuthenticationInfoAccessOcsp(authInfoAccessOCSP);
                    break;

                case CRL_DISTRIBUTION_POINT_URI:
                    DERIA5String cRLDistribPointURIObj = DERIA5String.getInstance(obj, false);
                    URI cRLDistribPointURI = new URI(cRLDistribPointURIObj.getString());
                    cert.setCrlDistributionPointUri(cRLDistribPointURI);
                    break;

                case EXTENSIONS:
                    ASN1Sequence x509extensionsSeq = ASN1Sequence.getInstance(obj, false);
                    parseX509extensions(x509extensionsSeq, cert);
                    break;

                default:
                    throw new IOException(
                        "unknow TBS certificate field number: " + tag.getTagNumber());
            }
        }
    }

    /**
     * Parses ASN.1 object identifier to construct a {@link SignatureAlgorithmOids} object.
     *
     * @param oid ASN.1 object identifier.
     * @return An instance of {@link SignatureAlgorithmOids} constructed from oid.
     */
    private SignatureAlgorithmOids parseKeyAlgorithmDefinitionAlgorithm(ASN1ObjectIdentifier oid) {
        SignatureAlgorithmOids algorithm = null;

        if (oid == null || oid.getId() == null || oid.getId().equals("")) {
            return null;
        }

        try {
            // try M2MSignatureAlgorithmOids first
            algorithm = M2mSignatureAlgorithmOids.getInstance(oid.getId());
        } catch (IllegalArgumentException e) {
            // try NfcSignatureAlgorithmOids now. Throws IllegalArgumentException if unknown OID
            algorithm = NfcSignatureAlgorithmOids.getInstance(oid.getId());
        }

        return algorithm;
    }

    /**
     * Parses ASN.1 sequence to construct an {@link EntityName} object.
     *
     * @param seq ASN.1 sequence data for {@link EntityName}.
     * @return An instance of {@link EntityName} constructed from seq.
     * @throw IOException if parsing has error or not enough data or too much data
     */
    private EntityName parseEntityName(ASN1Sequence seq) throws IOException {
        if (seq.size() < EntityName.MINIMUM_ATTRIBUTES) {
            throw new IOException("no name attribute in sequence");
        } else if (seq.size() > EntityName.MAXIMUM_ATTRIBUTES) {
            throw new IOException("too many name attributes in sequence:" + seq.size());
        }

        EntityName name = new EntityName();

        for (int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(i);
            name.addAttribute(parseEntityNameAttribute(obj));
        }

        return name;
    }

    /**
     * Parses ASN.1 tagged object to construct an {@link EntityNameAttribute} object.
     *
     * @param obj ASN.1 tagged object for {@link EntityNameAttribute}.
     * @return An instance of {@link EntityNameAttribute} constructed from obj.
     * @throw IOException if parsing has error or unknown ID or no value.
     */
    private EntityNameAttribute parseEntityNameAttribute(ASN1TaggedObject obj) throws IOException {
        EntityNameAttributeId aid = EntityNameAttributeId.getInstance(obj.getTagNo());
        String value = null;

        switch (aid) {
            case Country:
            case DistinguishedNameQualifier:
            case SerialNumber:
                value = DERPrintableString.getInstance(obj, false).getString();
                break;

            case Organization:
            case OrganizationalUnit:
            case StateOrProvince:
            case Locality:
            case CommonName:
                value = DERUTF8String.getInstance(obj, false).getString();
                break;

            case DomainComponent:
                value = DERIA5String.getInstance(obj, false).getString();
                break;

            case RegisteredId:
                value = ASN1ObjectIdentifier.getInstance(obj, false).getId();
                break;

            case OctetsName:
                byte[] octets = ASN1OctetString.getInstance(obj, false).getOctets();
                value = Hex.toHexString(octets);
                break;

            default:
                throw new IOException("unknown entity name attribute id: " + aid.getIndexId());
        }

        if (value == null) {
            throw new IOException("null entity name attribute value for id: " + aid.getIndexId());
        }

        EntityNameAttribute attribute = new EntityNameAttribute();
        attribute.setId(aid);
        attribute.setValue(value);

        if (!attribute.isValid()) {
            throw new IOException(
                "invalid entity name attribute value for id: " + aid.getIndexId());
        }

        return attribute;
    }

    /**
     * Parses ASN.1 sequence to construct an {@link AuthorityKeyIdentifier} object.
     *
     * @param seq An ASN.1 sequence.
     * @return An instance of {@link AuthorityKeyIdentifier} constructed from seq.
     * @throw IOException if parsing error or data invalid.
     */
    private AuthorityKeyIdentifier parseAuthorityKeyIdentifier(ASN1Sequence seq)
            throws IOException {
        if (seq.size() < 1) {
            throw new IOException("no authKeyId data in sequence");
        } else if (seq.size() > 3) {
            throw new IOException("too much authKeyId data in sequence: " + seq.size());
        }

        AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();

        for (int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(i);

            switch (obj.getTagNo()) {
                case AuthorityKeyIdentifier.INDEX_KEY_IDENTIFIER:
                    ASN1OctetString identifierObj = ASN1OctetString.getInstance(obj, false);
                    authKeyId.setKeyIdentifier(identifierObj.getOctets());
                    break;

                case AuthorityKeyIdentifier.INDEX_AUTH_CERT_ISSUER:
                    ASN1TaggedObject authCertIssuerObj = ASN1TaggedObject.getInstance(obj, true);
                    authKeyId.setCertificateIssuer(parseGeneralName(authCertIssuerObj));
                    break;

                case AuthorityKeyIdentifier.INDEX_AUTH_CERT_SERIAL_NUM:
                    ASN1OctetString authCertSerialNumObj = ASN1OctetString.getInstance(obj, false);
                    BigInteger serialNumber = new BigInteger(authCertSerialNumObj.getOctets());
                    authKeyId.setCertificateSerialNumber(serialNumber);
                    break;

                default:
                    throw new IOException("unknown authKeyId index: " + obj.getTagNo());
            }
        }

        if (!authKeyId.isValid()) {
            throw new IOException(
                "invalid AuthorityKeyIdentifier instance parsed from ASN.1 sequence");
        }

        return authKeyId;
    }

    /**
     * Parses ASN.1 tagged object to construct a {@link GeneralName} object.
     *
     * @param obj An ASN.1 tagged object.
     * @return An instance of {@link GeneralName} constructed from obj.
     * @throw IOException if parsing error or data invalid.
     */
    private GeneralName parseGeneralName(ASN1TaggedObject obj) throws IOException {
        GeneralName name = new GeneralName();
        GeneralNameAttributeId id = GeneralNameAttributeId.getInstance(obj.getTagNo());

        switch (id) {
            case Rfc822Name:
                DERIA5String rfc822NameObj = DERIA5String.getInstance(obj, false);
                name.setAttributeId(GeneralNameAttributeId.Rfc822Name);
                name.setValue(rfc822NameObj.getString());
                break;

            case DnsName:
                DERIA5String dNSNameObj = DERIA5String.getInstance(obj, false);
                name.setAttributeId(GeneralNameAttributeId.DnsName);
                name.setValue(dNSNameObj.getString());
                break;

            case DirectoryName:
                ASN1Sequence directoryNameSeq = ASN1Sequence.getInstance(obj, false);
                name.setEntity(parseEntityName(directoryNameSeq));
                break;

            case Uri:
                DERIA5String uriObj = DERIA5String.getInstance(obj, false);
                name.setAttributeId(GeneralNameAttributeId.Uri);
                name.setValue(uriObj.getString());
                break;

            case IpAddress:
                ASN1OctetString iPAddressObj = ASN1OctetString.getInstance(obj, false);
                String iPAddress =
                    InetAddress.getByAddress(iPAddressObj.getOctets()).getHostAddress();
                name.setAttributeId(GeneralNameAttributeId.IpAddress);
                name.setValue(iPAddress);
                break;

            case RegisteredId:
                ASN1ObjectIdentifier registeredIDObj = ASN1ObjectIdentifier.getInstance(obj, false);
                name.setAttributeId(GeneralNameAttributeId.RegisteredId);
                name.setValue(registeredIDObj.getId());
                break;

            default:
                throw new IOException("unknown GeneralName ID: " + id.getIndexId());
        }

        if (!name.isValid()) {
            throw new IOException("invalid GeneralName instance parsed from ASN.1 tagged object");
        }

        return name;
    }

    /**
     * Parses ASN.1 sequence to set up X.509 extentions of a {@link M2mCertificate} object.
     *
     * @param seq An ASN.1 sequence containing X.509 extentions.
     * @param cert A {@link M2mCertificate} object to be filled.
     * @throw IOException if parsing error or data invalid.
     */
    private void parseX509extensions(ASN1Sequence seq, M2mCertificate cert) throws IOException {
        if (seq.size() < 1) {
            throw new IOException("not X.509 extension data in sequence");
        }

        for (int i = 0; i < seq.size(); i++) {
            ASN1Sequence extSeq = (ASN1Sequence)seq.getObjectAt(i);
            if (extSeq.size() < 2) {
                throw new IOException("no enough data fields for X.509 extension in sequence");
            } else if (extSeq.size() > 3) {
                throw new IOException("too many data fields for X.509 extension in sequence");
            }

            String oid = null;
            boolean isCritical = false;
            byte[] value = null;

            for (int j = 0; j < extSeq.size(); j++) {
                ASN1TaggedObject obj = (ASN1TaggedObject)extSeq.getObjectAt(j);
                switch (obj.getTagNo()) {
                    case 0: // oid
                        ASN1ObjectIdentifier oidObj = ASN1ObjectIdentifier.getInstance(obj, false);
                        oid = oidObj.getId();
                        break;

                    case 1: // isCritical
                        ASN1Boolean isCriticalObj = ASN1Boolean.getInstance(obj, false);
                        isCritical = isCriticalObj.isTrue();
                        break;

                    case 2: // value
                        ASN1OctetString valueObj = ASN1OctetString.getInstance(obj, false);
                        value = valueObj.getOctets();
                        break;

                    default:
                        throw new IOException("unknown x509extension ID: " + obj.getTagNo());
                }
            }

            cert.addExtension(oid, isCritical, value);
        }
    }

    /**
     * Generates a {@link java.security.cert.CertPath CertPath} object and initializes it with the
     * data read from the {@link java.io.InputStream InputStream} inStream. The data is assumed to
     * be in the default encoding.
     *
     * NOTE: Assuming default certificate encoding path is PkiPath which means the certificates are
     * stored in order from root to signer.
     *
     * <p>
     * The returned certificate path object can be typecast to the {@link M2mCertPath} class.
     *
     * @param inStream an {@link java.io.InputStream InputStream} containing the data
     * @return a {@link java.security.cert.CertPath CertPath} initialized with the data from the
     *         {@link java.io.InputStream InputStream}
     * @exception CertificateException if an exception occurs while decoding
     */
    @Override
    public CertPath engineGenerateCertPath(InputStream inStream) throws CertificateException {
        return engineGenerateCertPath(inStream, SupportedEncodings.PKIPATH.getId());
    }

    /**
     * Generates a {@link java.security.cert.CertPath CertPath} object and initializes it with the
     * data read from the {@link java.io.InputStream InputStream} inStream. The data is assumed to
     * be in the specified encoding.
     *
     * <p>
     * The returned certificate path object can be typecast to the {@link M2mCertPath} class.
     *
     * @param inStream an {@link java.io.InputStream InputStream} containing the data
     * @param encoding the encoding used for the data
     * @return a {@link java.security.cert.CertPath CertPath} initialized with the data from the
     *         {@link java.io.InputStream InputStream}
     * @exception CertificateException if an exception occurs while decoding or the encoding
     *            requested is not supported
     */
    @Override
    public CertPath engineGenerateCertPath(InputStream inStream, String encoding)
            throws CertificateException {
        if (inStream == null) {
            throw new CertificateException("input stream is null");
        }

        try {
            ASN1InputStream aIn = new ASN1InputStream(inStream);
            ASN1Sequence seq = ASN1Sequence.getInstance(aIn.readObject());

            aIn.close();

            ASN1Encodable[] objs;
            List<M2mCertificate> certList;
            InputStream is;
            M2mCertificate cert;

            if (encoding.equals(SupportedEncodings.PKIPATH.getId())) {
                objs = seq.toArray();
                certList = new ArrayList<M2mCertificate>(objs.length);

                // certificates in PKIPATH encoding is from root to signer but M2MCerPath stores
                // certificates from signer to root so do it in reverse order.
                for (int i = objs.length - 1; i >= 0; i--) {
                    is = new ByteArrayInputStream(objs[i].toASN1Primitive().getEncoded());
                    cert = (M2mCertificate)engineGenerateCertificate(is);
                    certList.add(cert);
                }
            } else if (encoding.equals(SupportedEncodings.PKCS7.getId())) {
                ContentInfo ci = ContentInfo.getInstance(seq);
                SignedData sd = SignedData.getInstance(ci.getContent());
                objs = sd.getCertificates().toArray();
                certList = new ArrayList<M2mCertificate>(objs.length);
                // certificates in PKCS7 encoding is from signer to root, the same order as in
                // M2mCertPath
                for (int i = 0; i < objs.length; i++) {
                    is = new ByteArrayInputStream(objs[i].toASN1Primitive().getEncoded());
                    cert = (M2mCertificate)engineGenerateCertificate(is);
                    certList.add(cert);
                }
            } else {
                throw new CertificateException("unknown encoding path: " + encoding);
            }

            return new M2mCertPath(certList);
        } catch (IOException e) {
            throw new CertificateException("IOException parsing PkiPath data: " + e, e);
        }
    }

    /**
     * Generates a {@link java.security.cert.CertPath CertPath} object and initializes it with a
     * {@link java.util.List List} of {@link M2mCertificate}s.
     *
     * <p>The returned certificate path object can be typecast to the {@link M2mCertPath} class.
     *
     * @param certificates a {@link java.util.List List} of {@link M2mCertificate}s
     * @return a {@link java.security.cert.CertPath CertPath} initialized with the supplied list of
     *         M2M certificates
     * @exception CertificateException if an exception occurs
     */
    @Override
    public CertPath engineGenerateCertPath(List<? extends Certificate> certificates)
            throws CertificateException {
        List<M2mCertificate> certList = new ArrayList<M2mCertificate>();

        for (Certificate obj : certificates) {
            // Ensure that the List contains only M2MCertificate
            if ((obj instanceof M2mCertificate) == false) {
                throw new CertificateException(
                  "List is not all M2MCertificate: " + obj.getClass().getName());
            }
            certList.add((M2mCertificate)obj);
        }

        return new M2mCertPath(certList);
    }

    /**
     * Returns an iteration of the {@link java.security.cert.CertPath CertPath} encodings supported
     * by this certificate factory with the default encoding first. See the CertPath Encodings
     * section in the <a href="{@docRoot}/../technotes/guides/security/StandardNames.html#
     * CertPathEncodings"> Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard encoding names.
     * <p>
     * Attempts to modify the returned {@link java.util.Iterator Iterator} via its
     * {@link java.util.Iterator#remove() remove} method result in an
     * {@link java.lang.UnsupportedOperationException UnsupportedOperationException}.
     *
     * @return an {@link java.util.Iterator Iterator} over the names of the supported
     *         {@link java.security.cert.CertPath CertPath} encodings (as {@link java.lang.String
     *         String}s)
     */
    @Override
    public Iterator<String> engineGetCertPathEncodings() {
        return SupportedEncodings.getSupportedEncodings().listIterator();
    }

    /**
     * Returns a (possibly empty) collection view of the certificates read from the given input
     * stream {@code inStream}.
     *
     * <p>
     * The elements in the returned collection can be typecast to the {@link M2mCertificate}
     * class.
     *
     * <p>
     * The {@code inStream} may contain a single DER-encoded certificate in the formats described
     * for {@link java.security.cert.CertificateFactory#generateCertificate(java.io.InputStream)
     * generateCertificate}. In addition, {@code inStream} may contain a PKCS#7 certificate chain.
     * This is a PKCS#7 <i>SignedData</i> object, with the only significant field being
     * <i>certificates</i>. In particular, the signature and the contents are ignored. This format
     * allows multiple certificates to be downloaded at once. If no certificates are present, an
     * empty collection is returned.
     *
     * <p>
     * Note that if the given input stream does not support
     * {@link java.io.InputStream#mark(int) mark} and {@link java.io.InputStream#reset() reset},
     * this method will consume the entire input stream.
     *
     * @param inStream the input stream with the certificates.
     *
     * @return a (possibly empty) collection view of {@link java.security.cert.Certificate
     *         Certificate} objects initialized with the data from the input stream.
     *
     * @exception CertificateException on parsing errors.
     */
    @Override
    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream)
            throws CertificateException {
        // makes input markable if it's not
        if (inStream.markSupported() == false) {
            try {
                byte[] inData = new byte[inStream.available()];
                inStream.read(inData);
                inStream = new ByteArrayInputStream(inData);
            } catch (Exception e) {
                throw new CertificateException(
                    "exception on constructing ByteArrayInputStream" + e, e);
            }
        }
        // marks reading start postion
        inStream.mark(0);

        CertPath certPath;

        try {
            // try PkiPath
            certPath = engineGenerateCertPath(inStream, SupportedEncodings.PKIPATH.getId());
        } catch (Exception e) {
            try {
                // try PKCS#7
                inStream.reset();
                certPath = engineGenerateCertPath(inStream, SupportedEncodings.PKCS7.getId());
            } catch (IOException e1) {
                throw new CertificateException("IOException: " + e1, e1);
            } catch (Exception e1) {
                throw new CertificateException("unknown certificate path encoding: " + e1, e1);
            }
        }

        return certPath.getCertificates();
    }

    /**
     * Generates a certificate revocation list (CRL) object and initializes it with the data read
     * from the input stream {@code inStream}.
     *
     * <p>
     * The returned CRL object can be typecast to the {@link M2mCrl} class.
     *
     * <p>
     * Note that if the given input stream does not support
     * {@link java.io.InputStream#mark(int) mark} and {@link java.io.InputStream#reset() reset},
     * this method will consume the entire input stream. Otherwise, each call to this method
     * consumes one CRL and the read position of the input stream is positioned to the next
     * available byte after the inherent end-of-CRL marker. If the data in the input stream does not
     * contain an inherent end-of-CRL marker (other than EOF) and there is trailing data after the
     * CRL is parsed, a {@code CRLException} is thrown.
     *
     * @param inStream an input stream with the CRL data.
     *
     * @return a CRL object initialized with the data from the input stream.
     *
     * @exception CRLException on parsing errors.
     */
    @Override
    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        return null;
    }

    /**
     * Returns a (possibly empty) collection view of the CRLs read from the given input stream
     * {@code inStream}.
     *
     * <p>
     * The elements in the returned collection can be typecast to the {@link M2mCrl} class.
     *
     * <p>
     * The {@code inStream} may contain a single DER-encoded CRL. In addition, {@code inStream}
     * may contain a PKCS#7 CRL set. This is a PKCS#7 <i>SignedData</i> object, with the only
     * significant field being <i>crls</i>. In particular, the signature and the contents are
     * ignored. This format allows multiple CRLs to be downloaded at once. If no CRLs are present,
     * an empty collection is returned.
     *
     * <p>
     * Note that if the given input stream does not support
     * {@link java.io.InputStream#mark(int) mark} and {@link java.io.InputStream#reset() reset},
     * this method will consume the entire input stream.
     *
     * @param inStream the input stream with the CRLs.
     *
     * @return a (possibly empty) collection view of {@link java.security.cert.CRL CRL} objects
     *         initialized with the data from the input stream.
     *
     * @exception CRLException on parsing errors.
     */
    @Override
    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream) throws CRLException {
        return Collections.<M2mCrl>emptyList();
    }
}
