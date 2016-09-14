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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.trustpoint.m2m.M2mCertPath.SupportedEncodings;
import ca.trustpoint.m2m.util.KeyConversionUtils;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.M2mCertificateFactory} class.
 */
public class M2mCertificateFactoryTest {
  private static byte[] fullCertData;
  private static byte[] rootcaData;
  private static byte[] issuerData;
  private static byte[] signerData;
  private static byte[] pkiPathInputData;
  private static byte[] pkcs7InputData;
  private static byte[][] expectedCertPathData;
  private static final SupportedEncodings[] expectedEncodings = {
    SupportedEncodings.PKIPATH,
    SupportedEncodings.PKCS7
  };

  static {
    // A certificate chain
    rootcaData = Base64.decode(
      "dIIBTqCBvYEBAoIFK4E6AQ2kCoYIYmx1ZWxpbmWFBFeXxRGGBAHhM4CnCoYIYmx1ZWxpbmWIBSuBOgEN" +
      "ioGFBAB47wWdYFq4W2olpu8xoac6Yy08sE3GBqjKC1gjlmFoz69hMdjZtT9r32tilG7EtB1hj6P/f4u/" +
      "rL/U9k/jwz2p0gCkeuUo3FC284dtf1ujwILZkndR4ajE+TTZCUKzXFff4xGyZj6NAYetTt4xv5zSrYMX" +
      "EHNgUi/baXWrLNZtwCmYH4GBizCBiAJCAU8VyvjvOGJrLHz6hblUTgKGaCkMrbRfYuIVPqr1qdUa9b8N" +
      "AvLAV9OFa1y/s1KcJbhIFAWSQDn6YS1CKumhqFWRAkIBho09/l/Cvt0vdGiwsX7ScI52zQ03xE9NC7iG" +
      "k3UgRvz8VtmBizJTO4mSkjwsgUmUAKxE+77NYyTYrh3UHsc6Cyo=");
    issuerData = Base64.decode(
      "dIIBB6B4gQFlggUrgToBDaQKhghibHVlbGluZYUEV5kOX4YEA8JnAKcKhghNeUlzc3VlcogFK4E6AQmK" +
      "QQRhWR53nuSCVBz2PvKgcJ09BM6+H2IdR2Tv7MT/N0hkMF43QtqyaQ6Im4SQan0uq0RLngO1Rjk7/Pmy" +
      "s7h2WMb6gYGKMIGHAkIBao9QiZGTvYX/NpZRKfhvZCkLZPrUDnVco2fTGzSE8qVVLdqwWxJGMEz8QWTi" +
      "mVDVbeoEu02aPUieBxBtHT80Zp0CQWMe0IzX7q/mEUGJU8ZPGmCXtF0au1+5OQo86u2rPEf/PnoadU4e" +
      "DVOywv7pDrFOvaC08VJgw3X/wYaKdWm1Bf8I");
    signerData = Base64.decode(
      "dIG8oHGBAWiCBSuBOgEJpAqGCE15SXNzdWVyhQRXomvMhgQDwmcApwqGCE15U2lnbmVyikEEY8d5z/RO" +
      "s8l9fN+as62abtDctvPxoxVd9nQQmjqtCnV/yvLwHlPN7SVwetw4wicekLtVTbTtR7ZbJbtHjp47+IFH" +
      "MEUCIQDL2Wnu62N6A9YLMnG9cyDno92hse8BTmQfbDK/iX7qxgIgMP9//TpZybFvLzNXFrR0AqPP8+5m" +
      "d2eokBfSGCA81m4=");
  }

  @BeforeClass
  public static void initializeTests() throws Exception {
    // Construct certificate data
    // A full certificate
    M2mCertificate cert = new M2mCertificate();

    // serialNumber
    byte[] serialNumber = Hex.decode("F964EF36");
    cert.setSerialNumber(serialNumber);

    // cAAlgorithm, CAAlgParams
    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);
    caKeyDefinition.setParameters(Hex.decode("102030405060708090A0B0C0E0F0"));
    cert.setCaKeyDefinition(caKeyDefinition);

    // issuer
    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyRoot"));
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "DomC"));
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.OctetsName, "ca2f00"));
    cert.setIssuer(issuer);

    // validFrom
    Calendar calendar = new GregorianCalendar(2016, 7, 1);
    Date validFrom = calendar.getTime();
    cert.setValidFrom(validFrom);

    // validDuration
    cert.setValidDuration(60 * 60 * 24 * 365);

    // subject
    EntityName subject = new EntityName();
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyTest"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "DomC"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.OctetsName, "ca2f01"));
    cert.setSubject(subject);

    // pKAlgorithm, pKAlgParams
    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);
    publicKeyDefinition.setParameters(Hex.decode("0102030405060708090A0B0C0E0F"));
    cert.setPublicKeyDefinition(publicKeyDefinition);

    // pubKey
    byte[] rawPublicKey =
        Hex.decode(
            "040078EF059D605AB85B6A25A6EF31A1A73A632D3CB04DC606A8CA0B58239661" +
            "68CFAF6131D8D9B53F6BDF6B62946EC4B41D618FA3FF7F8BBFACBFD4F64FE3C3" +
            "3DA9D200A47AE528DC50B6F3876D7F5BA3C082D9927751E1A8C4F934D90942B3" +
            "5C57DFE311B2663E8D0187AD4EDE31BF9CD2AD8317107360522FDB6975AB2CD6" +
            "6DC029981F");
    boolean isCompressed = KeyConversionUtils.isCompressedEcPoint(rawPublicKey);
    cert.setIsPublicKeyCompressed(isCompressed);

    PublicKey publicKey = KeyConversionUtils.convertRawBytestoEcPublicKey(rawPublicKey);
    cert.setPublicKey(publicKey);

    // authKeyId
    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    authKeyId.setKeyIdentifier(Hex.decode("793F0C56"));
    GeneralName authKeyIdIssuer =
      new GeneralName(GeneralNameAttributeId.DnsName, "authKeyIdIssuer");
    authKeyId.setCertificateIssuer(authKeyIdIssuer);
    authKeyId.setCertificateSerialNumber(new BigInteger(Hex.decode("729CB27DAE30")));
    cert.setAuthorityKeyIdentifier(authKeyId);

    // subjKeyId
    cert.setSubjectKeyIdentifier(Hex.decode("729CB27DAE31"));

    // keyUsage
    KeyUsage keyUsage = new KeyUsage();
    keyUsage.setDigitalSignature(true);
    cert.setKeyUsage(keyUsage);

    // basicConstraints
    cert.setBasicConstraints(5);

    // certificatePolicy
    cert.setCertificatePolicy("1.2.66.148.0.12");

    // subjectAltName
    GeneralName subjectAltName = new GeneralName(GeneralNameAttributeId.DnsName, "subjectAltName");
    cert.setSubjectAlternativeName(subjectAltName);

    // issuerAltName
    GeneralName issuerAltName = new GeneralName(GeneralNameAttributeId.DnsName, "issuerAltName");
    cert.setIssuerAlternativeName(issuerAltName);

    // extendedKeyUsage
    cert.setExtendedKeyUsage("1.3.22.174.22");

    // authInfoAccessOCSP
    URI authInfoAccessOCSP = new URI("https://ocsptest.trustpointinnovation.com");
    cert.setAuthenticationInfoAccessOcsp(authInfoAccessOCSP);

    // cRLDistribPointURI
    URI cRLDistribPointURI = new URI("https://ocsptest.trustpointinnovation.com");
    cert.setCrlDistributionPointUri(cRLDistribPointURI);

    // x509extensions
    String oid1 = "1.5.24.632.0";
    String oid2 = "1.5.24.632.1";
    byte[] value1 = Hex.decode("003a772fb1");
    byte[] value2 = Hex.decode("98f2b10e27");
    cert.addExtension(oid1, true, value1);
    cert.addExtension(oid2, false, value2);

    // cACalcValue
    byte[] caCalcValue = Hex.decode(
      "3081880242014F15CAF8EF38626B2C7CFA85B9544E028668290CADB45F62E215" +
      "3EAAF5A9D51AF5BF0D02F2C057D3856B5CBFB3529C25B8481405924039FA612D" +
      "422AE9A1A85591024201868D3DFE5FC2BEDD2F7468B0B17ED2708E76CD0D37C4" +
      "4F4D0BB88693752046FCFC56D9818B32533B8992923C2C81499400AC44FBBECD" +
      "6324D8AE1DD41EC73A0B2A");
    cert.setCaCalcValue(caCalcValue);

    // get encoded data
    fullCertData = cert.getEncoded();

    int mySignerIndex = 0;
    int myIssuerIndex = 1;
    int bluelineIndex = 2;
    int certsTotal = 3;

    // construct certificate array
    ASN1Encodable[] certArray = new ASN1Encodable[certsTotal];
    certArray[mySignerIndex] = ASN1Primitive.fromByteArray(signerData);
    certArray[myIssuerIndex] = ASN1Primitive.fromByteArray(issuerData);
    certArray[bluelineIndex] = ASN1Primitive.fromByteArray(rootcaData);
    ASN1EncodableVector vCerts;

    // Construct PKI Path encoding input data
    vCerts = new ASN1EncodableVector();
    vCerts.add(certArray[bluelineIndex]);
    vCerts.add(certArray[myIssuerIndex]);
    vCerts.add(certArray[mySignerIndex]);
    pkiPathInputData = new DERSequence(vCerts).getEncoded();

    // Construct PKCS7 encoding input data
    ASN1EncodableVector vContentInfo = new ASN1EncodableVector();

    // contentType
    ASN1ObjectIdentifier contentType = PKCSObjectIdentifiers.data;
    vContentInfo.add(contentType);

    // content: signedData
    ASN1EncodableVector vSignedData = new ASN1EncodableVector();

    // version
    ASN1Integer sdVersion = new ASN1Integer(BigInteger.ONE);
    vSignedData.add(sdVersion);

    // digestAlgorithmIds
    DERSet sdDigestAlgorithmIds = new DERSet();
    vSignedData.add(sdDigestAlgorithmIds);

    // contentInfo without content
    BERSequence sdContentInfo = new BERSequence(PKCSObjectIdentifiers.data);
    vSignedData.add(sdContentInfo);

    // certificates [0] IMPLICIT SET OF certificate
    vCerts = new ASN1EncodableVector();
    vCerts.add(certArray[mySignerIndex]);
    vCerts.add(certArray[myIssuerIndex]);
    vCerts.add(certArray[bluelineIndex]);

    DERTaggedObject sdCertificates =
        new DERTaggedObject(false, 0, new DERSet(vCerts));
    vSignedData.add(sdCertificates);

    // signerInfos
    DERSet sdSignerInfos = new DERSet();
    vSignedData.add(sdSignerInfos);

    // content [0] EXPLICIT SEQUENCE signedData
    BERSequence signedData = new BERSequence(vSignedData);
    BERTaggedObject content = new BERTaggedObject(true, 0, signedData);
    vContentInfo.add(content);

    BERSequence contentInfo = new BERSequence(vContentInfo);
    pkcs7InputData = contentInfo.getEncoded();

    // Contruct cert path data list
    // Certificates are store in M2MCertPath from target to trust anchor.
    expectedCertPathData = new byte[][] {signerData, issuerData, rootcaData};
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificateFactory#engineGenerateCertificate(InputStream)}.
   */
  @Test
  public void testEngineGenerateCertificateInputStream() throws CertificateException {
    M2mCertificateFactory factory;
    InputStream inStream;
    M2mCertificate cert;

    inStream = new ByteArrayInputStream(fullCertData);
    factory = new M2mCertificateFactory();
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    assertArrayEquals(fullCertData, cert.getEncoded());

    inStream = new ByteArrayInputStream(rootcaData);
    factory = new M2mCertificateFactory();
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    assertArrayEquals(rootcaData, cert.getEncoded());

    inStream = new ByteArrayInputStream(issuerData);
    factory = new M2mCertificateFactory();
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    assertArrayEquals(issuerData, cert.getEncoded());

    inStream = new ByteArrayInputStream(signerData);
    factory = new M2mCertificateFactory();
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    assertArrayEquals(signerData, cert.getEncoded());
  }

  private static void verifyCertificateCollection(Collection<? extends Certificate> certList)
    throws CertificateException {
    Object[] certArray = certList.toArray();

    for (int i = 0; i < certArray.length; i++) {
      M2mCertificate cert = (M2mCertificate)certArray[i];
      //System.out.println("certList[" + i + "]:\n" + cert.toPlainText());
      assertArrayEquals(expectedCertPathData[i], cert.getEncoded());
    }
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificateFactory#engineGenerateCertPath(InputStream)}.
   */
  @Test
  public void testEngineGenerateCertPathInputStream() throws CertificateException {
    InputStream inStream = new ByteArrayInputStream(pkiPathInputData);
    M2mCertificateFactory factory = new M2mCertificateFactory();
    CertPath certPath = factory.engineGenerateCertPath(inStream);
    verifyCertificateCollection(certPath.getCertificates());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificateFactory#engineGenerateCertPath(InputStream, String)}.
   */
  @Test
  public void testEngineGenerateCertPathInputStreamString() throws CertificateException {
    M2mCertificateFactory factory;
    InputStream inStream;
    CertPath certPath;

    // PkiPath
    inStream = new ByteArrayInputStream(pkiPathInputData);
    factory = new M2mCertificateFactory();
    certPath = factory.engineGenerateCertPath(inStream, SupportedEncodings.PKIPATH.getId());
    verifyCertificateCollection(certPath.getCertificates());

    // PKCS7
    inStream = new ByteArrayInputStream(pkcs7InputData);
    factory = new M2mCertificateFactory();
    certPath = factory.engineGenerateCertPath(inStream, SupportedEncodings.PKCS7.getId());
    verifyCertificateCollection(certPath.getCertificates());

    // invalid encoding path
    inStream = new ByteArrayInputStream(pkiPathInputData);
    boolean exceptionFired = false;

    try {
      factory = new M2mCertificateFactory();
      factory.engineGenerateCertPath(inStream, "InvalidEncodingPath");
    } catch (CertificateException e) {
      System.out.println("Expected CertificateException: " + e.getMessage());
      exceptionFired = true;
    }
    assertTrue(exceptionFired);
  }

  /**
   * Test method for
   * {@link com.trustpoint.m2m.M2MCertificateFactory#engineGenerateCertPath(
   * List<? extends Certificate>)}.
   */
  @Test
  public void testEngineGenerateCertPathListCertificate()
      throws CertificateException, NoSuchProviderException {
    M2mCertificateFactory factory;
    InputStream inStream;
    CertPath certPath;

    // Construct a list of M2M certificate
    // NOTE: engineGenerateCertificate() was tested in testEngineGenerateCertificateInputStream(),
    //       so it's okay to use it for generating certificate from certificate raw data here.
    List<M2mCertificate> certs = new ArrayList<M2mCertificate>();
    M2mCertificate cert;

    factory = new M2mCertificateFactory();

    inStream = new ByteArrayInputStream(signerData);
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    certs.add(cert);

    inStream = new ByteArrayInputStream(issuerData);
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    certs.add(cert);

    inStream = new ByteArrayInputStream(rootcaData);
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    certs.add(cert);

    // list of M2MCertificate
    certPath = factory.engineGenerateCertPath(certs);
    verifyCertificateCollection(certPath.getCertificates());

    // list of X509Certificate
    CertificateFactory x509Factory =
        CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

    byte[] x509CertData = Base64.decode(
      "MIIBGzCBwaADAgECAgEBMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2JsYWNrc2Vh" +
      "bGNhMCAXDTE1MDIxMjIyNTcyNVoYDzIxMDAwNjEyMjI1NzI1WjAWMRQwEgYDVQQD" +
      "DAtibGFja3NlYWxjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLK1IMycJvcH" +
      "yo2gkGv/FjxVaOpYZM0iHnFKAD/62qG/mFXKekSoMlZqaUHEVG65/l+yzjj+JLQs" +
      "a23WhS22gUYwCgYIKoZIzj0EAwIDSQAwRgIhAJmaqh38kbajdX+rxQorfaLk30Kx" +
      "mqLpRQ8X68z/kb9PAiEAhETvquCbZQYnKUZCakOv02Dj9LlLApZSPU8NybOBXp4=");
    inStream = new ByteArrayInputStream(x509CertData);
    X509Certificate x509Cert = (X509Certificate)x509Factory.generateCertificate(inStream);

    List<X509Certificate> x509Certs = new ArrayList<X509Certificate>();
    x509Certs.add(x509Cert);

    boolean exceptionThrown = false;

    try {
      factory = new M2mCertificateFactory();
      factory.engineGenerateCertPath(x509Certs);
    } catch (CertificateException e) {
      System.out.println("Expected CertificateException: " + e.getMessage());
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificateFactory#engineGetCertPathEncodings()}.
   */
  @Test
  public void testEngineGetCertPathEncodings() {
    M2mCertificateFactory factory = new M2mCertificateFactory();
    Iterator<String> encodings = factory.engineGetCertPathEncodings();
    int index = 0;

    while (encodings.hasNext()) {
      assertEquals(expectedEncodings[index].getId(), encodings.next());
      index++;
    }
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificateFactory#engineGenerateCertificates(InputStream)}.
   */
  @Test
  public void testEngineGenerateCertificatesInputStream() throws CertificateException {
    M2mCertificateFactory factory;
    InputStream inStream;
    Collection<? extends Certificate> certCollection;

    // PkiPath
    inStream = new ByteArrayInputStream(pkiPathInputData);
    factory = new M2mCertificateFactory();
    certCollection = factory.engineGenerateCertificates(inStream);
    verifyCertificateCollection(certCollection);

    // PKCS7
    inStream = new ByteArrayInputStream(pkcs7InputData);
    factory = new M2mCertificateFactory();
    certCollection = factory.engineGenerateCertificates(inStream);
    verifyCertificateCollection(certCollection);

    // invalid encoding path
    byte[] junkInputData = Hex.decode(
      "7F1309814766EF998B3C975D651A007F534D063C766EF998B3C975D63045022100CBD969EEEB637A03D60B32" +
      "71BD7320E7A3DDA1B1EF014E641F6C32BF897EEAC6022030FF7FFD3A59C9B16F2F335716B47402A3CFF3EE66" +
      "7767A89017D218203CD66E");
    inStream = new ByteArrayInputStream(junkInputData);
    boolean exceptionFired = false;

    try {
      factory = new M2mCertificateFactory();
      factory.engineGenerateCertificates(inStream);
    } catch (CertificateException e) {
      System.out.println("Expected CertificateException: " + e.getMessage());
      exceptionFired = true;
    }
    assertTrue(exceptionFired);
  }
}
