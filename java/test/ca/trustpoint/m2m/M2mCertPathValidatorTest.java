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
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import ca.trustpoint.m2m.EntityName;
import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;
import ca.trustpoint.m2m.KeyAlgorithmDefinition;
import ca.trustpoint.m2m.KeyUsage;
import ca.trustpoint.m2m.M2mCertPath;
import ca.trustpoint.m2m.M2mCertPathParameters;
import ca.trustpoint.m2m.M2mCertPathValidator;
import ca.trustpoint.m2m.M2mCertPathValidatorResult;
import ca.trustpoint.m2m.M2mCertificate;
import ca.trustpoint.m2m.M2mSignatureAlgorithmOids;
import ca.trustpoint.m2m.M2mTrustAnchor;
import ca.trustpoint.m2m.NfcSignatureAlgorithmOids;

/**
 * Unit Tests for the {@link ca.trustpoint.m2m.M2mCertPathValidator M2MCertPathValidator} class.
 */
public class M2mCertPathValidatorTest {
  private static final M2mCertificate rootCertificate = new M2mCertificate();
  private static final M2mCertificate issuerCertificate = new M2mCertificate();
  private static final M2mCertificate signerCertificate = new M2mCertificate();
  private static final M2mCertificate rsaTestCertificate = new M2mCertificate();
  private static X509Certificate x509Ca = null;

  @BeforeClass
  public static void initializeTests() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    KeyAlgorithmDefinition caAlgorithm = new KeyAlgorithmDefinition();
    caAlgorithm.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    Date validFrom = new Date((new BigInteger(Hex.decode("5797C511"))).longValue() * 1000);
    int validDuration = (new BigInteger(Hex.decode("01E13380"))).intValue();

    EntityName subject = new EntityName();
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    KeyAlgorithmDefinition pkAlgorithm = new KeyAlgorithmDefinition();
    pkAlgorithm.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    X962Parameters keyParams = new X962Parameters(SECObjectIdentifiers.secp521r1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, keyParams.toASN1Primitive());
    SubjectPublicKeyInfo publicKeyInfo =
        new SubjectPublicKeyInfo(
            algId,
            Hex.decode(
                "040078EF059D605AB85B6A25A6EF31A1A73A632D3CB04DC606A8CA0B5823966168CFAF6131D8D9B5" +
                "3F6BDF6B62946EC4B41D618FA3FF7F8BBFACBFD4F64FE3C33DA9D200A47AE528DC50B6F3876D7F5B" +
                "A3C082D9927751E1A8C4F934D90942B35C57DFE311B2663E8D0187AD4EDE31BF9CD2AD8317107360" +
                "522FDB6975AB2CD66DC029981F"));
    PublicKey publicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);

    byte[] signature =
        Hex.decode(
            "3081880242014F15CAF8EF38626B2C7CFA85B9544E028668290CADB45F62E2153EAAF5A9D51AF5BF0D02" +
            "F2C057D3856B5CBFB3529C25B8481405924039FA612D422AE9A1A85591024201868D3DFE5FC2BEDD2F74" +
            "68B0B17ED2708E76CD0D37C44F4D0BB88693752046FCFC56D9818B32533B8992923C2C81499400AC44FB" +
            "BECD6324D8AE1DD41EC73A0B2A");

    rootCertificate.setSerialNumber(new byte[] {0x02});
    rootCertificate.setCaKeyDefinition(caAlgorithm);
    rootCertificate.setIssuer(issuer);
    rootCertificate.setValidFrom(validFrom);
    rootCertificate.setValidDuration(validDuration);
    rootCertificate.setSubject(subject);
    rootCertificate.setPublicKeyDefinition(pkAlgorithm);
    rootCertificate.setPublicKey(publicKey);
    rootCertificate.setCaCalcValue(signature);

    caAlgorithm = new KeyAlgorithmDefinition();
    caAlgorithm.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    validFrom = new Date((new BigInteger(Hex.decode("57990E5F"))).longValue() * 1000);
    validDuration = (new BigInteger(Hex.decode("03C26700"))).intValue();

    subject = new EntityName();
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyIssuer"));

    pkAlgorithm = new KeyAlgorithmDefinition();
    pkAlgorithm.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    keyParams = new X962Parameters(SECObjectIdentifiers.secp256r1);
    algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, keyParams.toASN1Primitive());
     publicKeyInfo =
        new SubjectPublicKeyInfo(
            algId,
            Hex.decode(
                "0461591E779EE482541CF63EF2A0709D3D04CEBE1F621D4764EFECC4FF374864305E3742DAB2690E" +
                "889B84906A7D2EAB444B9E03B546393BFCF9B2B3B87658C6FA"));
    publicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);

    signature =
        Hex.decode(
            "3081870242016A8F50899193BD85FF36965129F86F64290B64FAD40E755CA367D31B3484F2A5552DDAB0" +
            "5B1246304CFC4164E29950D56DEA04BB4D9A3D489E07106D1D3F34669D0241631ED08CD7EEAFE6114189" +
            "53C64F1A6097B45D1ABB5FB9390A3CEAEDAB3C47FF3E7A1A754E1E0D53B2C2FEE90EB14EBDA0B4F15260" +
            "C375FFC1868A7569B505FF08");

    issuerCertificate.setSerialNumber(new byte[] {0x65});
    issuerCertificate.setCaKeyDefinition(caAlgorithm);
    issuerCertificate.setIssuer(issuer);
    issuerCertificate.setValidFrom(validFrom);
    issuerCertificate.setValidDuration(validDuration);
    issuerCertificate.setSubject(subject);
    issuerCertificate.setPublicKeyDefinition(pkAlgorithm);
    issuerCertificate.setPublicKey(publicKey);
    issuerCertificate.setCaCalcValue(signature);

    caAlgorithm = new KeyAlgorithmDefinition();
    caAlgorithm.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyIssuer"));

    validFrom = new Date((new BigInteger(Hex.decode("57A26BCC"))).longValue() * 1000);
    validDuration = (new BigInteger(Hex.decode("03C26700"))).intValue();

    subject = new EntityName();
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MySigner"));

    keyParams = new X962Parameters(SECObjectIdentifiers.secp256r1);
    algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, keyParams.toASN1Primitive());
     publicKeyInfo =
        new SubjectPublicKeyInfo(
            algId,
            Hex.decode(
                "0463C779CFF44EB3C97D7CDF9AB3AD9A6ED0DCB6F3F1A3155DF674109A3AAD0A757FCAF2F01E53CD" +
                "ED25707ADC38C2271E90BB554DB4ED47B65B25BB478E9E3BF8"));
    publicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);

    signature =
        Hex.decode(
            "3045022100CBD969EEEB637A03D60B3271BD7320E7A3DDA1B1EF014E641F6C32BF897EEAC6022030FF7F" +
            "FD3A59C9B16F2F335716B47402A3CFF3EE667767A89017D218203CD66E");

    signerCertificate.setSerialNumber(new byte[] {0x68});
    signerCertificate.setCaKeyDefinition(caAlgorithm);
    signerCertificate.setIssuer(issuer);
    signerCertificate.setValidFrom(validFrom);
    signerCertificate.setValidDuration(validDuration);
    signerCertificate.setSubject(subject);
    signerCertificate.setPublicKey(publicKey);
    signerCertificate.setCaCalcValue(signature);

    caAlgorithm = new KeyAlgorithmDefinition();
    caAlgorithm.setAlgorithm(NfcSignatureAlgorithmOids.RSA_SHA256_RSA);

    issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "US"));
    issuer.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "NFC Forum Test RSA CA"));

    validFrom = new Date((new BigInteger(Hex.decode("5418AEDA"))).longValue() * 1000);
    validDuration = (new BigInteger(Hex.decode("05A497A0"))).intValue();

    subject = new EntityName();
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "US"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "UT"));
    subject.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "NFC Forum RSA Test M2M EE 1"));

    algId =
        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, new DERSet(DERNull.INSTANCE));
     publicKeyInfo =
        new SubjectPublicKeyInfo(
            algId,
            Hex.decode(
                "3082010A0282010100E93D3E174F587784C53A4B01C05D2F73CFEC22CCCD1FBCF1B1C5B49A118CE6" +
                "B323640F28DFE1D5882FAFAEFDE9BB9A20347C44347D69F431AEEF5788D2EAE2131E49E3B9FD6A94" +
                "BCE34AFCF88C603BAA8EADBC5E6BC558D1459064F9FF6F6157C472739E90B9A312A5DE67176A03FB" +
                "A77981A6F89F1CA9C0733C67797ED6DB766FC99ABEE0C8D3641D69A9C6FD1E6F33CEE29344374146" +
                "E9A8E3CB141163798FDD9217CF58D93E836EA735D5A7F642F203DE097C1623EB855AB72D81330014" +
                "26163E671C747DB54629C0EAF37342CF16923FCAD53B5CAF2CECCB3876853CE003C3753FA72C1F39" +
                "9A9B5FA7A232792FBE38C995B55B9D105F3C0AC536D841068B0203010001"));
    publicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);

    signature =
        Hex.decode(
            "B6A683AF9B20715210CA38D0DAA647F48270DBF67EDF3E043BFBD02265A035540D50540F877179D6" +
            "1349B9F872AFA41646835F8353CF90049551941B89D79B3FC61B1AADE00E8BA474A4342BDAACA5CD" +
            "28AFC9DD7C505127857224D0278A6E5C9AC4344B3FA36B7FD6E5E54D4D92FBCD717AD4D2FE73C2E6" +
            "2219D6A097970BB4F956AAA948501E4083137992EEBCFA41308687F36DBE8CEC54579C76DE4DE54A" +
            "1D6E007AD22F83BEE86CDEF39A37B4BCCD71D5B0A364C258B94D0B953DC3DA5637874157C3AD7CEC" +
            "3367F3075FA1D8939B27F4062DFBE436F871AECDC6D2A3098793A1212ED192F6B128648FFE764C4D" +
            "3176D64E6594DB295400465395781A37");

    rsaTestCertificate.setSerialNumber(Hex.decode("034F3F184941B948A47F3D59EE625F09"));
    rsaTestCertificate.setCaKeyDefinition(caAlgorithm);
    rsaTestCertificate.setIssuer(issuer);
    rsaTestCertificate.setValidFrom(validFrom);
    rsaTestCertificate.setValidDuration(validDuration);
    rsaTestCertificate.setSubject(subject);
    rsaTestCertificate.setPublicKey(publicKey);
    rsaTestCertificate.setKeyUsage(new KeyUsage((byte) 0xA0));
    rsaTestCertificate.setExtendedKeyUsage("2.16.840.1.114513.29.37");
    rsaTestCertificate.setCrlDistributionPointUri(
        new URI("http://crl.nfctest.example.com/nfctestrsaca.crl"));
    rsaTestCertificate.setCaCalcValue(signature);

    CertificateFactory x509Factory =
        CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

    FileInputStream fileInput =
        new FileInputStream("testdata/digicert_batch_2/NFC Forum Test RSA CA.cer");
    x509Ca = (X509Certificate) x509Factory.generateCertificate(fileInput);
    fileInput.close();
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertPathValidator#
   *     engineValidate(java.security.cert.CertPath, java.security.cert.CertPathParameters)}.
   */
  @Test
  public void testEngineValidateCertPathCertPathParameters() throws Exception {
    boolean exceptionThrown = false;
    M2mCertPathValidator validator = new M2mCertPathValidator();
    M2mCertPathValidatorResult result;

    try {
      validator.engineValidate(null, null);
    } catch (InvalidAlgorithmParameterException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    // list of X509Certificate
    byte[] x509CertData = Base64.decode(
      "MIIBGzCBwaADAgECAgEBMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2JsYWNrc2Vh" +
      "bGNhMCAXDTE1MDIxMjIyNTcyNVoYDzIxMDAwNjEyMjI1NzI1WjAWMRQwEgYDVQQD" +
      "DAtibGFja3NlYWxjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLK1IMycJvcH" +
      "yo2gkGv/FjxVaOpYZM0iHnFKAD/62qG/mFXKekSoMlZqaUHEVG65/l+yzjj+JLQs" +
      "a23WhS22gUYwCgYIKoZIzj0EAwIDSQAwRgIhAJmaqh38kbajdX+rxQorfaLk30Kx" +
      "mqLpRQ8X68z/kb9PAiEAhETvquCbZQYnKUZCakOv02Dj9LlLApZSPU8NybOBXp4=");
    CertificateFactory x509Factory =
      CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
    InputStream inStream = new ByteArrayInputStream(x509CertData);
    Certificate x509Cert = x509Factory.generateCertificate(inStream);
    List<Certificate> x509Certs = new ArrayList<Certificate>();
    x509Certs.add(x509Cert);
    CertPath x509Path = x509Factory.generateCertPath(x509Certs);

    try {
      validator.engineValidate(x509Path, null);
    } catch (InvalidAlgorithmParameterException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath path = new M2mCertPath(certificates);

    Set<TrustAnchor> pkixAnchors = new HashSet<TrustAnchor>();
    pkixAnchors.add(new TrustAnchor((X509Certificate) x509Cert, null));
    PKIXParameters pkixParams = new PKIXParameters(pkixAnchors);

    try {
      validator.engineValidate(path, pkixParams);
    } catch (InvalidAlgorithmParameterException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    Calendar validityDate = new GregorianCalendar(2016, 7, 5);

    M2mCertPathParameters params = new M2mCertPathParameters(null, validityDate.getTime(), true);
    result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);

    assertEquals(rootCertificate, result.getTrustAnchor().getCertificate());
    assertArrayEquals(
        signerCertificate.getPublicKey().getEncoded(), result.getPublicKey().getEncoded());

    params = new M2mCertPathParameters(null, validityDate.getTime(), false);

    try {
      result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);
    } catch (CertPathValidatorException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    certificates.remove(certificates.size() - 1);
    path = new M2mCertPath(certificates);

    try {
      result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);
    } catch (CertPathValidatorException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    List<M2mTrustAnchor> m2mAnchors = new ArrayList<M2mTrustAnchor>();
    m2mAnchors.add(new M2mTrustAnchor(rootCertificate));

    params = new M2mCertPathParameters(m2mAnchors, validityDate.getTime(), false);

    result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);

    assertEquals(rootCertificate, result.getTrustAnchor().getCertificate());
    assertArrayEquals(
        signerCertificate.getPublicKey().getEncoded(), result.getPublicKey().getEncoded());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertPathValidator#
   *     engineValidate(java.security.cert.CertPath, java.security.cert.CertPathParameters)} with
   * a X.509 trust root and an RSA signed certificate.
   *
   * Currently this test fails on signature verification of the EE certificate. The RSA signature
   * may be invalid, but that has yet to be verified.
   */
  @Test
  @Ignore
  public void testEngineValidateCertPathCertPathParametersX509() throws Exception {
    M2mCertPathValidator validator = new M2mCertPathValidator();
    M2mCertPathValidatorResult result;

    List<M2mTrustAnchor> m2mAnchors = new ArrayList<M2mTrustAnchor>();
    m2mAnchors.add(new M2mTrustAnchor(x509Ca));

    Calendar validityDate = new GregorianCalendar(2016, 7, 5);
    M2mCertPathParameters params =
        new M2mCertPathParameters(m2mAnchors, validityDate.getTime(), false);

    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(rsaTestCertificate);

    M2mCertPath path = new M2mCertPath(certificates);

    result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);

    assertEquals(
        m2mAnchors.get(0).getCaName(), result.getTrustAnchor().getCertificate().getSubject());
    assertArrayEquals(
        rsaTestCertificate.getPublicKey().getEncoded(), result.getPublicKey().getEncoded());
  }
}
