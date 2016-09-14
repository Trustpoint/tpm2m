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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.M2mProvider M2MProvider} class.
 */
public class M2mProviderTest {
  private static final M2mCertificate rootCertificate = new M2mCertificate();
  private static final M2mCertificate issuerCertificate = new M2mCertificate();
  private static final M2mCertificate signerCertificate = new M2mCertificate();

  @BeforeClass
  public static void initializeTests() throws Exception {
    Security.addProvider(new M2mProvider());

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
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mProvider} when used with
   * {@link java.security.cert.CertPathValidator CertPathValidator}.
   */
  @Test
  public void testM2MProviderCertPathValidator() throws Exception {
    CertPathValidator validator = CertPathValidator.getInstance("M2M", M2mProvider.PROVIDER_NAME);

    assertEquals("M2M", validator.getAlgorithm());
    assertEquals(M2mProvider.class, validator.getProvider().getClass());

    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath path = new M2mCertPath(certificates);

    Calendar validityDate = new GregorianCalendar(2016, 7, 5);
    M2mCertPathParameters params = new M2mCertPathParameters(null, validityDate.getTime(), true);

    M2mCertPathValidatorResult result =
        (M2mCertPathValidatorResult) validator.validate(path, params);

    assertEquals(rootCertificate, result.getTrustAnchor().getCertificate());
    assertArrayEquals(
        signerCertificate.getPublicKey().getEncoded(), result.getPublicKey().getEncoded());
  }


  /**
   * Test method for {@link ca.trustpoint.m2m.M2mProvider} when used with
   * {@link java.security.cert.CertificateFactory CertificateFactory}.
   */
  @Test
  public void testM2MProviderCertificateFactory() throws Exception {
    CertificateFactory factory = CertificateFactory.getInstance("M2M", M2mProvider.PROVIDER_NAME);

    assertEquals("M2M", factory.getType());
    assertEquals(M2mProvider.class, factory.getProvider().getClass());

    byte[] certificateBytes =
        Base64.decode(
            "dIIBTqCBvYEBAoIFK4E6AQ2kCoYIYmx1ZWxpbmWFBFeXxRGGBAHhM4CnCoYIYmx1ZWxpbmWIBSuBOgEN" +
            "ioGFBAB47wWdYFq4W2olpu8xoac6Yy08sE3GBqjKC1gjlmFoz69hMdjZtT9r32tilG7EtB1hj6P/f4u/" +
            "rL/U9k/jwz2p0gCkeuUo3FC284dtf1ujwILZkndR4ajE+TTZCUKzXFff4xGyZj6NAYetTt4xv5zSrYMX" +
            "EHNgUi/baXWrLNZtwCmYH4GBizCBiAJCAU8VyvjvOGJrLHz6hblUTgKGaCkMrbRfYuIVPqr1qdUa9b8N" +
            "AvLAV9OFa1y/s1KcJbhIFAWSQDn6YS1CKumhqFWRAkIBho09/l/Cvt0vdGiwsX7ScI52zQ03xE9NC7iG" +
            "k3UgRvz8VtmBizJTO4mSkjwsgUmUAKxE+77NYyTYrh3UHsc6Cyo=");
    ByteArrayInputStream byteStream = new ByteArrayInputStream(certificateBytes);

    M2mCertificate certificate = (M2mCertificate) factory.generateCertificate(byteStream);

    assertEquals(rootCertificate, certificate);
  }
}
