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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.trustpoint.m2m.EntityName;
import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;
import ca.trustpoint.m2m.KeyAlgorithmDefinition;
import ca.trustpoint.m2m.M2mCertPath;
import ca.trustpoint.m2m.M2mCertificate;
import ca.trustpoint.m2m.M2mSignatureAlgorithmOids;
import ca.trustpoint.m2m.M2mCertPath.SupportedEncodings;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.M2mCertPath} class.
 */
public class M2mCertPathTest {
  private static final M2mCertificate rootCertificate = new M2mCertificate();
  private static final M2mCertificate issuerCertificate = new M2mCertificate();
  private static final M2mCertificate signerCertificate = new M2mCertificate();
  private static final byte[] expectedPkiPathEncoding;
  private static final byte[] expectedPkcs7Encoding;

  static {
    expectedPkiPathEncoding =
        Hex.decode(
            "3082031C 7482014E A081BD81 01028205 2B813A01 0DA40A86 08626C75 656C696E" +
            "65850457 97C51186 0401E133 80A70A86 08626C75 656C696E 6588052B 813A010D" +
            "8A818504 0078EF05 9D605AB8 5B6A25A6 EF31A1A7 3A632D3C B04DC606 A8CA0B58" +
            "23966168 CFAF6131 D8D9B53F 6BDF6B62 946EC4B4 1D618FA3 FF7F8BBF ACBFD4F6" +
            "4FE3C33D A9D200A4 7AE528DC 50B6F387 6D7F5BA3 C082D992 7751E1A8 C4F934D9" +
            "0942B35C 57DFE311 B2663E8D 0187AD4E DE31BF9C D2AD8317 10736052 2FDB6975" +
            "AB2CD66D C029981F 81818B30 81880242 014F15CA F8EF3862 6B2C7CFA 85B9544E" +
            "02866829 0CADB45F 62E2153E AAF5A9D5 1AF5BF0D 02F2C057 D3856B5C BFB3529C" +
            "25B84814 05924039 FA612D42 2AE9A1A8 55910242 01868D3D FE5FC2BE DD2F7468" +
            "B0B17ED2 708E76CD 0D37C44F 4D0BB886 93752046 FCFC56D9 818B3253 3B899292" +
            "3C2C8149 9400AC44 FBBECD63 24D8AE1D D41EC73A 0B2A7482 0107A078 81016582" +
            "052B813A 010DA40A 8608626C 75656C69 6E658504 57990E5F 860403C2 6700A70A" +
            "86084D79 49737375 65728805 2B813A01 098A4104 61591E77 9EE48254 1CF63EF2" +
            "A0709D3D 04CEBE1F 621D4764 EFECC4FF 37486430 5E3742DA B2690E88 9B84906A" +
            "7D2EAB44 4B9E03B5 46393BFC F9B2B3B8 7658C6FA 81818A30 81870242 016A8F50" +
            "899193BD 85FF3696 5129F86F 64290B64 FAD40E75 5CA367D3 1B3484F2 A5552DDA" +
            "B05B1246 304CFC41 64E29950 D56DEA04 BB4D9A3D 489E0710 6D1D3F34 669D0241" +
            "631ED08C D7EEAFE6 11418953 C64F1A60 97B45D1A BB5FB939 0A3CEAED AB3C47FF" +
            "3E7A1A75 4E1E0D53 B2C2FEE9 0EB14EBD A0B4F152 60C375FF C1868A75 69B505FF" +
            "087481BC A0718101 6882052B 813A0109 A40A8608 4D794973 73756572 850457A2" +
            "6BCC8604 03C26700 A70A8608 4D795369 676E6572 8A410463 C779CFF4 4EB3C97D" +
            "7CDF9AB3 AD9A6ED0 DCB6F3F1 A3155DF6 74109A3A AD0A757F CAF2F01E 53CDED25" +
            "707ADC38 C2271E90 BB554DB4 ED47B65B 25BB478E 9E3BF881 47304502 2100CBD9" +
            "69EEEB63 7A03D60B 3271BD73 20E7A3DD A1B1EF01 4E641F6C 32BF897E EAC60220" +
            "30FF7FFD 3A59C9B1 6F2F3357 16B47402 A3CFF3EE 667767A8 9017D218 203CD66E"
        );
    expectedPkcs7Encoding =
        Hex.decode(
            "30800609 2a864886 f70d0107 01a08030 80020101 31003080 06092a86 4886f70d" +
            "01070100 00a08203 1c7481bc a0718101 6882052b 813a0109 a40a8608 4d794973" +
            "73756572 850457a2 6bcc8604 03c26700 a70a8608 4d795369 676e6572 8a410463" +
            "c779cff4 4eb3c97d 7cdf9ab3 ad9a6ed0 dcb6f3f1 a3155df6 74109a3a ad0a757f" +
            "caf2f01e 53cded25 707adc38 c2271e90 bb554db4 ed47b65b 25bb478e 9e3bf881" +
            "47304502 2100cbd9 69eeeb63 7a03d60b 3271bd73 20e7a3dd a1b1ef01 4e641f6c" +
            "32bf897e eac60220 30ff7ffd 3a59c9b1 6f2f3357 16b47402 a3cff3ee 667767a8" +
            "9017d218 203cd66e 74820107 a0788101 6582052b 813a010d a40a8608 626c7565" +
            "6c696e65 85045799 0e5f8604 03c26700 a70a8608 4d794973 73756572 88052b81" +
            "3a01098a 41046159 1e779ee4 82541cf6 3ef2a070 9d3d04ce be1f621d 4764efec" +
            "c4ff3748 64305e37 42dab269 0e889b84 906a7d2e ab444b9e 03b54639 3bfcf9b2" +
            "b3b87658 c6fa8181 8a308187 0242016a 8f508991 93bd85ff 36965129 f86f6429" +
            "0b64fad4 0e755ca3 67d31b34 84f2a555 2ddab05b 1246304c fc4164e2 9950d56d" +
            "ea04bb4d 9a3d489e 07106d1d 3f34669d 0241631e d08cd7ee afe61141 8953c64f" +
            "1a6097b4 5d1abb5f b9390a3c eaedab3c 47ff3e7a 1a754e1e 0d53b2c2 fee90eb1" +
            "4ebda0b4 f15260c3 75ffc186 8a7569b5 05ff0874 82014ea0 81bd8101 0282052b" +
            "813a010d a40a8608 626c7565 6c696e65 85045797 c5118604 01e13380 a70a8608" +
            "626c7565 6c696e65 88052b81 3a010d8a 81850400 78ef059d 605ab85b 6a25a6ef" +
            "31a1a73a 632d3cb0 4dc606a8 ca0b5823 966168cf af6131d8 d9b53f6b df6b6294" +
            "6ec4b41d 618fa3ff 7f8bbfac bfd4f64f e3c33da9 d200a47a e528dc50 b6f3876d" +
            "7f5ba3c0 82d99277 51e1a8c4 f934d909 42b35c57 dfe311b2 663e8d01 87ad4ede" +
            "31bf9cd2 ad831710 7360522f db6975ab 2cd66dc0 29981f81 818b3081 88024201" +
            "4f15caf8 ef38626b 2c7cfa85 b9544e02 8668290c adb45f62 e2153eaa f5a9d51a" +
            "f5bf0d02 f2c057d3 856b5cbf b3529c25 b8481405 924039fa 612d422a e9a1a855" +
            "91024201 868d3dfe 5fc2bedd 2f7468b0 b17ed270 8e76cd0d 37c44f4d 0bb88693" +
            "752046fc fc56d981 8b32533b 8992923c 2c814994 00ac44fb becd6324 d8ae1dd4" +
            "1ec73a0b 2a310000 00000000 00"
        );
  }

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
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertPath#M2MCertPath(java.util.List)}.
   */
  @Test
  public void testM2MCertPath() throws Exception {
    boolean exceptionThrown = false;
    M2mCertPath path;

    try {
      path = new M2mCertPath(null);
    } catch (IllegalArgumentException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
    exceptionThrown = false;

    FileInputStream certFile = new FileInputStream("testdata/DigiCertGlobalRootG3.crt");

    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    Certificate x509cert = factory.generateCertificate(certFile);

    List<Certificate> x509chain = new ArrayList<Certificate>();
    x509chain.add(x509cert);

    try {
      path = new M2mCertPath(x509chain);
    } catch (IllegalArgumentException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    path = new M2mCertPath(certificates);
    List<? extends Certificate> pathCerts = path.getCertificates();

    assertNotNull(pathCerts);
    assertEquals(3, pathCerts.size());
    assertEquals(signerCertificate, pathCerts.get(0));
    assertEquals(issuerCertificate, pathCerts.get(1));
    assertEquals(rootCertificate, pathCerts.get(2));
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertPath#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws Exception {
    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath certPath = new M2mCertPath(certificates);

    assertArrayEquals(expectedPkiPathEncoding, certPath.getEncoded());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertPath#getEncoded(java.lang.String)}.
   */
  @Test
  public void testGetEncodedString() throws Exception {
    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath certPath = new M2mCertPath(certificates);

    assertArrayEquals(expectedPkiPathEncoding, certPath.getEncoded("PkiPath"));
    assertArrayEquals(expectedPkcs7Encoding, certPath.getEncoded("PKCS7"));

    boolean exceptionThrown = false;

    try {
      certPath.getEncoded("foo");
    } catch (CertificateEncodingException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertPath#
   *        getEncoded(ca.trustpoint.m2m.M2mCertPath.SupportedEncodings)}.
   */
  @Test
  public void testGetEncodedSupportedEncodings() throws Exception {
    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath certPath = new M2mCertPath(certificates);

    assertArrayEquals(expectedPkiPathEncoding, certPath.getEncoded(SupportedEncodings.PKIPATH));
    assertArrayEquals(expectedPkcs7Encoding, certPath.getEncoded(SupportedEncodings.PKCS7));
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertPath#getEncodings()}.
   */
  @Test
  public void testGetEncodings() {
    List<M2mCertificate> certificates = new ArrayList<M2mCertificate>();
    certificates.add(signerCertificate);
    certificates.add(issuerCertificate);
    certificates.add(rootCertificate);

    M2mCertPath certPath = new M2mCertPath(certificates);

    Iterator<String> encodings = certPath.getEncodings();

    assertTrue(encodings.hasNext());
    assertEquals("PkiPath", encodings.next());
    assertTrue(encodings.hasNext());
    assertEquals("PKCS7", encodings.next());
    assertFalse(encodings.hasNext());
  }
}
