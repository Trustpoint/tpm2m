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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.M2mCertificate} class.
 */
public class M2mCertificateTest {
  private static final int SECONDS_PER_DAY = 86400;

  @BeforeClass
  public static void initializeTests() {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#M2MCertificateNew()}.
   */
  @Test
  public void testM2MCertificateNew() {
    M2mCertificate cert = new M2mCertificate();

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setSerialNumber(java.math.BigInteger)}.
   */
  @Test
  public void testSetSerialNumber() {
    M2mCertificate cert = new M2mCertificate();
    byte[] expectedValue = Hex.decode("f2aa85c10b57");
    cert.setSerialNumber(expectedValue);

    assertEquals(0, cert.getVersion());
    assertArrayEquals(expectedValue, cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setSerialNumber(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate# setCaKeyDefinition(ca.trustpoint.m2m.KeyAlgorithmDefinition)}.
   */
  @Test
  public void testSetCaKeyDefinition() {
    M2mCertificate cert = new M2mCertificate();
    KeyAlgorithmDefinition expectedValue =
        new KeyAlgorithmDefinition(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1, null);
    cert.setCaKeyDefinition(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertEquals(expectedValue, cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setCaKeyDefinition(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setIssuer(ca.trustpoint.m2m.EntityName)}.
   */
  @Test
  public void testSetIssuer() {
    M2mCertificate cert = new M2mCertificate();
    EntityName expectedValue = new EntityName();
    expectedValue.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.CommonName, "M2M Library Testing"));
    cert.setIssuer(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertEquals(expectedValue, cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setIssuer(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setValidFrom(java.util.Date)}.
   */
  @Test
  public void testSetValidFrom() {
    M2mCertificate cert = new M2mCertificate();
    Date expectedValue = new GregorianCalendar(2010, 3, 25).getTime();
    cert.setValidFrom(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertEquals(expectedValue, cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setValidFrom(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setValidDuration(java.lang.Integer)}.
   */
  @Test
  public void testSetValidDuration() {
    M2mCertificate cert = new M2mCertificate();
    Integer expectedValue = 300;
    cert.setValidDuration(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertEquals(expectedValue, cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setValidDuration(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setSubject(ca.trustpoint.m2m.EntityName)}.
   */
  @Test
  public void testSetSubject() {
    M2mCertificate cert = new M2mCertificate();
    EntityName expectedValue = new EntityName();
    expectedValue
        .addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "Testing Subject"));
    cert.setSubject(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertEquals(expectedValue, cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setSubject(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate# setPublicKeyDefinition(ca.trustpoint.m2m.KeyAlgorithmDefinition)}.
   */
  @Test
  public void testSetPublicKeyDefinition() {
    M2mCertificate cert = new M2mCertificate();
    KeyAlgorithmDefinition expectedValue =
        new KeyAlgorithmDefinition(NfcSignatureAlgorithmOids.ECQV_SHA256_SECP224R1, null);
    cert.setPublicKeyDefinition(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertEquals(expectedValue, cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setPublicKeyDefinition(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate# setAuthorityKeyIdentifier(ca.trustpoint.m2m.AuthorityKeyIdentifier)}.
   */
  @Test
  public void testSetAuthorityKeyIdentifier() {
    M2mCertificate cert = new M2mCertificate();
    AuthorityKeyIdentifier expectedValue = new AuthorityKeyIdentifier();
    expectedValue.setKeyIdentifier(Hex.decode("093c672ff2"));
    expectedValue.setCertificateIssuer(new GeneralName(GeneralNameAttributeId.DnsName, "testing"));
    expectedValue.setCertificateSerialNumber(new BigInteger(Hex.decode("729cb27dae30")));
    cert.setAuthorityKeyIdentifier(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertEquals(expectedValue, cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setAuthorityKeyIdentifier(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setSubjectKeyId(byte[])}.
   */
  @Test
  public void testSetSubjectKeyId() {
    M2mCertificate cert = new M2mCertificate();
    byte[] expectedValue = Hex.decode("003cd1e7");
    cert.setSubjectKeyIdentifier(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertArrayEquals(expectedValue, cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setSubjectKeyIdentifier(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setKeyUsage(ca.trustpoint.m2m.KeyUsage)}.
   */
  @Test
  public void testSetKeyUsage() {
    M2mCertificate cert = new M2mCertificate();
    KeyUsage expectedValue = new KeyUsage();
    expectedValue.setDigitalSignature(true);
    cert.setKeyUsage(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertEquals(expectedValue, cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setKeyUsage(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setBasicConstraints(java.lang.Integer)}.
   */
  @Test
  public void testSetBasicConstraints() {
    M2mCertificate cert = new M2mCertificate();
    Integer expectedValue = 5;
    cert.setBasicConstraints(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertEquals(expectedValue, cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setBasicConstraints(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setCertificatePolicy(java.lang.String)}.
   */
  @Test
  public void testSetCertificatePolicy() {
    M2mCertificate cert = new M2mCertificate();
    String expectedValue = "1.2.66.148.0.12";
    cert.setCertificatePolicy(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertEquals(expectedValue, cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setCertificatePolicy(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate# setSubjectAlternativeName(ca.trustpoint.m2m.GeneralName)}.
   */
  @Test
  public void testSetSubjectAlternativeName() {
    M2mCertificate cert = new M2mCertificate();
    GeneralName expectedValue = new GeneralName(GeneralNameAttributeId.DnsName, "testing");
    cert.setSubjectAlternativeName(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertEquals(expectedValue, cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setSubjectAlternativeName(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate# setIssuerAlternativeName(ca.trustpoint.m2m.GeneralName)}.
   */
  @Test
  public void testSetIssuerAlternativeName() {
    M2mCertificate cert = new M2mCertificate();
    GeneralName expectedValue = new GeneralName(GeneralNameAttributeId.DnsName, "testing");
    cert.setIssuerAlternativeName(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertEquals(expectedValue, cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setIssuerAlternativeName(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setExtendedKeyUsage(java.lang.String)}.
   */
  @Test
  public void testSetExtendedKeyUsage() {
    M2mCertificate cert = new M2mCertificate();
    String expectedValue = "1.3.22.174.22";
    cert.setExtendedKeyUsage(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertEquals(expectedValue, cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setExtendedKeyUsage(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setAuthenticationInfoAccessOcsp(java.net.URI)}.
   */
  @Test
  public void testSetAuthenticationInfoAccessOcsp() throws Exception {
    M2mCertificate cert = new M2mCertificate();
    URI expectedValue = new URI("https://ocsptest.trustpointinnovation.com");
    cert.setAuthenticationInfoAccessOcsp(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertEquals(expectedValue, cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setAuthenticationInfoAccessOcsp(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#setCrlDistributionPointUri(java.net.URI)}.
   */
  @Test
  public void testSetCrlDistributionPointUri() throws Exception {
    M2mCertificate cert = new M2mCertificate();
    URI expectedValue = new URI("https://crl.trustpointinnovation.com");
    cert.setCrlDistributionPointUri(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertEquals(expectedValue, cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setCrlDistributionPointUri(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setExtensions(java.util.List)}.
   */
  @Test
  public void testSetExtensions() {
    M2mCertificate cert = new M2mCertificate();
    String expectedOid1 = "1.5.24.632.0";
    String expectedOid2 = "1.5.24.632.1";
    byte[] expectedValue1 = Hex.decode("003a772fb1");
    byte[] expectedValue2 = Hex.decode("98f2b10e27");
    cert.addExtension(expectedOid1, true, expectedValue1);
    cert.addExtension(expectedOid2, false, expectedValue2);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertEquals(1, cert.getCriticalExtensionOIDs().size());
    assertTrue(cert.getCriticalExtensionOIDs().contains(expectedOid1));
    assertEquals(1, cert.getNonCriticalExtensionOIDs().size());
    assertTrue(cert.getNonCriticalExtensionOIDs().contains(expectedOid2));
    assertArrayEquals(expectedValue1, cert.getExtensionValue(expectedOid1));
    assertArrayEquals(expectedValue2, cert.getExtensionValue(expectedOid2));
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setPublicKey(byte[])}.
   */
  @Test
  public void testSetPublicKey() throws Exception {
    M2mCertificate cert = new M2mCertificate();
    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId,
        Hex.decode("029e3073ff1d303346fd486db4012e6d822fd11216bf1198d51b090e4447078c51"));
    PublicKey expectedValue = BouncyCastleProvider.getPublicKey(info);
    cert.setPublicKey(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertEquals(expectedValue, cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());

    cert.setPublicKey(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }


  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#setCaCalcValue(byte[])}.
   */
  @Test
  public void testSetCaCalcValue() {
    M2mCertificate cert = new M2mCertificate();
    byte[] expectedValue =
        Hex.decode("00e34a98c2ae3bb12093675518d1da608782134781acc52deef288031901029a");
    cert.setCaCalcValue(expectedValue);

    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertArrayEquals(expectedValue, cert.getCaCalcValue());

    cert.setCaCalcValue(null);
    assertEquals(0, cert.getVersion());
    assertNull(cert.getSerialNumber());
    assertNull(cert.getCaKeyDefinition());
    assertNull(cert.getIssuer());
    assertNull(cert.getValidFrom());
    assertNull(cert.getValidDuration());
    assertNull(cert.getSubject());
    assertNull(cert.getPublicKeyDefinition());
    assertNull(cert.getPublicKey());
    assertNull(cert.getAuthorityKeyIdentifier());
    assertNull(cert.getSubjectKeyIdentifier());
    assertNull(cert.getKeyUsage());
    assertNull(cert.getBasicConstraints());
    assertNull(cert.getCertificatePolicy());
    assertNull(cert.getSubjectAlternativeName());
    assertNull(cert.getIssuerAlternativeName());
    assertNull(cert.getExtendedKeyUsage());
    assertNull(cert.getAuthenticationInfoAccessOcsp());
    assertNull(cert.getCrlDistributionPointUri());
    assertTrue(cert.getCriticalExtensionOIDs().isEmpty());
    assertTrue(cert.getNonCriticalExtensionOIDs().isEmpty());
    assertNull(cert.getCaCalcValue());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#getTBSCertificate()}.
   */
  @Test
  public void testGetTBSCertificate() throws Exception {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    try {
      certificate.getTBSCertificate();
    } catch (IOException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    EntityName subject = new EntityName();
    subject.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.CommonName, "M2M Library Testing"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Locality, "Waterloo"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "ON"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));

    byte[] expectedEncoding = new byte[] {0x30, 0x32, (byte) 0x81, 0x07, 0x00, 0x73, 0x68,
        (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32,
        0x4D, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69,
        0x6E, 0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84,
        0x02, 0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41};
    certificate.setSerialNumber(Hex.decode("007368a3dc6e4f"));
    certificate.setSubject(subject);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    expectedEncoding = new byte[] {0x30, 0x39, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61,
        0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08, 0x57, 0x61,
        0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80, 0x02, 0x43,
        0x41};
    certificate.setCaKeyDefinition(caKeyDefinition);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    caKeyDefinition.setParameters(Hex.decode("018d56aab63fc2b7"));

    expectedEncoding = new byte[] {0x30, 0x43, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2,
        (byte) 0xB7, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08,
        0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80,
        0x02, 0x43, 0x41};
    certificate.setCaKeyDefinition(caKeyDefinition);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "Test Issuer"));
    issuer.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "TrustPoint Innovation"));

    expectedEncoding = new byte[] {0x30, 0x69, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2,
        (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73,
        0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69,
        0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E, (byte) 0xA7,
        0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
        0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65,
        0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41};
    certificate.setIssuer(issuer);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    Calendar validFromDate = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    validFromDate.set(2000, 0, 1, 0, 0, 0);
    validFromDate.set(Calendar.MILLISECOND, 0);

    Date validFrom = validFromDate.getTime();
    expectedEncoding = new byte[] {0x30, 0x6F, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2,
        (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73,
        0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69,
        0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E, (byte) 0x85,
        0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41};
    certificate.setValidFrom(validFrom);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, 0x75, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2,
        (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73,
        0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69,
        0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E, (byte) 0x85,
        0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01, (byte) 0xE1, 0x33,
        (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08,
        0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80,
        0x02, 0x43, 0x41};
    certificate.setValidDuration(31536000); // One year in seconds. (365 * 24 * 60 * 60)
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

    expectedEncoding = new byte[] {0x30, 0x7C, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3,
        (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09,
        (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2,
        (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73,
        0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69,
        0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E, (byte) 0x85,
        0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01, (byte) 0xE1, 0x33,
        (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08,
        0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80,
        0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x0A};
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    publicKeyDefinition.setParameters(Hex.decode("00f965ea33ab9810"));

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0x86, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10};
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId,
        Hex.decode("029e3073ff1d303346fd486db4012e6d822fd11216bf1198d51b090e4447078c51"));

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xC9, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72};
    certificate.setPublicKey(BouncyCastleProvider.getPublicKey(info));
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    authKeyId.setKeyIdentifier(Hex.decode("8dff22379a"));

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xD2, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A};
    certificate.setAuthorityKeyIdentifier(authKeyId);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xD9, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A};
    certificate.setSubjectKeyIdentifier(Hex.decode("300057d28a"));
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    KeyUsage usage = new KeyUsage();
    usage.setKeyEncipherment(true);
    usage.setKeyAgreement(true);

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xDC, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28};
    certificate.setKeyUsage(usage);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xDF, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03};
    certificate.setBasicConstraints(3);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xE6, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51};
    certificate.setCertificatePolicy("1.3.11.4632.81");
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    GeneralName subjectAltName = new GeneralName();
    subjectAltName.setAttributeId(GeneralNameAttributeId.DnsName);
    subjectAltName.setValue("testing");

    expectedEncoding = new byte[] {0x30, (byte) 0x81, (byte) 0xF1, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67};
    certificate.setSubjectAlternativeName(subjectAltName);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    GeneralName issuerAltName = new GeneralName();
    issuerAltName.setAttributeId(GeneralNameAttributeId.Uri);
    issuerAltName.setValue("http://testing.trustpoint.ca");

    expectedEncoding = new byte[] {0x30, (byte) 0x82, 0x01, 0x11, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1, 0x1E, (byte) 0x83,
        0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61};
    certificate.setIssuerAlternativeName(issuerAltName);
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x82, 0x01, 0x1D, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1, 0x1E, (byte) 0x83,
        0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61,
        (byte) 0x92, 0x0A, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE, 0x51, 0x1D,
        0x25, 0x05};
    certificate.setExtendedKeyUsage("2.16.840.1.114513.29.37.5");
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x82, 0x01, 0x3C, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1, 0x1E, (byte) 0x83,
        0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61,
        (byte) 0x92, 0x0A, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE, 0x51, 0x1D,
        0x25, 0x05, (byte) 0x93, 0x1D, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73,
        0x74, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E,
        0x74, 0x2E, 0x63, 0x61};
    certificate.setAuthenticationInfoAccessOcsp(new URI("http://testocsp.trustpoint.ca"));
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x82, 0x01, 0x5A, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1, 0x1E, (byte) 0x83,
        0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61,
        (byte) 0x92, 0x0A, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE, 0x51, 0x1D,
        0x25, 0x05, (byte) 0x93, 0x1D, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73,
        0x74, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E,
        0x74, 0x2E, 0x63, 0x61, (byte) 0x94, 0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74,
        0x65, 0x73, 0x74, 0x63, 0x72, 0x6C, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69,
        0x6E, 0x74, 0x2E, 0x63, 0x61};
    certificate.setCrlDistributionPointUri(new URI("http://testcrl.trustpoint.ca"));
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());

    expectedEncoding = new byte[] {0x30, (byte) 0x82, 0x01, 0x7D, (byte) 0x81, 0x07, 0x00, 0x73,
        0x68, (byte) 0xA3, (byte) 0xDC, 0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A,
        0x01, 0x09, (byte) 0x83, 0x08, 0x01, (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F,
        (byte) 0xC2, (byte) 0xB7, (byte) 0xA4, 0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74,
        0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49, 0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F,
        0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43, (byte) 0x80, (byte) 0x86, 0x04, 0x01,
        (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27, (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D,
        0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E,
        0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72, 0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02,
        0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01,
        0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65, (byte) 0xEA, 0x33, (byte) 0xAB,
        (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E, 0x30, 0x73, (byte) 0xFF, 0x1D,
        0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01, 0x2E, 0x6D, (byte) 0x82, 0x2F,
        (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98, (byte) 0xD5, 0x1B, 0x09, 0x0E,
        0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10, 0x70, 0x1F, 0x6A, (byte) 0xC3,
        0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39, (byte) 0x98, (byte) 0xBE,
        (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C, (byte) 0xE5, (byte) 0xEC,
        (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C, 0x1E, 0x72, (byte) 0xAB,
        0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37, (byte) 0x9A, (byte) 0x8C,
        0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D, 0x01, 0x28, (byte) 0x8E,
        0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51, (byte) 0xB0, 0x09,
        (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1, 0x1E, (byte) 0x83,
        0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67,
        0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61,
        (byte) 0x92, 0x0A, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE, 0x51, 0x1D,
        0x25, 0x05, (byte) 0x93, 0x1D, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73,
        0x74, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E,
        0x74, 0x2E, 0x63, 0x61, (byte) 0x94, 0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74,
        0x65, 0x73, 0x74, 0x63, 0x72, 0x6C, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69,
        0x6E, 0x74, 0x2E, 0x63, 0x61, (byte) 0xB5, 0x21, 0x30, 0x0E, (byte) 0x80, 0x03, 0x55, 0x1D,
        0x21, (byte) 0x82, 0x07, 0x23, (byte) 0xD6, (byte) 0xF1, (byte) 0x90, 0x00, 0x28,
        (byte) 0xA4, 0x30, 0x0F, (byte) 0x80, 0x03, 0x55, 0x1D, 0x24, (byte) 0x81, 0x01,
        (byte) 0xFF, (byte) 0x82, 0x05, 0x00, (byte) 0xB7, 0x3A, 0x49, 0x2F};
    certificate.addExtension("2.5.29.33", false, Hex.decode("23d6f1900028a4"));
    certificate.addExtension("2.5.29.36", true, Hex.decode("00b73a492f"));
    assertArrayEquals(expectedEncoding, certificate.getTBSCertificate());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#getEncoded()}.
   */
  @Test
  public void testGetEncoded() throws Exception {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    try {
      certificate.getEncoded();
    } catch (CertificateEncodingException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);
    caKeyDefinition.setParameters(Hex.decode("018d56aab63fc2b7"));

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "Test Issuer"));
    issuer.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.Organization, "TrustPoint Innovation"));

    Calendar validFromDate = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    validFromDate.set(2000, 0, 1, 0, 0, 0);
    validFromDate.set(Calendar.MILLISECOND, 0);

    Date validFrom = validFromDate.getTime();

    EntityName subject = new EntityName();
    subject.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.CommonName, "M2M Library Testing"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Locality, "Waterloo"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.StateOrProvince, "ON"));
    subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));

    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);
    publicKeyDefinition.setParameters(Hex.decode("00f965ea33ab9810"));

    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId,
        Hex.decode("029e3073ff1d303346fd486db4012e6d822fd11216bf1198d51b090e4447078c51"));


    AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
    authKeyId.setKeyIdentifier(Hex.decode("8dff22379a"));

    KeyUsage usage = new KeyUsage();
    usage.setKeyEncipherment(true);
    usage.setKeyAgreement(true);

    GeneralName subjectAltName = new GeneralName();
    subjectAltName.setAttributeId(GeneralNameAttributeId.DnsName);
    subjectAltName.setValue("testing");

    GeneralName issuerAltName = new GeneralName();
    issuerAltName.setAttributeId(GeneralNameAttributeId.Uri);
    issuerAltName.setValue("http://testing.trustpoint.ca");

    certificate.setSerialNumber(Hex.decode("007368a3dc6e4f"));
    certificate.setCaKeyDefinition(caKeyDefinition);
    certificate.setIssuer(issuer);
    certificate.setValidFrom(validFrom);
    certificate.setValidDuration(31536000); // One year in seconds. (365 * 24 * 60 * 60)
    certificate.setSubject(subject);
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    certificate.setPublicKey(BouncyCastleProvider.getPublicKey(info));
    certificate.setAuthorityKeyIdentifier(authKeyId);
    certificate.setSubjectKeyIdentifier(Hex.decode("300057d28a"));
    certificate.setKeyUsage(usage);
    certificate.setBasicConstraints(3);
    certificate.setCertificatePolicy("1.3.11.4632.81");
    certificate.setSubjectAlternativeName(subjectAltName);
    certificate.setIssuerAlternativeName(issuerAltName);
    certificate.setExtendedKeyUsage("2.16.840.1.114513.29.37.5");
    certificate.setAuthenticationInfoAccessOcsp(new URI("http://testocsp.trustpoint.ca"));
    certificate.setCrlDistributionPointUri(new URI("http://testcrl.trustpoint.ca"));
    certificate.addExtension("2.5.29.33", false, Hex.decode("23d6f1900028a4"));
    certificate.addExtension("2.5.29.36", true, Hex.decode("00b73a492f"));

    exceptionThrown = false;

    try {
      certificate.getEncoded();
    } catch (CertificateEncodingException ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);

    certificate.setCaCalcValue(
        Hex.decode("00e34a98c2ae3bb12093675518d1da608782134781acc52deef288031901029a"));

    byte[] expectedEncoding = new byte[] {0x74, (byte) 0x82, 0x01, (byte) 0xA3, (byte) 0xA0,
        (byte) 0x82, 0x01, 0x7D, (byte) 0x81, 0x07, 0x00, 0x73, 0x68, (byte) 0xA3, (byte) 0xDC,
        0x6E, 0x4F, (byte) 0x82, 0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x09, (byte) 0x83, 0x08, 0x01,
        (byte) 0x8D, 0x56, (byte) 0xAA, (byte) 0xB6, 0x3F, (byte) 0xC2, (byte) 0xB7, (byte) 0xA4,
        0x24, (byte) 0x86, 0x0B, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72,
        (byte) 0x81, 0x15, 0x54, 0x72, 0x75, 0x73, 0x74, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x49,
        0x6E, 0x6E, 0x6F, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E, (byte) 0x85, 0x04, 0x38, 0x6D, 0x43,
        (byte) 0x80, (byte) 0x86, 0x04, 0x01, (byte) 0xE1, 0x33, (byte) 0x80, (byte) 0xA7, 0x27,
        (byte) 0x86, 0x13, 0x4D, 0x32, 0x4D, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20,
        0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0x85, 0x08, 0x57, 0x61, 0x74, 0x65, 0x72,
        0x6C, 0x6F, 0x6F, (byte) 0x84, 0x02, 0x4F, 0x4E, (byte) 0x80, 0x02, 0x43, 0x41, (byte) 0x88,
        0x05, 0x2B, (byte) 0x81, 0x3A, 0x01, 0x0A, (byte) 0x89, 0x08, 0x00, (byte) 0xF9, 0x65,
        (byte) 0xEA, 0x33, (byte) 0xAB, (byte) 0x98, 0x10, (byte) 0x8A, 0x41, 0x04, (byte) 0x9E,
        0x30, 0x73, (byte) 0xFF, 0x1D, 0x30, 0x33, 0x46, (byte) 0xFD, 0x48, 0x6D, (byte) 0xB4, 0x01,
        0x2E, 0x6D, (byte) 0x82, 0x2F, (byte) 0xD1, 0x12, 0x16, (byte) 0xBF, 0x11, (byte) 0x98,
        (byte) 0xD5, 0x1B, 0x09, 0x0E, 0x44, 0x47, 0x07, (byte) 0x8C, 0x51, (byte) 0xA9, 0x56, 0x10,
        0x70, 0x1F, 0x6A, (byte) 0xC3, 0x44, 0x7D, (byte) 0xE6, (byte) 0xAF, (byte) 0x90, 0x39,
        (byte) 0x98, (byte) 0xBE, (byte) 0xF9, 0x07, 0x1B, 0x7F, 0x79, (byte) 0xFB, (byte) 0x8C,
        (byte) 0xE5, (byte) 0xEC, (byte) 0xC8, (byte) 0xED, (byte) 0xC6, 0x4A, 0x61, (byte) 0x8C,
        0x1E, 0x72, (byte) 0xAB, 0x07, (byte) 0x80, 0x05, (byte) 0x8D, (byte) 0xFF, 0x22, 0x37,
        (byte) 0x9A, (byte) 0x8C, 0x05, 0x30, 0x00, 0x57, (byte) 0xD2, (byte) 0x8A, (byte) 0x8D,
        0x01, 0x28, (byte) 0x8E, 0x01, 0x03, (byte) 0x8F, 0x05, 0x2B, 0x0B, (byte) 0xA4, 0x18, 0x51,
        (byte) 0xB0, 0x09, (byte) 0x81, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, (byte) 0xB1,
        0x1E, (byte) 0x83, 0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74,
        0x69, 0x6E, 0x67, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E,
        0x63, 0x61, (byte) 0x92, 0x0A, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x86, (byte) 0xFE,
        0x51, 0x1D, 0x25, 0x05, (byte) 0x93, 0x1D, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74,
        0x65, 0x73, 0x74, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70, 0x6F,
        0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61, (byte) 0x94, 0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F,
        0x2F, 0x74, 0x65, 0x73, 0x74, 0x63, 0x72, 0x6C, 0x2E, 0x74, 0x72, 0x75, 0x73, 0x74, 0x70,
        0x6F, 0x69, 0x6E, 0x74, 0x2E, 0x63, 0x61, (byte) 0xB5, 0x21, 0x30, 0x0E, (byte) 0x80, 0x03,
        0x55, 0x1D, 0x21, (byte) 0x82, 0x07, 0x23, (byte) 0xD6, (byte) 0xF1, (byte) 0x90, 0x00,
        0x28, (byte) 0xA4, 0x30, 0x0F, (byte) 0x80, 0x03, 0x55, 0x1D, 0x24, (byte) 0x81, 0x01,
        (byte) 0xFF, (byte) 0x82, 0x05, 0x00, (byte) 0xB7, 0x3A, 0x49, 0x2F, (byte) 0x81, 0x20,
        0x00, (byte) 0xE3, 0x4A, (byte) 0x98, (byte) 0xC2, (byte) 0xAE, 0x3B, (byte) 0xB1, 0x20,
        (byte) 0x93, 0x67, 0x55, 0x18, (byte) 0xD1, (byte) 0xDA, 0x60, (byte) 0x87, (byte) 0x82,
        0x13, 0x47, (byte) 0x81, (byte) 0xAC, (byte) 0xC5, 0x2D, (byte) 0xEE, (byte) 0xF2,
        (byte) 0x88, 0x03, 0x19, 0x01, 0x02, (byte) 0x9A};
    assertArrayEquals(expectedEncoding, certificate.getEncoded());
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#verify(java.security.PublicKey)}.
   */
  @Test
  public void testVerifyPublicKey() throws Exception {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    long secondsSinceEpoch = new BigInteger(Hex.decode("57AA2B20")).longValue() * 1000;
    Date validFrom = new Date(secondsSinceEpoch);

    int validDuration = new BigInteger(Hex.decode("01E13380")).intValue();

    EntityName subject = new EntityName();
    subject
        .addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "C (P256 ECDSA)"));

    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId,
        Hex.decode(
            "040B7733A4ABF6024D9901C3EE26718E0F22AA6FD75CE4CACCE896689E39D629A005655E9088ADDE"
                + "AC1DFC16EC26A722064C54F006EAF9A93763E16582DFA81937"));

    certificate.setSerialNumber(Hex.decode("0E"));
    certificate.setCaKeyDefinition(caKeyDefinition);
    certificate.setIssuer(issuer);
    certificate.setValidFrom(validFrom);
    certificate.setValidDuration(validDuration);
    certificate.setSubject(subject);
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    certificate.setPublicKey(BouncyCastleProvider.getPublicKey(info));

    certificate.setCaCalcValue(Hex.decode(
        "308188024200E6E20956572B988A8CD20F099ACB1758378B61F03C2EAABCA819D9CF59EFD427E5A71402"
            + "C3890B76C2E900E860E55CCBCAB060971BD2ED066402D22DD3BC5C8D9C0242017492DFD4CDF1C0BF535D"
            + "1E284E15F2357FD8C9FF688354A6B0597A1701414B571BEA82FB788094C41B407CADB4B421DBE56D1D68"
            + "756B961FD702B02CC7C9FA9367"));

    params = new X962Parameters(SECObjectIdentifiers.secp521r1);
    algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo caKeyInfo = new SubjectPublicKeyInfo(algId,
        Hex.decode("040043FF2A9FE4C5DDA97D82D43082AFEC8B26A925F833287C279DFA555CCB57DACF3119163470"
            + "8FB7F02FFB5E1DF26E92E8D6617DA0134B2AA652622C725FA569795E016B2C5C7593CC381F61DD63"
            + "B49DBB19ABA7D5C7FD8921F79DE0CABDF1D9D9728A360E51DFBA09F33787B31F97103B31AF057628"
            + "F3E56B6C4F1089EA6F299604670E"));

    certificate.verify(BouncyCastleProvider.getPublicKey(caKeyInfo));

    certificate.setSerialNumber(Hex.decode("FF"));

    try {
      certificate.verify(BouncyCastleProvider.getPublicKey(caKeyInfo));
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#verify(java.security.PublicKey, java.lang.String)}.
   */
  @Test
  public void testVerifyPublicKeyString() throws Exception {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    long secondsSinceEpoch = new BigInteger(Hex.decode("57AA2B20")).longValue() * 1000;
    Date validFrom = new Date(secondsSinceEpoch);

    int validDuration = new BigInteger(Hex.decode("01E13380")).intValue();

    EntityName subject = new EntityName();
    subject
        .addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "C (P256 ECDSA)"));

    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId,
        Hex.decode(
            "040B7733A4ABF6024D9901C3EE26718E0F22AA6FD75CE4CACCE896689E39D629A005655E9088ADDE"
                + "AC1DFC16EC26A722064C54F006EAF9A93763E16582DFA81937"));

    certificate.setSerialNumber(Hex.decode("0E"));
    certificate.setCaKeyDefinition(caKeyDefinition);
    certificate.setIssuer(issuer);
    certificate.setValidFrom(validFrom);
    certificate.setValidDuration(validDuration);
    certificate.setSubject(subject);
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    certificate.setPublicKey(BouncyCastleProvider.getPublicKey(info));

    certificate.setCaCalcValue(Hex.decode(
        "308188024200E6E20956572B988A8CD20F099ACB1758378B61F03C2EAABCA819D9CF59EFD427E5A71402"
            + "C3890B76C2E900E860E55CCBCAB060971BD2ED066402D22DD3BC5C8D9C0242017492DFD4CDF1C0BF535D"
            + "1E284E15F2357FD8C9FF688354A6B0597A1701414B571BEA82FB788094C41B407CADB4B421DBE56D1D68"
            + "756B961FD702B02CC7C9FA9367"));

    params = new X962Parameters(SECObjectIdentifiers.secp521r1);
    algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo caKeyInfo = new SubjectPublicKeyInfo(algId,
        Hex.decode("040043FF2A9FE4C5DDA97D82D43082AFEC8B26A925F833287C279DFA555CCB57DACF3119163470"
            + "8FB7F02FFB5E1DF26E92E8D6617DA0134B2AA652622C725FA569795E016B2C5C7593CC381F61DD63"
            + "B49DBB19ABA7D5C7FD8921F79DE0CABDF1D9D9728A360E51DFBA09F33787B31F97103B31AF057628"
            + "F3E56B6C4F1089EA6F299604670E"));

    certificate.verify(BouncyCastleProvider.getPublicKey(caKeyInfo),
        BouncyCastleProvider.PROVIDER_NAME);

    certificate.setSerialNumber(Hex.decode("FF"));

    try {
      certificate.verify(BouncyCastleProvider.getPublicKey(caKeyInfo),
          BouncyCastleProvider.PROVIDER_NAME);
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#checkValidity()}.
   */
  @Test
  public void testCheckValidity() {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    try {
      certificate.checkValidity();
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    Calendar notBefore = new GregorianCalendar(2000, 0, 1);
    certificate.setValidFrom(notBefore.getTime());

    try {
      certificate.checkValidity();
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    notBefore = GregorianCalendar.getInstance();
    notBefore.add(Calendar.DAY_OF_MONTH, 2);
    certificate.setValidFrom(notBefore.getTime());

    try {
      certificate.checkValidity();
    } catch (CertificateNotYetValidException ex) {
      exceptionThrown = true;
    } catch (Exception ex) {
      exceptionThrown = false;
    }

    assertTrue(exceptionThrown);

    notBefore = GregorianCalendar.getInstance();
    notBefore.add(Calendar.DAY_OF_MONTH, -1);

    certificate.setValidFrom(notBefore.getTime());
    certificate.setValidDuration(5 * SECONDS_PER_DAY);

    exceptionThrown = false;

    try {
      certificate.checkValidity();
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    certificate.setValidDuration(0);

    try {
      certificate.checkValidity();
    } catch (CertificateExpiredException ex) {
      exceptionThrown = true;
    } catch (Exception ex) {
      exceptionThrown = false;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.M2mCertificate#checkValidity(java.lang.Date)}.
   */
  @Test
  public void testCheckValidityDate() {
    boolean exceptionThrown = false;
    M2mCertificate certificate = new M2mCertificate();

    Date testDate = (new GregorianCalendar(2016, 7, 9)).getTime();

    try {
      certificate.checkValidity(testDate);
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    Calendar notBefore = new GregorianCalendar(2000, 0, 1);
    certificate.setValidFrom(notBefore.getTime());

    try {
      certificate.checkValidity();
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    testDate = (new GregorianCalendar(1999, 7, 9)).getTime();

    try {
      certificate.checkValidity(testDate);
    } catch (CertificateNotYetValidException ex) {
      exceptionThrown = true;
    } catch (Exception ex) {
      exceptionThrown = false;
    }

    assertTrue(exceptionThrown);

    certificate.setValidDuration(5 * SECONDS_PER_DAY);
    testDate = (new GregorianCalendar(2000, 0, 3)).getTime();

    exceptionThrown = false;

    try {
      certificate.checkValidity(testDate);
    } catch (Exception ex) {
      exceptionThrown = true;
    }

    assertFalse(exceptionThrown);

    testDate = (new GregorianCalendar(2000, 0, 6)).getTime();

    try {
      certificate.checkValidity();
    } catch (CertificateExpiredException ex) {
      exceptionThrown = true;
    } catch (Exception ex) {
      exceptionThrown = false;
    }

    assertTrue(exceptionThrown);
  }

  /**
   * Test method for
   * {@link ca.trustpoint.m2m.M2mCertificate#reconstructPublicKey(java.security.PublicKey)}.
   */
  @Test
  public void testReconstructPublicKey() throws Exception {

      M2mCertificate certificate = new M2mCertificate();

      //set M2mSignatureAlgorithmOid
      KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
      caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

      //set issuer
      EntityName issuer = new EntityName();
      issuer.
          addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "C (P256 ECQV)"));

      //set validFrom: 2016-09-12 14:10:14
      long secondsSinceEpoch = new BigInteger(Hex.decode("57D6B746")).longValue() * 1000;
      Date validFrom = new Date(secondsSinceEpoch);

      //set validDuration: 24 Months
      int validDuration = new BigInteger(Hex.decode("03C26700")).intValue();

      EntityName subject = new EntityName();
      subject.addAttribute(
          new EntityNameAttribute(EntityNameAttributeId.CommonName, "test"));
      subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Organization, "test"));

      //call setters for ECQV cert
      certificate.setSerialNumber(Hex.decode("01"));
      certificate.setCaKeyDefinition(caKeyDefinition);
      certificate.setIssuer(issuer);
      certificate.setValidFrom(validFrom);
      certificate.setValidDuration(validDuration);
      certificate.setSubject(subject);
      certificate.setCaCalcValue(
              Hex.decode("03F3171B68FE9EAAE211325DC2BD84A1FE50C07221CDBE038967B28CD06EB0CBFB"));

      //configure CA certificate
      X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);

      AlgorithmIdentifier algId = new AlgorithmIdentifier(
              X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
      SubjectPublicKeyInfo caKeyInfo = new SubjectPublicKeyInfo(
              algId, Hex.decode(
                      "04B10BD183820F3F32B7C000BAC7A480C8041998CFBE211DDA811B915FD03CED9EE7653551B"
                      + "7AFB30725C5617FD0AF767385CC9778ED3385A84DEEE6EFE64660CF"));

      //test is assumed to pass if reconstructPublicKey() call does not throw an exception
      certificate.reconstructPublicKey(BouncyCastleProvider.getPublicKey(caKeyInfo));
  }

  /**
   * Negative Test method for
   * {@link com.trustpoint.m2m.M2MCertificate#reconstructPublicKey(java.security.PublicKey)}.
   */
 @Test (expected=IllegalArgumentException.class) //test should throw a IllegalArgumentException
 public void testReconstructPublicKeyWithNullPublicKey() throws Exception {

     M2mCertificate certificate = new M2mCertificate();

     //test when publicKey is null
     assertNull(certificate.getPublicKey());

     //throws a IllegalArgumentException which is what the test expects
     certificate.reconstructPublicKey(certificate.getPublicKey());
  }

 /**
  * Negative Test method for
  * {@link com.trustpoint.m2m.M2MCertificate#reconstructPublicKey(java.security.PublicKey)}.
* @throws IOException
* @throws NoSuchAlgorithmException
* @throws InvalidKeyException
  */
@Test (expected=NoSuchAlgorithmException.class) //test should throw a NoSuchAlgorithmException
 public void testReconstructPublicKeyWithNonECQVCertificate() throws Exception {

    M2mCertificate certificate = new M2mCertificate();

    //test when Certificate is not a ECQV certificate
    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);

    EntityName issuer = new EntityName();
    issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "blueline"));

    long secondsSinceEpoch = new BigInteger(Hex.decode("57AA2B20")).longValue() * 1000;
    Date validFrom = new Date(secondsSinceEpoch);

    int validDuration = new BigInteger(Hex.decode("01E13380")).intValue();

    EntityName subject = new EntityName();
    subject.addAttribute(
        new EntityNameAttribute(EntityNameAttributeId.CommonName, "C (P256 ECDSA)"));

    KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
    publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);

    X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime256v1);
    AlgorithmIdentifier algId =
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive());
    SubjectPublicKeyInfo info =
        new SubjectPublicKeyInfo(
            algId,
            Hex.decode(
                "040B7733A4ABF6024D9901C3EE26718E0F22AA6FD75CE4CACCE896689E39D629A005655E9088ADD" +
                "EAC1DFC16EC26A722064C54F006EAF9A93763E16582DFA81937"));

    certificate.setSerialNumber(Hex.decode("0E"));
    certificate.setCaKeyDefinition(caKeyDefinition);
    certificate.setIssuer(issuer);
    certificate.setValidFrom(validFrom);
    certificate.setValidDuration(validDuration);
    certificate.setSubject(subject);
    certificate.setPublicKeyDefinition(publicKeyDefinition);
    certificate.setPublicKey(BouncyCastleProvider.getPublicKey(info));

    //throws a NoSuchAlgorithmException which is what the test expects
    certificate.reconstructPublicKey(certificate.getPublicKey());
 }
}
