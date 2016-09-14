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

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Creating and Validating NDEF Messages and Records of varying complexity
 */
@RunWith(JUnit4.class)
public class DigicertCertificates2 {
  public void main() throws Exception {
    DigicertCertificates2 test = new DigicertCertificates2();
    test.createSharedVariables();

    test.parseECCert();
    test.parseRSACert();
  }

  @Before
  public void createSharedVariables() {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Tests parsing an ECC certificate form Digicert.
   *
   * @throws Exception
   */
  @Test
  public void parseECCert() throws Exception {
    System.out.println("=================================");
    System.out.println("==== PARSE DIGICERT ECC CERT ====");
    System.out.println("=================================");
    parseCert("testdata/digicert_batch_2/NFC Forum EC Test M2M EE 1.m2m");
  }

  /**
   * Tests parsing a RSA certificate form Digicert.
   *
   * @throws Exception
   */
  @Test
  @Ignore
  public void parseRSACert() throws Exception {
    System.out.println("=================================");
    System.out.println("==== PARSE DIGICERT RSA CERT ====");
    System.out.println("=================================");
    parseCert("testdata/digicert_batch_2/NFC Forum RSA Test M2M EE 1.m2m");
  }

  /**
   * Parses the given certificate file.
   *
   * @param filename
   * @throws Exception
   */
  private void parseCert(final String filename) throws Exception {

    InputStream fis = new FileInputStream(filename);

    M2mCertificateFactory certFactroy = new M2mCertificateFactory();
    certFactroy.engineGenerateCertificate(fis);

    fis.close();
  }
}
