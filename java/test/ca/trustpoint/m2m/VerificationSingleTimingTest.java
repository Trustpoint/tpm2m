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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class VerificationSingleTimingTest {
  private static final int ITERATIONS = 50;

  public static void main(String[] args) throws Exception {
    VerificationSingleTimingTest tests = new VerificationSingleTimingTest();
    tests.stressTest();
  }

  /**
   * Simple stress test running a tight loop on M2M cert verify.
   *
   * @throws Exception
   */
  @Test
  public void stressTest() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    M2mCertificateFactory factory;
    InputStream inStream;
    M2mCertificate cert;

    byte[] certData = Base64.decode(
        "dIHKoH+BAWaCBSuBOgEJpBGGD1NlbGYgU2lnbmVkICMxMIUEVHyKLIYEA9TcAKcRhg9TZWxmIFNpZ2" +
        "5lZCAjMTCKQQQ4mwknUz3zC/MQZF6hPNfsyz/0d/0DhGbeTJMcsCBPlE1UDggGr0XDFDltw0uqy1oF" +
        "H9t/gQxdZ32JOVNiSQRbgUcwRQIhAK/Bxm6rOIbb5b1S7gF2F+b6K10KoS5IxxdJBAU/oVi+AiAn0z" +
        "fK7ST5j9eL3t9IGl/sbmmqyWqAcefJ3hdrPX5IPA==");

    inStream = new ByteArrayInputStream(certData);
    factory = new M2mCertificateFactory();
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);

    PublicKey pubKey = cert.getPublicKey();

    // Tight loop of verification
    for(int i = 0; i < ITERATIONS; i++) {
      cert.verify(pubKey);
    }
  }
}
