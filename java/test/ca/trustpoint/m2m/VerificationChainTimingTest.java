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
import java.security.Security;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Simple stress test running a tight loop on M2M cert verify
 */
@RunWith(JUnit4.class)
public class VerificationChainTimingTest {
  private static final int ITERATIONS = 50;

  public static void main(String[] args) throws Exception {
    VerificationChainTimingTest tests = new VerificationChainTimingTest();
    tests.stressTest();
  }

  /**
   * Stress test for certificate chain verification.
   *
   * @throws Exception
   */
  @Test
  public void stressTest() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    M2mCertificateFactory factory;
    InputStream inStream;

    M2mCertPathValidator validator = new M2mCertPathValidator();

    byte[] signature = Base64.decode(
         "MEUCIQC73TC9nqt18hVxE28TkFRNd+yXXWI3/BodfiiPT8RPHAIgPViFgbgSWtRciiilQEpGSu6YP" +
         "ENgpDGAGjqyWgTYUJE=");

    byte[] signerCert = Base64.decode(
         "dIIBCKB4gQEJggUrgToBDaQKhghibHVlbGluZYUEV5fFEYYEAeEzgKcKhghDIChQMjU2KYgFK4E6A" +
         "QmKQQTYEDiOt19zyoGull4uJ+V1xcFQT4SAu30fo+ALWO6SQbNI81UkajsV+vBB7HVZwDIr0Bw8Vz" +
         "PCYkzhXCF8T/pWgYGLMIGIAkIBvuaG0c3KqZsnRE408FY3RGYkc4vbte2ZovSUyhe72e7UjsHaImo" +
         "M8WWPzDDe/rI558l5QYM2kPh/nRhlROLQiwICQgF1iObyUR5maod8GiJz0GHxgk9U16KuOqKLYyzI" +
         "9+rl9UVAne2RSqmSKMwWX1Rcg1pTVZKNKAFvRe5z0qNlTVvr5g==");

    byte[] rootCert = Base64.decode(
         "dIIBTqCBvYEBAoIFK4E6AQ2kCoYIYmx1ZWxpbmWFBFeXxRGGBAHhM4CnCoYIYmx1ZWxpbmWIBSuBO" +
         "gENioGFBAB47wWdYFq4W2olpu8xoac6Yy08sE3GBqjKC1gjlmFoz69hMdjZtT9r32tilG7EtB1hj6" +
         "P/f4u/rL/U9k/jwz2p0gCkeuUo3FC284dtf1ujwILZkndR4ajE+TTZCUKzXFff4xGyZj6NAYetTt4" +
         "xv5zSrYMXEHNgUi/baXWrLNZtwCmYH4GBizCBiAJCAU8VyvjvOGJrLHz6hblUTgKGaCkMrbRfYuIV" +
         "Pqr1qdUa9b8NAvLAV9OFa1y/s1KcJbhIFAWSQDn6YS1CKumhqFWRAkIBho09/l/Cvt0vdGiwsX7Sc" +
         "I52zQ03xE9NC7iGk3UgRvz8VtmBizJTO4mSkjwsgUmUAKxE+77NYyTYrh3UHsc6Cyo=");

    // Construct a list of M2M certificate
    // NOTE: engineGenerateCertificate() was tested in testEngineGenerateCertificateInputStream(),
    //       so it's okay to use it for generating certificate from certificate raw data here.
    List<M2mCertificate> certs = new ArrayList<M2mCertificate>();
    M2mCertificate cert;

    factory = new M2mCertificateFactory();

    inStream = new ByteArrayInputStream(signerCert);
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    certs.add(cert);

    inStream = new ByteArrayInputStream(rootCert);
    cert = (M2mCertificate)factory.engineGenerateCertificate(inStream);
    certs.add(cert);

    M2mCertPath path = new M2mCertPath(certs);

    List<M2mTrustAnchor> m2mAnchors = new ArrayList<M2mTrustAnchor>();
    m2mAnchors.add(new M2mTrustAnchor(cert));

    Calendar validityDate = new GregorianCalendar(2016, 7, 5);
    M2mCertPathParameters params = new M2mCertPathParameters(null, validityDate.getTime(), true);
    params = new M2mCertPathParameters(m2mAnchors, validityDate.getTime(), false);

    M2mCertPathValidatorResult result;
    result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);

    for(int i = 0; i < ITERATIONS; i++) {
      result = (M2mCertPathValidatorResult) validator.engineValidate(path, params);
    }
  }
}
