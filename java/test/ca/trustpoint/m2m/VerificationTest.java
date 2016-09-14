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

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class VerificationTest {
  public VerificationTest() {}

  public static void main(String[] args) throws Exception {
    VerificationTest test = new VerificationTest();
    test.setup();
    test.parseKnownCert();
  }

  @Before
  public void setup() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Tests parsing an ECQV certificate.
   *
   * TODO: (M2M-26) Re-enable this test when the M2MCertFactorySpi is implemented.
   *
   * @throws IOException
   */
  @Test
  @Ignore
  public void parseKnownCert() throws Exception {
    // Implicit Known Certificate (should parse successfully)
    String certBase64DER =
        "dIHgoIGZgAEAgQFkgglghkgBhv5RAACkK4ACQ0GBClRydXN0UG9pbnSEA09OVIgUaHR0cDovL3RydXN0cG9pbnQuY2GFBFKUtDiGAwFgYqcGhgRURVNUiAcqhkjOPQIBij0EW23FO8YaJUj/sPZxRy3myVIanS0lNOZav8vV/gxwf9nx7S5l8J9s4Ik7r16OMeauguqMNZIzW+kG043ugUIwQAIeB4aCPJzRpafXFVSMnT+7Dd8uQIfy+EjC3Leqc1xcAh5qfq2hFJnY/KpfvWuwLRsO70lZ5s0fQr3lEDqw13M=";
    parse(Base64.decode(certBase64DER));
  }


  /**
   * Tests parsing a certificate chain.
   *
   * TODO: (M2M-26, M2M-27) Re-enable this test when the M2MCertFactorySpi and M2MCertPath classes
   * are implemented.
   *
   * @throws IOException
   */
  @Test
  @Ignore
  public void verifyChainTest() throws Exception {
    // ArrayList<byte[]> chain = new ArrayList<byte[]>(3);
    //
    // String endEntity =
    //     "dIHWoGuBAgC7ggUrgToBC6QLhglzZWNwMzg0cjGFBFbwRmqGBAPCZwCnG4YZVGVzdCBTaWduZXIgMTQ1ODU4NzI0MTk4OIgFK4E6AQmKIQLnGotPDpsKmUj0CQ0h8idnFhRVXsjxk5Gd7A3N8zr8kIFnMGUCMDSxepdPm9531vXQr25r4XCapJzGGS820GZuj8gsEBNCabicLp903uXKagpHNW3xJwIxAI6oTZv2LV4RGaTszsjRzAkk1nXZRl/1rC0v1bC+FM6ZgkT9+dynqaTfUkJnYYWdlg==";
    // String issuerCert =
    //     "dIIBKqCBmoECALqCBSuBOgENpAqGCGJsdWVsaW5lhQRW8EZqhgQDwmcApwuGCXNlY3AzODRyMYgFK4E6AQuKYQQ4cdnPjFUyGjmj+xgoBc9WYf+px8QjVhM5sAGJcCG9bPMSWP2CbzPgUV67dNL7rYGB8k+fKPeAzDbcmX5l9wd8lRwQliNsmhHlSXfA4rMHVa83AoukufGqt/oYyshiVumBgYowgYcCQgC5oBYxEu/WVuTkDi3JRKvEpMrXf40AS7/f1jMTp2EAMQpBl1RgTXPeEM+gUtLSwnNwWJvcECQIHYq95tSnGf6czAJBPIvqpuQVS+EX8r3GfuXihNLEkWD/DC7n4zFwM+qwkubYXVrsK6o+qT2xagbWV+r58dii0lDF4ApDPvs7M0cnR3g=";
    // String rootCert =
    //     "dIIBTaCBvYEBAoIFK4E6AQ2kCoYIYmx1ZWxpbmWFBFbrGRmGBAHhM4CnCoYIYmx1ZWxpbmWIBSuBOgENioGFBAC5SAhuM79GlXAdULiiex+oyhR44cJnBoI7rtpMmvN6hjrsTvq/Nzttco0IXdzgwl/7Z1zz8eyrmNir2WQMkoqdOgHEWt1NYOP8VaWZM0CQ+uTNk4S26TMxOG4WKN+O3qR94Kh5UIMorMbmtzrTsz0jzj7Dee37m26EOH8UM080kHcX64GBijCBhwJCAP7xbgQNiw+bubDIB5Ux6/s54Yw+7hYn1rM5mrwOZqjunjg3lI76CP2X1qLTka8S/YhkRRVGuMGfbysNXBBUyI3wAkFGtmSXSjIYnopkObOn+XH79jv/7DUYdt5YKox2aVN5u26fmi2CQDMfhArZ6zUf0HFYJuM9X00OojS2nONb7e7/UQ==";
    //
    // chain.add(Base64.decode(endEntity));
    // chain.add(Base64.decode(issuerCert));
    // chain.add(Base64.decode(rootCert));
    //
    // M2MChainVerifier cv = new M2MChainVerifier();
    //
    // StringBuilder result = new StringBuilder();
    // if(!cv.chainedVerify(chain, result)) {
    //   Assert.fail("Valid Cert Chain Unexpectedly Failed");
    // }
    //
    // // Reorder the chain, and make sure it fails.
    // ArrayList<byte[]> badChain = new ArrayList<byte[]>(3);
    // badChain.add(Base64.decode(endEntity));
    // badChain.add(Base64.decode(rootCert));
    // badChain.add(Base64.decode(issuerCert));
    //
    // result = new StringBuilder();
    // if(cv.chainedVerify(badChain, result)) {
    //   Assert.fail("Bad Cert Chain Unexpectedly Verified");
    // }
  }

  /**
   * Parses the given certificate.
   *
   * TODO: (M2M-26) Rewrite this method when the M2MCertFactorySpi is implemented.
   *
   * @param certBytes
   * @throws Exception
   */
  private void parse(byte[] certBytes) throws Exception {
    // M2MCertificate.parse(certBytes);
    // System.out.println("-- PARSE SUCCESS");
    //
    // //System.out.println(certificate.toPlainText());
  }
}
