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

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class M2mProvider extends Provider {
  private static final long serialVersionUID = 752116870110958923L;

  public static final String PROVIDER_NAME = "TPM2M";
  public static final double VERSION = 1.0;

  /**
   * To add the provider at runtime use:
   * <pre>
   * import java.security.Security;
   * import com.trustpoint.m2m.M2MProvider;
   *
   * Security.addProvider(new M2MProvider());
   * </pre>
   * The provider can also be configured as part of your environment via static registration by
   * adding an entry to the java.security properties file (found in
   * $JAVA_HOME/jre/lib/security/java.security, where $JAVA_HOME is the location of your JDK/JRE
   * distribution). You'll find detailed instructions in the file but basically it comes down to
   * adding a line:
   * <pre>
   * <code>
   *    security.provider.&lt;n&gt;=com.trustpoint.m2m.M2MProvider
   * </code>
   * </pre>
   * Where &lt;n&gt; is the preference you want the provider at (1 being the most preferred).
   * <p>Note: JCE algorithm names should be upper-case only so the case insensitive test for
   * getInstance() works.
   */
  public M2mProvider() {
    super(PROVIDER_NAME, VERSION, "M2M Certificate Handling Provider v1.0.");

    put("CertPathValidator.M2M", M2mCertPathValidator.class.getName());
    put("CertificateFactory.M2M", M2mCertificateFactory.class.getName());

    // Since this library is built on top of Bouncy Castle, make sure the Bouncy Castle provider is
    // registered.
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }
}
