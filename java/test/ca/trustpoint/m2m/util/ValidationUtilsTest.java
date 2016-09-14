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

package ca.trustpoint.m2m.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ca.trustpoint.m2m.util.ValidationUtils;

/**
 * Unit tests for the {@link ca.trustpoint.m2m.util.ValidationUtils} class.
 */
public class ValidationUtilsTest {

  /**
   * Test method for {@link ca.trustpoint.m2m.util.ValidationUtils#isValidOid(java.lang.String)}.
   */
  @Test
  public void testIsValidOid() {
    assertTrue(ValidationUtils.isValidOid("1.3.55.0.2"));
    assertTrue(ValidationUtils.isValidOid("1.0.3.98.1"));
    assertFalse(ValidationUtils.isValidOid("02.12.12.1"));
    assertFalse(ValidationUtils.isValidOid("addfs22"));
    assertFalse(ValidationUtils.isValidOid("1.3.55.0.2."));
    assertFalse(ValidationUtils.isValidOid("1.3..55.0.2"));
  }

  /**
   * Test method for {@link ca.trustpoint.m2m.util.ValidationUtils#isValidHex(java.lang.String)}.
   */
  @Test
  public void testIsValidHex() {
    assertTrue(ValidationUtils.isValidHex("0f34daf1"));
    assertTrue(ValidationUtils.isValidHex("AC74D28B"));
    assertTrue(ValidationUtils.isValidHex("00"));
    assertFalse(ValidationUtils.isValidHex("A"));
    assertFalse(ValidationUtils.isValidHex("1234FG"));
    assertFalse(ValidationUtils.isValidHex("zz23"));
  }
}
