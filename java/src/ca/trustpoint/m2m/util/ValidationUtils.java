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

import java.util.regex.Pattern;

/**
 * Utility methods used for data validation.
 */
public class ValidationUtils {
  /** Regex pattern for matching ASN.1 Object Identifiers. */
  private static final String OID_MATCH_PATTERN = "^[1-9][0-9]*(\\.[0-9]+)*$";

  /** Used to validate ASN.1 Object Identifier strings. */
  private static final Pattern oidMatcher = Pattern.compile(OID_MATCH_PATTERN);

  /** Regex pattern for matching hex strings. */
  private static final String HEX_MATCH_PATTERN = "^([0-9A-Fa-f]{2})+$";

  /** Used to validate hex strings. */
  private static final Pattern hexMatcher = Pattern.compile(HEX_MATCH_PATTERN);

  /**
   * Returns true if the given string could be a valid ASN.1 Object Identifier.
   *
   * @param oid The Object Identifier to validate.
   * @return True if the given string could be a valid ASN.1 Object Identifier.
   */
  public static boolean isValidOid(String oid) {
    return (oidMatcher.matcher(oid).matches());
  }

  /**
   * Returns true if the given string is a valid hex string.
   *
   * @param hex The hex string to validate.
   * @return True if the given string is a valid hex string.
   */
  public static boolean isValidHex(String hex) {
    return (hexMatcher.matcher(hex).matches());
  }

  // Private constructor to prevent instantiation.
  private ValidationUtils() {}
}
