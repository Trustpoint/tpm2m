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

public class FormattingUtils {
  // Used to indent output
  public static StringBuffer indent(StringBuffer buffer, int depth) {
    if (depth <= 0) {
      return buffer;
    }

    for (int i = 0; i < depth; i++) {
      buffer.append("  ");
    }

    return buffer;
  }
}
