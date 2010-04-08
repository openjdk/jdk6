/*
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores,
 * CA 94065 USA or visit www.oracle.com if you need additional information or
 * have any questions.
 *
 */

package sun.jvm.hotspot.interpreter;

import sun.jvm.hotspot.oops.*;
import sun.jvm.hotspot.utilities.*;

public class BytecodeInstanceOf extends BytecodeWithKlass {
  BytecodeInstanceOf(Method method, int bci) {
    super(method, bci);
  }

  public InstanceKlass getInstanceOfKlass() {
    return (InstanceKlass) getKlass();
  }

  public void verify() {
    if (Assert.ASSERTS_ENABLED) {
      Assert.that(isValid(), "check instanceof");
    }
  }

  public boolean isValid() {
    return javaCode() == Bytecodes._instanceof;
  }

  public static BytecodeInstanceOf at(Method method, int bci) {
    BytecodeInstanceOf b = new BytecodeInstanceOf(method, bci);
    if (Assert.ASSERTS_ENABLED) {
      b.verify();
    }
    return b;
  }

  /** Like at, but returns null if the BCI is not at instanceof  */
  public static BytecodeInstanceOf atCheck(Method method, int bci) {
    BytecodeInstanceOf b = new BytecodeInstanceOf(method, bci);
    return (b.isValid() ? b : null);
  }

  public static BytecodeInstanceOf at(BytecodeStream bcs) {
    return new BytecodeInstanceOf(bcs.method(), bcs.bci());
  }
}
