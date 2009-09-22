#ifdef USE_PRAGMA_IDENT_SRC
#pragma ident "@(#)toolHelp.cpp 1.10 07/05/05 17:02:07 JVM"
#endif
/*
 * Copyright 2001 Sun Microsystems, Inc.  All Rights Reserved.
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
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 */

#include "toolHelp.hpp"
#include <assert.h>

namespace ToolHelp {

static HMODULE kernelDLL = NULL;

HMODULE loadDLL() {
  if (kernelDLL == NULL) {
    kernelDLL = LoadLibrary("KERNEL32.DLL");
  }

  assert(kernelDLL != NULL);
  return kernelDLL;
}

void unloadDLL() {
  if (kernelDLL != NULL) {
    FreeLibrary(kernelDLL);
    kernelDLL = NULL;
  }
}

} // namespace ToolHelp
