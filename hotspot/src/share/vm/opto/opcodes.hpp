#ifdef USE_PRAGMA_IDENT_HDR
#pragma ident "@(#)opcodes.hpp  1.31 07/05/05 17:06:24 JVM"
#endif
/*
 * Copyright 1997-2008 Sun Microsystems, Inc.  All Rights Reserved.
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

// Build a big enum of class names to give them dense integer indices
#define macro(x) Op_##x,
enum Opcodes {
  Op_Node = 0,
  macro(Set)                    // Instruction selection match rule
  macro(RegN)                   // Machine narrow oop register
  macro(RegI)                   // Machine integer register
  macro(RegP)                   // Machine pointer register
  macro(RegF)                   // Machine float   register
  macro(RegD)                   // Machine double  register
  macro(RegL)                   // Machine long    register
  macro(RegFlags)               // Machine flags   register
  _last_machine_leaf,           // Split between regular opcodes and machine
#include "classes.hpp"
  _last_opcode
};
#undef macro

// Table of names, indexed by Opcode
extern const char *NodeClassNames[];
