#ifdef USE_PRAGMA_IDENT_HDR
#pragma ident "@(#)gcStats.hpp  1.10 07/05/05 17:05:34 JVM"
#endif
/*
 * Copyright 2003-2006 Sun Microsystems, Inc.  All Rights Reserved.
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

class GCStats : public CHeapObj {
 protected:
  // Avg amount promoted; used for avoiding promotion undo
  // This class does not update deviations if the sample is zero.
  AdaptivePaddedNoZeroDevAverage*   _avg_promoted;

 public:
  GCStats();

  enum Name {
    GCStatsKind,
    CMSGCStatsKind
  };

  virtual Name kind() {
    return GCStatsKind;
  }

  AdaptivePaddedNoZeroDevAverage*  avg_promoted() const { return _avg_promoted; }

  // Average in bytes
  size_t average_promoted_in_bytes() const {
    return (size_t)_avg_promoted->average();
  }

  // Padded average in bytes
  size_t padded_average_promoted_in_bytes() const {
    return (size_t)_avg_promoted->padded_average();
  }
};

class CMSGCStats : public GCStats {
 public:
  CMSGCStats();

  virtual Name kind() {
    return CMSGCStatsKind;
  }
};
