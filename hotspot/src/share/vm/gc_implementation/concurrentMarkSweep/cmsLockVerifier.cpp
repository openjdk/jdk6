#ifdef USE_PRAGMA_IDENT_SRC
#pragma ident "@(#)cmsLockVerifier.cpp	1.14 07/05/05 17:05:44 JVM"
#endif
/*
 * Copyright 2002-2005 Sun Microsystems, Inc.  All Rights Reserved.
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

# include "incls/_precompiled.incl"
# include "incls/_cmsLockVerifier.cpp.incl"

///////////// Locking verification specific to CMS //////////////
// Much like "assert_lock_strong()", except that it relaxes the
// assertion somewhat for the parallel GC case, where VM thread
// or the CMS thread might hold the lock on behalf of the parallel
// threads. The second argument is in support of an extra locking
// check for CFL spaces' free list locks.
#ifndef PRODUCT
void CMSLockVerifier::assert_locked(const Mutex* lock, const Mutex* p_lock) {
  if (!Universe::is_fully_initialized()) {
    return;
  }

  Thread* myThread = Thread::current();

  if (lock == NULL) { // a "lock-free" structure, e.g. MUT, protected by CMS token
    assert(p_lock == NULL, "Unexpected state");
    if (myThread->is_ConcurrentGC_thread()) {
      // This test might have to change in the future, if there can be
      // multiple peer CMS threads.  But for now, if we're testing the CMS
      assert(myThread == ConcurrentMarkSweepThread::cmst(),
	     "In CMS, CMS thread is the only Conc GC thread.");
      assert(ConcurrentMarkSweepThread::cms_thread_has_cms_token(),
             "CMS thread should have CMS token");
    } else if (myThread->is_VM_thread()) {
      assert(ConcurrentMarkSweepThread::vm_thread_has_cms_token(),
             "VM thread should have CMS token");
    } else {
      // Token should be held on our behalf by one of the other
      // of CMS or VM thread; not enough easily testable
      // state info to test which here.
      assert(myThread->is_GC_task_thread(), "Unexpected thread type");
    }
    return;
  } 

  if (ParallelGCThreads == 0) {
    assert_lock_strong(lock);
  } else {
    if (myThread->is_VM_thread()
        || myThread->is_ConcurrentGC_thread()
        || myThread->is_Java_thread()) {
      // Make sure that we are holding the associated lock.
      assert_lock_strong(lock);
      // The checking of p_lock is a spl case for CFLS' free list
      // locks: we make sure that none of the parallel GC work gang
      // threads are holding "sub-locks" of freeListLock(). We check only
      // the parDictionaryAllocLock because the others are too numerous.
      // This spl case code is somewhat ugly and any improvements
      // are welcome XXX FIX ME!!
      if (p_lock != NULL) {
        assert(!p_lock->is_locked() || p_lock->owned_by_self(),
               "Possible race between this and parallel GC threads");
      }
    } else if (myThread->is_GC_task_thread()) {
      // Make sure that the VM or CMS thread holds lock on our behalf
      // XXX If there were a concept of a gang_master for a (set of)
      // gang_workers, we could have used the identity of that thread
      // for checking ownership here; for now we just disjunct.
      assert(lock->owner() == VMThread::vm_thread() ||
             lock->owner() == ConcurrentMarkSweepThread::cmst(),
             "Should be locked by VM thread or CMS thread on my behalf");
    } else {
      // Make sure we didn't miss some obscure corner case
      ShouldNotReachHere();
    }
  }
}
#endif

