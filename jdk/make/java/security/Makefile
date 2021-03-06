#
# Copyright (c) 1996, 2005, Oracle and/or its affiliates. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.  Oracle designates this
# particular file as subject to the "Classpath" exception as provided
# by Oracle in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
# or visit www.oracle.com if you need additional information or have any
# questions.
#

BUILDDIR = ../..
PACKAGE = java.security
PRODUCT = sun
JAVAC_MAX_WARNINGS = false
JAVAC_LINT_OPTIONS = -Xlint:all,-deprecation
include $(BUILDDIR)/common/Defs.gmk

CRYPTOLEVEL_JARFILE = $(BUILDTOOLJARDIR)/customizesecurityfile.jar
TOOL_CRYPTOLEVEL = $(BOOT_JAVA_CMD) -jar $(CRYPTOLEVEL_JARFILE)

#
# Rules
#
AUTO_FILES_JAVA_DIRS = java/security

#
# Directories
#

# The default security properties file is for linux
PROPS_SRC   = $(TOPDIR)/src/share/lib/security/java.security-linux
SUNPKCS11   =

ifeq ($(PLATFORM), solaris)
PROPS_SRC   = $(TOPDIR)/src/share/lib/security/java.security-solaris
SUNPKCS11   = sunpkcs11

else # PLATFORM

# Register Microsoft CryptoAPI provider only on (non-64-bit) Windows platform.
ifeq ($(PLATFORM), windows)
  ifneq ($(ARCH_DATA_MODEL), 64)
    PROPS_SRC   = $(TOPDIR)/src/share/lib/security/java.security-windows
  endif
endif
endif # PLATFORM

PROPS_BUILD = $(LIBDIR)/security/java.security

SUNPKCS11_SRC   = $(TOPDIR)/src/share/lib/security/sunpkcs11-solaris.cfg
SUNPKCS11_BUILD = $(LIBDIR)/security/sunpkcs11-solaris.cfg

POLICY_SRC =	$(TOPDIR)/src/share/lib/security/java.policy
POLICY_BUILD = $(LIBDIR)/security/java.policy

CACERTS_SRC =	$(CACERTS_FILE)
CACERTS_BUILD = $(LIBDIR)/security/cacerts

FILES_class = $(FILES_java:%.java=$(CLASSBINDIR)/%.class)

#
# Rules
#
include $(BUILDDIR)/common/Rules.gmk

build: properties $(SUNPKCS11) policy cacerts

install: all

properties: classes  $(PROPS_BUILD)

sunpkcs11: classes $(SUNPKCS11_BUILD)

policy: classes  $(POLICY_BUILD)

cacerts: classes $(CACERTS_BUILD)

$(PROPS_BUILD): $(PROPS_SRC)
	$(MKDIR) -p $(@D)
	$(CP) $^ $@.tmp
	if [ "x$(UNLIMITED_CRYPTO)" = "xtrue" ] ; then \
	  $(TOOL_CRYPTOLEVEL) $@.tmp $@.tmp2 unlimited; \
	  $(MV) $@.tmp2 $@.tmp; \
	fi 
	$(MV) $@.tmp $@

$(SUNPKCS11_BUILD): $(SUNPKCS11_SRC)
	$(install-file)

$(POLICY_BUILD): $(POLICY_SRC)
	$(install-file)

$(CACERTS_BUILD): $(CACERTS_SRC)
	$(install-file)

clean clobber:: .delete.classlist
	$(RM) -r $(CLASSBINDIR)/java/security
	$(RM) $(PROPS_BUILD) $(POLICY_BUILD) $(CACERTS_BUILD) $(SUNPKCS11_BUILD)

# Additional Rule for building sun.security.util
$(CLASSBINDIR)/%.class: $(SHARE_SRC)/sun/%.java
	@$(ECHO) $? >> $(TEMPDIR)/.classes.list

