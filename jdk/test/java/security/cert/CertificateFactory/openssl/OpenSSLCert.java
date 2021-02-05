/*
 * Copyright (c) 2009, 2011, Oracle and/or its affiliates. All rights reserved.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
/*
 * @test
 * @bug 6535697
 * @summary keytool can be more flexible on format of PEM-encoded
 *  X.509 certificates
 */

import java.io.*;
import java.util.Arrays;
import java.security.cert.CertificateFactory;

public class OpenSSLCert {
    static final String OUTFILE = "6535697.test";

    public static void main(String[] args) throws Exception {
        test("open");
        test("pem");
        test("open", "open");
        test("open", "pem");
        test("pem", "pem");
        test("pem", "open");
        test("open", "pem", "open");
        test("pem", "open", "pem");
    }

    static void test(String... files) throws Exception {
        FileOutputStream fout = null;
        FileInputStream fin = null;
        try {
            fout = new FileOutputStream(OUTFILE);
            String here = System.getProperty("test.src", ".");
            for (String file: files) {
                try {
                    fin = new FileInputStream(new File(here, file));
                    byte[] buffer = new byte[4096];
                    while (true) {
                        int len = fin.read(buffer);
                        if (len < 0) break;
                        fout.write(buffer, 0, len);
                    }
                } finally {
                    if (fin != null) { fin.close(); fin = null; }
                }
            }
        } finally {
            if (fout != null) { fout.close(); }
        }
        try {
            fin = new FileInputStream(OUTFILE);
            System.out.println("Testing " + Arrays.toString(files) + "...");
            if (CertificateFactory.getInstance("X509")
                    .generateCertificates(fin)
                    .size() != files.length) {
                throw new Exception("Not same number");
            }
        } finally {
            if (fin != null) { fin.close(); }
        }
        new File(OUTFILE).delete();
    }
}
