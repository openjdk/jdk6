/*
 * Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

/**
 * @test
 * @bug 8169335
 * @summary Add a crypto policy fallback in case Security Property
 * 'crypto.policy' does not exist.
 * @run main/othervm CryptoPolicyFallback
 */
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.*;

/*
 * Take the current java.security file, strip out the 'crypto.policy' entry,
 * write to a new file in the current directory, then use that file as the
 * replacement java.security file.  This test will fail if the crypto.policy
 * entry doesn't match the compiled in value.
 */
public class CryptoPolicyFallback {

    private static final String FILENAME = "java.security";

    public static void main(String[] args) throws Exception {

        String path = System.getProperty("java.home") + "/lib/security/" + FILENAME;
        List<String> lines = readAllLines(new File(path));

        /*
         * Get the default value.
         */
        String defaultPolicy = "";
        for (String line : lines) {
            /*
             * If the input java.security file is malformed
             * (missing crypto.policy, attribute/no value, etc), throw
             * exception.  split() might throw AIOOB which
             * is ok behavior.
             */
            if (line.startsWith("crypto.policy=")) {
                defaultPolicy = line.split("=")[1].trim();
                break;
            }
        }

        /*
         * We know there is at least one crypto.policy entry, strip
         * all of them out of the java.security file.
         */
        PrintWriter out = null;
        try {
            out = new PrintWriter(FILENAME);
            for (String line : lines) {
                if (!line.startsWith("crypto.policy=")) {
                    out.println(line);
                }
            }
        } finally {
            out.close();
        }

        /*
         * "-Djava.security.properties==file" does a complete replacement
         * of the system java.security file.  i.e. value must be "=file"
         */
        System.setProperty("java.security.properties", "=" + FILENAME);

        /*
         * Find out expected value.
         */
        int expected;
        if (defaultPolicy.equals("limited")) {
            expected = 128;

        } else if (defaultPolicy.equals("") || defaultPolicy.equals("unlimited")) {
            expected = Integer.MAX_VALUE;

        } else {
            throw new Exception(
                    "Unexpected Default Policy Value: " + defaultPolicy);
        }

        /*
         * Do the actual check.  If the JCE Framework can't initialize
         * an Exception is normally thrown here.
         */
        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");

        System.out.println("Default Policy: " + defaultPolicy
                + "\nExpected max AES key length: " + expected
                + ", received : " + maxKeyLen);

        if (expected != maxKeyLen) {
            throw new Exception("Wrong Key Length size!");
        }

        System.out.println("PASSED!");
    }

    private static List<String> readAllLines(File path) throws IOException {
        List<String> strings = new ArrayList<String>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
        String line = reader.readLine();
        while (line != null) {
            strings.add(line);
            line = reader.readLine();
        }
        return strings;
    }
}
