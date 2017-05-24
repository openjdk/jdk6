/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
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

import java.io.*;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import sun.misc.BASE64Decoder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;

import jdk.testlibrary.OutputAnalyzer;
import jdk.testlibrary.ProcessTools;
import jdk.testlibrary.Utils;

/*
 * @test
 * @summary Verify the restrictions for certificate path on JSSE with custom trust store.
 * @library /lib/testlibrary
 * @compile JSSEClient.java
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions DEFAULT
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C1
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S1
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C2
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S2
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C3
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S3
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C4
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S4
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C5
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S5
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C6
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S6
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C7
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S7
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C8
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S8
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions C9
 * @run main/othervm -Djava.security.debug=certpath TLSRestrictions S9
 */
public class TLSRestrictions {

    private static final String TEST_CLASSES = System.getProperty("test.classes");
    private static final char[] PASSWORD = "".toCharArray();
    private static final String CERT_DIR = System.getProperty("cert.dir",
            System.getProperty("test.src") + "/certs");

    static final String PROP = "jdk.certpath.disabledAlgorithms";
    static final String NOSHA1 = "MD2, MD5";
    private static final String TLSSERVER = "SHA1 usage TLSServer";
    private static final String TLSCLIENT = "SHA1 usage TLSClient";
    static final String JDKCATLSSERVER = "SHA1 jdkCA & usage TLSServer";
    static final String JDKCATLSCLIENT = "SHA1 jdkCA & usage TLSClient";

    // This is a space holder in command arguments, and stands for none certificate.
    static final String NONE_CERT = "NONE_CERT";

    static final String DELIMITER = ",";
    static final int TIMEOUT = 30000;

    // It checks if java.security contains constraint "SHA1 jdkCA & usage TLSServer"
    // for jdk.certpath.disabledAlgorithms by default.
    private static void checkDefaultConstraint() {
        System.out.println(
                "Case: Checks the default value of jdk.certpath.disabledAlgorithms");
        if (!Security.getProperty(PROP).contains(JDKCATLSSERVER)) {
            throw new RuntimeException(String.format(
                    "%s doesn't contain constraint \"%s\", the real value is \"%s\".",
                    PROP, JDKCATLSSERVER, Security.getProperty(PROP)));
        }
    }

    /*
     * This method creates trust store and key store with specified certificates
     * respectively. And then it creates SSL context with the stores.
     * If trustNames contains NONE_CERT only, it does not create a custom trust
     * store, but the default one in JDK.
     *
     * @param trustNames Trust anchors, which are used to create custom trust store.
     *                   If null, no custom trust store is created and the default
     *                   trust store in JDK is used.
     * @param certNames Certificate chain, which is used to create key store.
     *                  It cannot be null.
     */
    static SSLContext createSSLContext(String[] trustNames,
            String[] certNames) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        TrustManagerFactory tmf = null;
        if (trustNames != null && trustNames.length > 0
                && !trustNames[0].equals(NONE_CERT)) {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            for (int i = 0; i < trustNames.length; i++) {
                InputStream is = null;
                try {
                    is = new ByteArrayInputStream(
                            loadCert(trustNames[i]).getBytes());

                    Certificate trustCert = certFactory.generateCertificate(is);
                    trustStore.setCertificateEntry("trustCert-" + i, trustCert);
                } finally {
                    if (is != null) {
                        is.close();
                    }
                }
            }

            tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trustStore);
        }

        Certificate[] certChain = new Certificate[certNames.length];
        for (int i = 0; i < certNames.length; i++) {
            InputStream is = null;
            try {
                is = new ByteArrayInputStream(
                        loadCert(certNames[i]).getBytes());

                Certificate cert = certFactory.generateCertificate(is);
                certChain[i] = cert;
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        }

        BASE64Decoder decoder = new BASE64Decoder();

        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(
                decoder.decodeBuffer(loadPrivKey(certNames[0])));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("keyCert", privKey, PASSWORD, certChain);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(keyStore, PASSWORD);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(),
                tmf == null ? null : tmf.getTrustManagers(), null);
        return context;
    }

    /*
     * This method sets jdk.certpath.disabledAlgorithms, and then retrieves
     * and prints its value.
     */
    static void setConstraint(String side, String constraint) {
        System.out.printf("%s: Old %s=%s%n", side, PROP,
                Security.getProperty(PROP));
        Security.setProperty(PROP, constraint);
        System.out.printf("%s: New %s=%s%n", side, PROP,
                Security.getProperty(PROP));
    }

    /*
     * This method is used to run a variety of cases.
     * It launches a server, and then takes a client to connect the server.
     * Both of server and client use the same certificates.
     *
     * @param trustNames Trust anchors, which are used to create custom trust store.
     *                   If null, the default trust store in JDK is used.
     * @param certNames Certificate chain, which is used to create key store.
     *                  It cannot be null. The first certificate is regarded as
     *                  the end entity.
     * @param serverConstraint jdk.certpath.disabledAlgorithms value on server side.
     * @param clientConstraint jdk.certpath.disabledAlgorithms value on client side.
     * @param needClientAuth If true, server side acquires client authentication;
     *                       otherwise, false.
     * @param pass If true, the connection should be blocked; otherwise, false.
     */
    static void testConstraint(String[] trustNames, String[] certNames,
            String serverConstraint, String clientConstraint,
            boolean needClientAuth, boolean pass) throws Throwable {
        String trustNameStr = trustNames == null ? ""
                : Utils.join(DELIMITER, trustNames);
        String certNameStr = certNames == null ? ""
                : Utils.join(DELIMITER, certNames);

        System.out.printf("Case:%n"
                + "  trustNames=%s; certNames=%s%n"
                + "  serverConstraint=%s; clientConstraint=%s%n"
                + "  needClientAuth=%s%n"
                + "  pass=%s%n%n",
                trustNameStr, certNameStr,
                serverConstraint, clientConstraint,
                needClientAuth,
                pass);
        setConstraint("Server", serverConstraint);
        JSSEServer server = new JSSEServer(
                createSSLContext(trustNames, certNames),
                needClientAuth);
        int port = server.getPort();
        server.start();

        // Run client on another JVM so that its properties cannot be in conflict
        // with server's.
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(
                "-Dcert.dir=" + CERT_DIR,
                "-Djava.security.debug=certpath",
                "-classpath",
                TEST_CLASSES,
                "JSSEClient",
                port + "",
                trustNameStr,
                certNameStr,
                clientConstraint);
        int exitValue = outputAnalyzer.getExitValue();
        String clientOut = outputAnalyzer.getOutput();

        Exception serverException = server.getException();
        if (serverException != null) {
            System.out.println("Server: failed");
        }

        System.out.println("---------- Client output start ----------");
        System.out.println(clientOut);
        System.out.println("---------- Client output end ----------");

        if (serverException instanceof SocketTimeoutException
                || clientOut.contains("SocketTimeoutException")) {
            System.out.println("The communication gets timeout and skips the test.");
            return;
        }

        if (pass) {
            if (serverException != null || exitValue != 0) {
                throw new RuntimeException(
                        "Unexpected failure. Operation was blocked.");
            }
        } else {
            if (serverException == null && exitValue == 0) {
                throw new RuntimeException(
                        "Unexpected pass. Operation was allowed.");
            }

            // The test may encounter non-SSL issues, like network problem.
            if (!(serverException instanceof SSLHandshakeException
                    || clientOut.contains("SSLHandshakeException"))) {
                throw new RuntimeException("Failure with unexpected exception.");
            }
        }
    }

    /*
     * This method is used to run a variety of cases, which don't require client
     * authentication by default.
     */
    static void testConstraint(String[] trustNames, String[] certNames,
            String serverConstraint, String clientConstraint, boolean pass)
            throws Throwable {
        testConstraint(trustNames, certNames, serverConstraint, clientConstraint,
                false, pass);
    }

    public static void main(String[] args) throws Throwable {
        String testCase = args[0];

        // Case DEFAULT only checks one of default settings for
        // jdk.certpath.disabledAlgorithms in JDK/conf/security/java.security.
        if ("DEFAULT".equals(testCase)) {
            checkDefaultConstraint();
        }

        // Cases C1 and S1 use SHA256 root CA in trust store,
        // and use SHA256 end entity in key store.
        // C1 only sets constraint "SHA1 usage TLSServer" on client side;
        // S1 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should not be blocked.
        else if ("C1".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{"INTER_CA_SHA256-ROOT_CA_SHA256"},
                    NOSHA1,
                    TLSSERVER,
                    true);
        }
        else if ("S1".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{"INTER_CA_SHA256-ROOT_CA_SHA256"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    true);
        }

        // Cases C2 and S2 use SHA256 root CA in trust store,
        // and use SHA1 end entity in key store.
        // C2 only sets constraint "SHA1 usage TLSServer" on client side;
        // S2 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should be blocked.
        else if ("C2".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{"INTER_CA_SHA1-ROOT_CA_SHA256"},
                    NOSHA1,
                    TLSSERVER,
                    false);
        }
        else if ("S2".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{"INTER_CA_SHA1-ROOT_CA_SHA256"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    false);
        }

        // Cases C3 and S3 use SHA1 root CA in trust store,
        // and use SHA1 end entity in key store.
        // C3 only sets constraint "SHA1 usage TLSServer" on client side;
        // S3 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should be blocked.
        else if ("C3".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{"INTER_CA_SHA1-ROOT_CA_SHA1"},
                    NOSHA1,
                    TLSSERVER,
                    false);
        }
        else if ("S3".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{"INTER_CA_SHA1-ROOT_CA_SHA1"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    false);
        }

        // Cases C4 and S4 use SHA1 root CA as trust store,
        // and use SHA256 end entity in key store.
        // C4 only sets constraint "SHA1 usage TLSServer" on client side;
        // S4 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should not be blocked.
        else if ("C4".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{"INTER_CA_SHA256-ROOT_CA_SHA1"},
                    NOSHA1,
                    TLSSERVER,
                    true);
        }
        else if ("S4".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{"INTER_CA_SHA256-ROOT_CA_SHA1"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    true);
        }

        // Cases C5 and S5 use SHA1 root CA in trust store,
        // and use SHA256 intermediate CA and SHA256 end entity in key store.
        // C5 only sets constraint "SHA1 usage TLSServer" on client side;
        // S5 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should not be blocked.
        else if("C5".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA256-ROOT_CA_SHA1",
                            "INTER_CA_SHA256-ROOT_CA_SHA1"},
                    NOSHA1,
                    TLSSERVER,
                    true);
        }
        else if ("S5".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA256-ROOT_CA_SHA1",
                            "INTER_CA_SHA256-ROOT_CA_SHA1"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    true);
        }

        // Cases C6 and S6 use SHA1 root CA as trust store,
        // and use SHA1 intermediate CA and SHA256 end entity in key store.
        // C6 only sets constraint "SHA1 usage TLSServer" on client side;
        // S6 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should be blocked.
        else if ("C6".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA1",
                            "INTER_CA_SHA1-ROOT_CA_SHA1"},
                    NOSHA1,
                    TLSSERVER,
                    false);
        }
        else if ("S6".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA1"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA1",
                            "INTER_CA_SHA1-ROOT_CA_SHA1"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    false);
        }

        // Cases C7 and S7 use SHA256 root CA in trust store,
        // and use SHA256 intermediate CA and SHA1 end entity in key store.
        // C7 only sets constraint "SHA1 usage TLSServer" on client side;
        // S7 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should be blocked.
        else if ("C7".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA1-INTER_CA_SHA256-ROOT_CA_SHA256",
                            "INTER_CA_SHA256-ROOT_CA_SHA256"},
                    NOSHA1,
                    TLSSERVER,
                    false);
        }
        else if ("S7".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA1-INTER_CA_SHA256-ROOT_CA_SHA256",
                            "INTER_CA_SHA256-ROOT_CA_SHA256"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    false);
        }

        // Cases C8 and S8 use SHA256 root CA in trust store,
        // and use SHA1 intermediate CA and SHA256 end entity in key store.
        // C8 only sets constraint "SHA1 usage TLSServer" on client side;
        // S8 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should be blocked.
        else if ("C8".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA256",
                            "INTER_CA_SHA1-ROOT_CA_SHA256"},
                    NOSHA1,
                    TLSSERVER,
                    false);
        }
        else if ("S8".equals(testCase)) {
            testConstraint(
                    new String[]{"ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA256",
                            "INTER_CA_SHA1-ROOT_CA_SHA256"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    false);
        }

        // Cases C9 and S9 use SHA256 root CA and SHA1 intermediate CA in trust store,
        // and use SHA256 end entity in key store.
        // C9 only sets constraint "SHA1 usage TLSServer" on client side;
        // S9 only sets constraint "SHA1 usage TLSClient" on server side with client auth.
        // The connection of the both cases should not be blocked.
        else if ("C9".equals(testCase)) {
            testConstraint(
                    new String[]{
                            "ROOT_CA_SHA256",
                            "INTER_CA_SHA1-ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA256"},
                    NOSHA1,
                    TLSSERVER,
                    true);
        }
        else if ("S9".equals(testCase)) {
            testConstraint(
                    new String[]{
                            "ROOT_CA_SHA256",
                            "INTER_CA_SHA1-ROOT_CA_SHA256"},
                    new String[]{
                            "END_ENTITY_SHA256-INTER_CA_SHA1-ROOT_CA_SHA256"},
                    TLSCLIENT,
                    NOSHA1,
                    true,
                    true);
        }


        System.out.println("Case passed");
        System.out.println("========================================");
    }

    private static String loadCert(String certName) {
        try {
            File certFilePath = new File(CERT_DIR,  certName + ".cer");
            final Charset utf8 = Charset.forName("UTF-8");
            List<String> lines = readAllLines(certFilePath, utf8);

            List<String> dataLines = new ArrayList<String>();

            for (String line : lines) {
                if (!line.startsWith("Certificate") && !line.startsWith(" ")) {
                    dataLines.add(line);
                }
            }

            String[] data = new String[dataLines.size()];

            return Utils.join("\n",
                    dataLines.toArray(data));
        } catch (IOException e) {
            throw new RuntimeException("Load certificate failed", e);
        }
    }

    private static List<String> readAllLines(File path, Charset charset) throws IOException {
        List<String> strings = new ArrayList<String>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
        String line = reader.readLine();
        while (line != null) {
            strings.add(line);
            line = reader.readLine();
        }
        return strings;
    }

    private static String loadPrivKey(String certName) {
        File priveKeyFilePath = new File(CERT_DIR, certName + "-PRIV.key");
        try {
            return new String(readAllBytes(priveKeyFilePath));
        } catch (IOException e) {
            throw new RuntimeException("Load private key failed", e);
        }
    }

    private static byte[] readAllBytes(File path) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        BufferedInputStream is = new BufferedInputStream(new FileInputStream(path));
        byte[] buf = new byte[1024];
        int len = is.read(buf, 0, buf.length);
        while (len > 0) {
            os.write(buf, 0, len);
            len = is.read(buf, 0, buf.length);
        }
        return os.toByteArray();
    }
}
