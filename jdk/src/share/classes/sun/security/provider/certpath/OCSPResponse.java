/*
 * Copyright (c) 2003, 2017, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.provider.certpath;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

import sun.misc.HexDumpEncoder;
import sun.security.action.GetIntegerAction;
import sun.security.x509.*;
import sun.security.util.*;

/**
 * This class is used to process an OCSP response.
 * The OCSP Response is defined
 * in RFC 2560 and the ASN.1 encoding is as follows:
 * <pre>
 *
 *  OCSPResponse ::= SEQUENCE {
 *      responseStatus         OCSPResponseStatus,
 *      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 *
 *   OCSPResponseStatus ::= ENUMERATED {
 *       successful            (0),  --Response has valid confirmations
 *       malformedRequest      (1),  --Illegal confirmation request
 *       internalError         (2),  --Internal error in issuer
 *       tryLater              (3),  --Try again later
 *                                   --(4) is not used
 *       sigRequired           (5),  --Must sign the request
 *       unauthorized          (6)   --Request unauthorized
 *   }
 *
 *   ResponseBytes ::=       SEQUENCE {
 *       responseType   OBJECT IDENTIFIER,
 *       response       OCTET STRING }
 *
 *   BasicOCSPResponse       ::= SEQUENCE {
 *      tbsResponseData      ResponseData,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING,
 *      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 *
 *   The value for signature SHALL be computed on the hash of the DER
 *   encoding ResponseData.
 *
 *   ResponseData ::= SEQUENCE {
 *      version              [0] EXPLICIT Version DEFAULT v1,
 *      responderID              ResponderID,
 *      producedAt               GeneralizedTime,
 *      responses                SEQUENCE OF SingleResponse,
 *      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 *
 *   ResponderID ::= CHOICE {
 *      byName               [1] Name,
 *      byKey                [2] KeyHash }
 *
 *   KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
 *   (excluding the tag and length fields)
 *
 *   SingleResponse ::= SEQUENCE {
 *      certID                       CertID,
 *      certStatus                   CertStatus,
 *      thisUpdate                   GeneralizedTime,
 *      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
 *      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
 *
 *   CertStatus ::= CHOICE {
 *       good        [0]     IMPLICIT NULL,
 *       revoked     [1]     IMPLICIT RevokedInfo,
 *       unknown     [2]     IMPLICIT UnknownInfo }
 *
 *   RevokedInfo ::= SEQUENCE {
 *       revocationTime              GeneralizedTime,
 *       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
 *
 *   UnknownInfo ::= NULL -- this can be replaced with an enumeration
 *
 * </pre>
 *
 * @author      Ram Marti
 */

public final class OCSPResponse {

    public enum ResponseStatus {
        SUCCESSFUL,            // Response has valid confirmations
        MALFORMED_REQUEST,     // Illegal confirmation request
        INTERNAL_ERROR,        // Internal error in issuer
        TRY_LATER,             // Try again later
        UNUSED,                // is not used
        SIG_REQUIRED,          // Must sign the request
        UNAUTHORIZED           // Request unauthorized
    };
    private static final ResponseStatus[] rsvalues = ResponseStatus.values();

    private static final Debug DEBUG = Debug.getInstance("certpath");
    private static final boolean dump = false;
    private static final ObjectIdentifier OCSP_BASIC_RESPONSE_OID =
        ObjectIdentifier.newInternal(new int[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1});
    private static final ObjectIdentifier OCSP_NONCE_EXTENSION_OID =
        ObjectIdentifier.newInternal(new int[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 2});

    // Certificate status CHOICE
    private static final int CERT_STATUS_GOOD = 0;
    private static final int CERT_STATUS_REVOKED = 1;
    private static final int CERT_STATUS_UNKNOWN = 2;

    // ResponderID CHOICE tags
    private static final int NAME_TAG = 1;
    private static final int KEY_TAG = 2;

    // Object identifier for the OCSPSigning key purpose
    private static final String KP_OCSP_SIGNING_OID = "1.3.6.1.5.5.7.3.9";

    private final ResponseStatus responseStatus;
    private final Map<CertId, SingleResponse> singleResponseMap;

    // Default maximum clock skew in milliseconds (15 minutes)
    // allowed when checking validity of OCSP responses
    private static final int DEFAULT_MAX_CLOCK_SKEW = 900000;

    /**
     * Integer value indicating the maximum allowable clock skew, in seconds,
     * to be used for the OCSP check.
     */
    private static final int MAX_CLOCK_SKEW = initializeClockSkew();

    /**
     * Initialize the maximum allowable clock skew by getting the OCSP
     * clock skew system property. If the property has not been set, or if its
     * value is negative, set the skew to the default.
     */
    private static int initializeClockSkew() {
        Integer tmp = java.security.AccessController.doPrivileged(
                new GetIntegerAction("com.sun.security.ocsp.clockSkew"));
        if (tmp == null || tmp < 0) {
            return DEFAULT_MAX_CLOCK_SKEW;
        }
        // Convert to milliseconds, as the system property will be
        // specified in seconds
        return tmp * 1000;
    }

    private final byte[] responseNonce;
    private final ResponderId respId;
    private Date producedAtDate = null;
    private final Map<String, Extension> responseExtensions;

    /*
     * Create an OCSP response from its ASN.1 DER encoding.
     */
    // used by OCSPChecker
    OCSPResponse(byte[] bytes, Date dateCheckedAgainst,
        X509Certificate responderCert, String variant)
        throws IOException, CertPathValidatorException {

        // OCSPResponse
        if (dump) {
            HexDumpEncoder hexEnc = new HexDumpEncoder();
            System.out.println("OCSPResponse bytes are...");
            System.out.println(hexEnc.encode(bytes));
        }
        DerValue der = new DerValue(bytes);
        if (der.tag != DerValue.tag_Sequence) {
            throw new IOException("Bad encoding in OCSP response: " +
                "expected ASN.1 SEQUENCE tag.");
        }
        DerInputStream derIn = der.getData();

        // responseStatus
        int status = derIn.getEnumerated();
        if (status >= 0 && status < rsvalues.length) {
            responseStatus = rsvalues[status];
        } else {
            // unspecified responseStatus
            throw new IOException("Unknown OCSPResponse status: " + status);
        }
        if (DEBUG != null) {
            DEBUG.println("OCSP response status: " + responseStatus);
        }
        if (responseStatus != ResponseStatus.SUCCESSFUL) {
            // no need to continue, responseBytes are not set.
            singleResponseMap = Collections.emptyMap();
            responseNonce = null;
            responseExtensions = Collections.emptyMap();
            respId = null;
            return;
        }

        // responseBytes
        der = derIn.getDerValue();
        if (!der.isContextSpecific((byte)0)) {
            throw new IOException("Bad encoding in responseBytes element " +
                "of OCSP response: expected ASN.1 context specific tag 0.");
        };
        DerValue tmp = der.data.getDerValue();
        if (tmp.tag != DerValue.tag_Sequence) {
            throw new IOException("Bad encoding in responseBytes element " +
                "of OCSP response: expected ASN.1 SEQUENCE tag.");
        }

        // responseType
        derIn = tmp.data;
        ObjectIdentifier responseType = derIn.getOID();
        if (responseType.equals(OCSP_BASIC_RESPONSE_OID)) {
            if (DEBUG != null) {
                DEBUG.println("OCSP response type: basic");
            }
        } else {
            if (DEBUG != null) {
                DEBUG.println("OCSP response type: " + responseType);
            }
            throw new IOException("Unsupported OCSP response type: " +
                responseType);
        }

        // BasicOCSPResponse
        DerInputStream basicOCSPResponse =
            new DerInputStream(derIn.getOctetString());

        DerValue[] seqTmp = basicOCSPResponse.getSequence(2);
        if (seqTmp.length < 3) {
            throw new IOException("Unexpected BasicOCSPResponse value");
        }

        DerValue responseData = seqTmp[0];

        // Need the DER encoded ResponseData to verify the signature later
        byte[] responseDataDer = seqTmp[0].toByteArray();

        // tbsResponseData
        if (responseData.tag != DerValue.tag_Sequence) {
            throw new IOException("Bad encoding in tbsResponseData " +
                "element of OCSP response: expected ASN.1 SEQUENCE tag.");
        }
        DerInputStream seqDerIn = responseData.data;
        DerValue seq = seqDerIn.getDerValue();

        // version
        if (seq.isContextSpecific((byte)0)) {
            // seq[0] is version
            if (seq.isConstructed() && seq.isContextSpecific()) {
                //System.out.println ("version is available");
                seq = seq.data.getDerValue();
                int version = seq.getInteger();
                if (seq.data.available() != 0) {
                    throw new IOException("Bad encoding in version " +
                        " element of OCSP response: bad format");
                }
                seq = seqDerIn.getDerValue();
            }
        }

        // responderID
        respId = new ResponderId(seq.toByteArray());
        if (DEBUG != null) {
            DEBUG.println("Responder ID: " + respId);
        }

        // producedAt
        seq = seqDerIn.getDerValue();
        producedAtDate = seq.getGeneralizedTime();
        if (DEBUG != null) {
            DEBUG.println("OCSP response produced at: " + producedAtDate);
        }

        // responses
        DerValue[] singleResponseDer = seqDerIn.getSequence(1);
        singleResponseMap
            = new HashMap<CertId, SingleResponse>(singleResponseDer.length);
        if (DEBUG != null) {
            DEBUG.println("OCSP number of SingleResponses: "
                + singleResponseDer.length);
        }
        for (DerValue srDer : singleResponseDer) {
            SingleResponse singleResponse = new SingleResponse(srDer);
            singleResponseMap.put(singleResponse.getCertId(), singleResponse);
        }

        // responseExtensions
        Map<String, Extension> tmpExtMap = new HashMap<String, Extension>();
        if (seqDerIn.available() > 0) {
            seq = seqDerIn.getDerValue();
            if (seq.isContextSpecific((byte)1)) {
                tmpExtMap = parseExtensions(seq);
            }
        }
        responseExtensions = tmpExtMap;

        // Attach the nonce value if found in the extension map
        Extension nonceExt = tmpExtMap.get(
                PKIXExtensions.OCSPNonce_Id.toString());
        responseNonce = (nonceExt != null) ?
                nonceExt.getExtensionValue() : null;
        if (DEBUG != null && responseNonce != null) {
            DEBUG.println("Response nonce: " + Arrays.toString(responseNonce));
        }

        // signatureAlgorithmId
        AlgorithmId sigAlgId = AlgorithmId.parse(seqTmp[1]);

        // signature
        byte[] signature = seqTmp[2].getBitString();
        X509CertImpl[] x509Certs = null;

        // if seq[3] is available , then it is a sequence of certificates
        if (seqTmp.length > 3) {
            // certs are available
            DerValue seqCert = seqTmp[3];
            if (!seqCert.isContextSpecific((byte)0)) {
                throw new IOException("Bad encoding in certs element of " +
                    "OCSP response: expected ASN.1 context specific tag 0.");
            }
            DerValue[] certs = seqCert.getData().getSequence(3);
            x509Certs = new X509CertImpl[certs.length];
            try {
                for (int i = 0; i < certs.length; i++) {
                    x509Certs[i] = new X509CertImpl(certs[i].toByteArray());
                }
            } catch (CertificateException ce) {
                throw new IOException("Bad encoding in X509 Certificate", ce);
            }
        }

        // Check whether the cert returned by the responder is trusted
        if (x509Certs != null && x509Certs[0] != null) {
            X509Certificate cert = x509Certs[0];

            // First check if the cert matches the responder cert which
            // was set locally.
            if (cert.equals(responderCert)) {
                // cert is trusted, now verify the signed response

            // Next check if the cert was issued by the responder cert
            // which was set locally.
            } else if (cert.getIssuerX500Principal().equals(
                    responderCert.getSubjectX500Principal())) {

                // Check for the OCSPSigning key purpose
                try {
                    List<String> keyPurposes = cert.getExtendedKeyUsage();
                    if (keyPurposes == null ||
                        !keyPurposes.contains(KP_OCSP_SIGNING_OID)) {
                        throw new CertPathValidatorException(
                            "Responder's certificate not valid for signing " +
                            "OCSP responses");
                    }
                } catch (CertificateParsingException cpe) {
                    // assume cert is not valid for signing
                    throw new CertPathValidatorException(
                        "Responder's certificate not valid for signing " +
                        "OCSP responses", cpe);
                }

                // Check algorithm constraints specified in security property
                // "jdk.certpath.disabledAlgorithms".
                AlgorithmChecker algChecker = new AlgorithmChecker(
                                    new TrustAnchor(responderCert, null), variant);
                algChecker.init(false);
                algChecker.check(cert, Collections.<String>emptySet());

                // verify the signature
                try {
                    cert.verify(responderCert.getPublicKey());
                    responderCert = cert;
                    // cert is trusted, now verify the signed response

                } catch (GeneralSecurityException e) {
                    responderCert = null;
                }
            }
        }

        // Confirm that the signed response was generated using the public
        // key from the trusted responder cert
        if (responderCert != null) {
            // Check algorithm constraints specified in security property
            // "jdk.certpath.disabledAlgorithms".
            AlgorithmChecker.check(responderCert.getPublicKey(), sigAlgId, variant);

            if (!verifyResponse(responseDataDer, responderCert,
                sigAlgId, signature)) {
                throw new CertPathValidatorException(
                    "Error verifying OCSP Responder's signature");
            }
        } else {
            // Need responder's cert in order to verify the signature
            throw new CertPathValidatorException(
                "Unable to verify OCSP Responder's signature");
        }
    }

    /**
     * Returns the OCSP ResponseStatus.
     *
     * @return the {@code ResponseStatus} for this OCSP response
     */
    public ResponseStatus getResponseStatus() {
        return responseStatus;
    }

    /*
     * Verify the signature of the OCSP response.
     * The responder's cert is implicitly trusted.
     */
    private boolean verifyResponse(byte[] responseData, X509Certificate cert,
        AlgorithmId sigAlgId, byte[] signBytes)
        throws CertPathValidatorException {

        try {
            Signature respSignature = Signature.getInstance(sigAlgId.getName());
            respSignature.initVerify(cert);
            respSignature.update(responseData);

            if (respSignature.verify(signBytes)) {
                if (DEBUG != null) {
                    DEBUG.println("Verified signature of OCSP Responder");
                }
                return true;

            } else {
                if (DEBUG != null) {
                    DEBUG.println(
                        "Error verifying signature of OCSP Responder");
                }
                return false;
            }
        } catch (InvalidKeyException ike) {
            throw new CertPathValidatorException(ike);
        } catch (NoSuchAlgorithmException nsae) {
            throw new CertPathValidatorException(nsae);
        } catch (SignatureException se) {
            throw new CertPathValidatorException(se);
        }
    }

    /**
     * Returns the SingleResponse of the specified CertId, or null if
     * there is no response for that CertId.
     *
     * @param certId the {@code CertId} for a {@code SingleResponse} to be
     * searched for in the OCSP response.
     *
     * @return the {@code SingleResponse} for the provided {@code CertId},
     * or {@code null} if it is not found.
     */
    public SingleResponse getSingleResponse(CertId certId) {
        return singleResponseMap.get(certId);
    }

    /**
     * Return a set of all CertIds in this {@code OCSPResponse}
     *
     * @return an unmodifiable set containing every {@code CertId} in this
     *      response.
     */
    public Set<CertId> getCertIds() {
        return Collections.unmodifiableSet(singleResponseMap.keySet());
    }

    /**
     * Get the {@code ResponderId} from this {@code OCSPResponse}
     *
     * @return the {@code ResponderId} from this response or {@code null}
     *      if no responder ID is in the body of the response (e.g. a
     *      response with a status other than SUCCESS.
     */
    public ResponderId getResponderId() {
        return respId;
    }

    /**
     * Provide a String representation of an OCSPResponse
     *
     * @return a human-readable representation of the OCSPResponse
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("OCSP Response:\n");
        sb.append("Response Status: ").append(responseStatus).append("\n");
        sb.append("Responder ID: ").append(respId).append("\n");
        sb.append("Produced at: ").append(producedAtDate).append("\n");
        int count = singleResponseMap.size();
        sb.append(count).append(count == 1 ?
                " response:\n" : " responses:\n");
        for (SingleResponse sr : singleResponseMap.values()) {
            sb.append(sr).append("\n");
        }
        if (responseExtensions != null && responseExtensions.size() > 0) {
            count = responseExtensions.size();
            sb.append(count).append(count == 1 ?
                    " extension:\n" : " extensions:\n");
            for (String extId : responseExtensions.keySet()) {
                sb.append(responseExtensions.get(extId)).append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Build a String-Extension map from DER encoded data.
     * @param derVal A {@code DerValue} object built from a SEQUENCE of
     *      extensions
     *
     * @return a {@code Map} using the OID in string form as the keys.  If no
     *      extensions are found or an empty SEQUENCE is passed in, then
     *      an empty {@code Map} will be returned.
     *
     * @throws IOException if any decoding errors occur.
     */
    private static Map<String, Extension>
        parseExtensions(DerValue derVal) throws IOException {
        DerValue[] extDer = derVal.data.getSequence(3);
        Map<String, Extension> extMap =
                new HashMap<String, Extension>(extDer.length);

        for (DerValue extDerVal : extDer) {
            Extension ext = new Extension(extDerVal);
            if (DEBUG != null) {
                DEBUG.println("Extension: " + ext);
            }
            // We don't support any extensions yet. Therefore, if it
            // is critical we must throw an exception because we
            // don't know how to process it.
            if (ext.isCritical()) {
                throw new IOException("Unsupported OCSP critical extension: " +
                        ext.getExtensionId());
            }
            extMap.put(ext.toString(), ext);
        }

        return extMap;
    }

    /*
     * A class representing a single OCSP response.
     */
    public static final class SingleResponse implements OCSP.RevocationStatus {
        private final CertId certId;
        private final CertStatus certStatus;
        private final Date thisUpdate;
        private final Date nextUpdate;
        private final Date revocationTime;
        private static Reason[] values = Reason.values();
        private final Reason revocationReason;

        private SingleResponse(DerValue der) throws IOException {
            if (der.tag != DerValue.tag_Sequence) {
                throw new IOException("Bad ASN.1 encoding in SingleResponse");
            }
            DerInputStream tmp = der.data;

            certId = new CertId(tmp.getDerValue().data);
            DerValue derVal = tmp.getDerValue();
            short tag = (byte)(derVal.tag & 0x1f);
            if (tag ==  CERT_STATUS_REVOKED) {
                certStatus = CertStatus.REVOKED;
                revocationTime = derVal.data.getGeneralizedTime();
                if (derVal.data.available() != 0) {
                    DerValue dv = derVal.data.getDerValue();
                    tag = (byte)(dv.tag & 0x1f);
                    if (tag == 0) {
                        int reason = dv.data.getEnumerated();
                        // if reason out-of-range just leave as UNSPECIFIED
                        if (reason >= 0 && reason < values.length) {
                            revocationReason = values[reason];
                        } else {
                            revocationReason = Reason.UNSPECIFIED;
                        }
                    } else {
                        revocationReason = Reason.UNSPECIFIED;
                    }
                } else {
                    revocationReason = Reason.UNSPECIFIED;
                }

                // RevokedInfo
                if (DEBUG != null) {
                    DEBUG.println("Revocation time: " + revocationTime);
                    DEBUG.println("Revocation reason: " + revocationReason);
                }
            } else {
                revocationTime = null;
                revocationReason = null;
                if (tag == CERT_STATUS_GOOD) {
                    certStatus = CertStatus.GOOD;
                } else if (tag == CERT_STATUS_UNKNOWN) {
                    certStatus = CertStatus.UNKNOWN;
                } else {
                    throw new IOException("Invalid certificate status");
                }
            }

            thisUpdate = tmp.getGeneralizedTime();

            if (tmp.available() == 0)  {
                // we are done
                nextUpdate = null;
            } else {
                derVal = tmp.getDerValue();
                tag = (byte)(derVal.tag & 0x1f);
                if (tag == 0) {
                    // next update
                    nextUpdate = derVal.data.getGeneralizedTime();
                } else {
                    nextUpdate = null;
                }
            }
            // singleExtensions
            if (tmp.available() > 0) {
                derVal = tmp.getDerValue();
                if (derVal.isContextSpecific((byte)1)) {
                    DerValue[] singleExtDer = derVal.data.getSequence(3);
                    for (int i = 0; i < singleExtDer.length; i++) {
                        Extension ext = new Extension(singleExtDer[i]);
                        if (DEBUG != null) {
                            DEBUG.println("OCSP single extension: " + ext);
                        }
                        if (ext.isCritical())  {
                            throw new IOException(
                                "Unsupported OCSP critical extension: " +
                                ext.getExtensionId());
                        }
                    }
                }
            }

            long now = System.currentTimeMillis();
            Date nowPlusSkew = new Date(now + MAX_CLOCK_SKEW);
            Date nowMinusSkew = new Date(now - MAX_CLOCK_SKEW);
            if (DEBUG != null) {
                String until = "";
                if (nextUpdate != null) {
                    until = " until " + nextUpdate;
                }
                DEBUG.println("OCSP response validity interval is from " +
                              thisUpdate + until);
                DEBUG.println("Checking validity of OCSP response on: " +
                    new Date(now));
            }
            // Check that the test date is within the validity interval:
            //   [ thisUpdate - MAX_CLOCK_SKEW,
            //     MAX(thisUpdate, nextUpdate) + MAX_CLOCK_SKEW ]
            if (nowPlusSkew.before(thisUpdate) ||
                nowMinusSkew.after(
                    nextUpdate != null ? nextUpdate : thisUpdate)) {

                if (DEBUG != null) {
                    DEBUG.println("Response is unreliable: its validity " +
                        "interval is out-of-date");
                }
                throw new IOException("Response is unreliable: its validity " +
                    "interval is out-of-date");
            }
        }

        /*
         * Return the certificate's revocation status code
         */
        @Override public CertStatus getCertStatus() {
            return certStatus;
        }

        private CertId getCertId() {
            return certId;
        }

        @Override public Date getRevocationTime() {
            return (Date) revocationTime.clone();
        }

        @Override public Reason getRevocationReason() {
            return revocationReason;
        }

        /**
         * Construct a string representation of a single OCSP response.
         */
        @Override public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("SingleResponse:\n");
            sb.append(certId);
            sb.append("\nCertStatus: ").append(certStatus).append("\n");
            if (certStatus == CertStatus.REVOKED) {
                sb.append("revocationTime is ");
                sb.append(revocationTime).append("\n");
                sb.append("revocationReason is ");
                sb.append(revocationReason).append("\n");
            }
            sb.append("thisUpdate is ").append(thisUpdate).append("\n");
            if (nextUpdate != null) {
                sb.append("nextUpdate is ").append(nextUpdate).append("\n");
            }
            return sb.toString();
        }
    }

    /**
     * Helper class that allows consumers to pass in issuer information.  This
     * will always consist of the issuer's name and public key, but may also
     * contain a certificate if the originating data is in that form.  The
     * trust anchor for the certificate chain will be included for certpath
     * disabled algorithm checking.
     */
    static final class IssuerInfo {
        private final TrustAnchor anchor;
        private final X509Certificate certificate;
        private final X500Principal name;
        private final PublicKey pubKey;

        IssuerInfo(TrustAnchor anchor) {
            this(anchor, (anchor != null) ? anchor.getTrustedCert() : null);
        }

        IssuerInfo(X509Certificate issuerCert) {
            this(null, issuerCert);
        }

        IssuerInfo(TrustAnchor anchor, X509Certificate issuerCert) {
            if (anchor == null && issuerCert == null) {
                throw new NullPointerException("TrustAnchor and issuerCert " +
                        "cannot be null");
            }
            this.anchor = anchor;
            if (issuerCert != null) {
                name = issuerCert.getSubjectX500Principal();
                pubKey = issuerCert.getPublicKey();
                certificate = issuerCert;
            } else {
                name = anchor.getCA();
                pubKey = anchor.getCAPublicKey();
                certificate = anchor.getTrustedCert();
            }
        }

        /**
         * Get the certificate in this IssuerInfo if present.
         *
         * @return the {@code X509Certificate} used to create this IssuerInfo
         * object, or {@code null} if a certificate was not used in its
         * creation.
         */
        X509Certificate getCertificate() {
            return certificate;
        }

        /**
         * Get the name of this issuer.
         *
         * @return an {@code X500Principal} corresponding to this issuer's
         * name.  If derived from an issuer's {@code X509Certificate} this
         * would be equivalent to the certificate subject name.
         */
        X500Principal getName() {
            return name;
        }

        /**
         * Get the public key for this issuer.
         *
         * @return a {@code PublicKey} for this issuer.
         */
        PublicKey getPublicKey() {
            return pubKey;
        }

        /**
         * Get the TrustAnchor for the certificate chain.
         *
         * @return a {@code TrustAnchor}.
         */
        TrustAnchor getAnchor() {
            return anchor;
        }

        /**
         * Create a string representation of this IssuerInfo.
         *
         * @return a {@code String} form of this IssuerInfo object.
         */
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Issuer Info:\n");
            sb.append("Name: ").append(name.toString()).append("\n");
            sb.append("Public Key:\n").append(pubKey.toString()).append("\n");
            return sb.toString();
        }
    }
}
