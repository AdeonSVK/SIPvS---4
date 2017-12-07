//import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;
import com.sun.org.apache.xpath.internal.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.xpath.XPathException;
import org.xml.sax.SAXException;

import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.ByteArrayInputStream;

import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.math.BigInteger;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpressionException;
import java.io.StringWriter;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRLEntry;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;


public class SignatureVerifier {
    Document mDocument;

    // nacitanie relevantnych elementov
    Element root;
    Element signature;
    Element signedInfo;
    Element signatureValue;
    Element keyInfo;
    Element signatureProperties;
    Element signatureMethod;
    Element canonicalizationMethod;
    TimeStampToken token;
    X509CRL crl;

    private List<String> canonicalizationMethods = new ArrayList<String>(Arrays.asList(

            new String[]{
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            }
    ));

    private List<String> transformMethods = new ArrayList<>(Arrays.asList(

            new String[]{
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            }
    ));

    private List<String> digestMethods = new ArrayList<>(Arrays.asList(

            new String[]{
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    "http://www.w3.org/2001/04/xmldsig-more#sha224",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    "http://www.w3.org/2001/04/xmldsig-more#sha384",
                    "http://www.w3.org/2001/04/xmlenc#sha512"
            }
    ));

    private List<String> signatureMethods = new ArrayList<>(Arrays.asList(

            new String[]{
                    "http://www.w3.org/2001/04/xmldsig#dsa-sha1",
                    "http://www.w3.org/2001/04/xmldsig#rsa-sha1",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            }
    ));

    private List<String> validReferences = new ArrayList<>(Arrays.asList(

            new String[]{
                    "ds:KeyInfo",
                    "ds:SignatureProperties",
                    "xades:SignedProperties",
                    "ds:Manifest"
            }
    ));

    private static final Map<String, String> DIGEST_ALG;

    static {
        DIGEST_ALG = new HashMap<String, String>();
        DIGEST_ALG.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha224", "SHA-224");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
    }

    private static final Map<String, String> SIGN_ALG;

    static {
        SIGN_ALG = new HashMap<String, String>();
        SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
        SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA/ISO9796-2");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
    }

    public SignatureVerifier(Document document) {

        com.sun.org.apache.xml.internal.security.Init.init();

        mDocument = document;

        mDocument.getDocumentElement().normalize();
        root = mDocument.getDocumentElement();

        // nacitanie relevantnych elementov
        signature = (Element) root.getElementsByTagName("ds:Signature").item(0);
        signedInfo = (Element) signature.getElementsByTagName("ds:SignedInfo").item(0);
        signatureValue = (Element) signature.getElementsByTagName("ds:SignatureValue").item(0);
        keyInfo = (Element) signature.getElementsByTagName("ds:KeyInfo").item(0);
        signatureProperties = (Element) signature.getElementsByTagName("ds:SignatureProperties").item(0);

        signatureMethod = (Element) signature.getElementsByTagName("ds:SignatureMethod").item(0);
        canonicalizationMethod = (Element) signature.getElementsByTagName("ds:CanonicalizationMethod").item(0);

        token = getTimestampToken();
        crl = getCRL();
    }

    void verifyRootElement() {
        mDocument.getDocumentElement().normalize();
        Element root = mDocument.getDocumentElement();

        // Overenie dátovej obálky:
        // kontrola 1
        if (root.hasAttribute("xmlns:xzep") && (root.getAttribute("xmlns:xzep").equals("http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0"))) {
        } else {
            System.out.println("Check 1 : Fail - xmlns:xzep is missing or is not valid");
            return;
        }
        if (root.hasAttribute("xmlns:ds") && (root.getAttribute("xmlns:ds").equals("http://www.w3.org/2000/09/xmldsig#"))) {
        } else {
            System.out.println("Check 1 : Fail - xmlns:ds is missing or is not valid");
            return;
        }
        System.out.println("Check 1 : OK - xmlns:ds is valid");
    }

    void verifySignatureAndCanonicalizationMethods() {

        // Overenie XML Signature:
        // kontrola 2

        if (canonicalizationMethod.hasAttribute("Algorithm") && canonicalizationMethods.contains(canonicalizationMethod.getAttribute("Algorithm"))) {
        } else {
            System.out.println("Check 2 : Fail - canonicalization algorithm is missing or is not supported");
            return;
        }

        if (signatureMethod.hasAttribute("Algorithm") && signatureMethods.contains(signatureMethod.getAttribute("Algorithm"))) {
        } else {
            System.out.println("Check 2 : Fail - signature algorithm is missing or is not supported");
            return;
        }
        System.out.println("Check 2 : OK - signature algorithm is valid");

    }

    void verifyTransformsAndDigestMethods() {
        NodeList transformsElements = null;
        try {
            transformsElements = XPathAPI.selectNodeList(mDocument.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms");
        } catch (XPathException e) {
            System.out.println("Check 3 : Fail - Chyba pri kontrole elementu ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms. Element nebol v dokumente najdeny");
            return;
        } catch (TransformerException e) {
            e.printStackTrace();
        }

        for (int i = 0; i < transformsElements.getLength(); i++) {

            Element transformsElement = (Element) transformsElements.item(i);
            Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(0);

			/*
             * Kontrola obsahu ds:Transforms
			 * Musi obsahovať URI niektorého z podporovaných algoritmov
			 */
            if (!assertElementAttributeValue(transformElement, "Algorithm", transformMethods)) {

                System.out.println("Check 3 : Fail - Atribút Algorithm elementu ds:Transforms neobsahuje URI niektorého z podporovaných algoritmov");
                return;
            }
        }


        NodeList digestMethodElements = signedInfo.getElementsByTagName("ds:DigestMethod");
//        try {
//            digestMethodElements = XPathAPI.selectNodeList(mDocument.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod");
//
//        } catch (XPathException e) {
//
//            System.out.println("Chyba pri kontrole elementu ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod. Element nebol v dokumente najdeny");
//            return;
//        }

//        System.out.println("digestMethodElements" + digestMethodElements + " + size = " + digestMethodElements.getLength());

        for (int i = 0; i < digestMethodElements.getLength(); i++) {

            Element digestMethodElement = (Element) digestMethodElements.item(i);

            if (!assertElementAttributeValue(digestMethodElement, "Algorithm", digestMethods)) {
                System.out.println("Check 3 : Fail - Atribút Algorithm elementu ds:DigestMethod neobsahuje URI niektorého z podporovaných algoritmov");
                return;
            }
        }

        System.out.println("Check 3 : OK - xmlns:ds is valid");
    }

    void verifyCore() {
        // TODO Kontrola 4 - Core validation
        verifyCoreReferencesAndDigestValue();
    }


    public void verifyCoreReferencesAndDigestValue() {

        NodeList referencesElements = signedInfo.getElementsByTagName("ds:Reference");

//        try {
//            referencesElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference");
//
//        } catch (XPathException e) {
//        } catch (XPathException e) {
//
//            throw new DocumentVerificationException(
//                    "Chyba pri ziskavani elementu ds:Signature/ds:SignedInfo/ds:Reference. Element nebol v dokumente najdeny");
//        }

        for (int i = 0; i < referencesElements.getLength(); i++) {

            Element referenceElement = (Element) referencesElements.item(i);
            String uri = referenceElement.getAttribute("URI").substring(1);

            Element manifestElement = findByAttributeValue("ds:Manifest", "Id", uri);

            if (manifestElement == null) {
                continue;
            }

            Element digestValueElement = (Element) referenceElement.getElementsByTagName("ds:DigestValue").item(0);
            String expectedDigestValue = digestValueElement.getTextContent();

            Element digestMethodElement = (Element) referenceElement.getElementsByTagName("ds:DigestMethod").item(0);

            if (!assertElementAttributeValue(digestMethodElement, "Algorithm", digestMethods)) {

                System.out.println("Check 4: Fail - Atribút Algorithm elementu ds:DigestMethod (" + digestMethodElement.getAttribute("Algorithm") + ") neobsahuje URI niektorého z podporovaných algoritmov");
                return;
            }

            String digestMethod = digestMethodElement.getAttribute("Algorithm");
            digestMethod = DIGEST_ALG.get(digestMethod);


            byte[] manifestElementBytes = null;

            try {
                manifestElementBytes = fromElementToString(manifestElement).getBytes();

            } catch (TransformerException e) {

                System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri tranformacii z Element do String");
                return;
            }

            NodeList transformsElements = manifestElement.getElementsByTagName("ds:Transforms");

            for (int j = 0; j < transformsElements.getLength(); j++) {

                Element transformsElement = (Element) transformsElements.item(j);
                Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(0);
                String transformMethod = transformElement.getAttribute("Algorithm");

                if ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".equals(transformMethod)) {

                    try {
                        Canonicalizer canonicalizer = Canonicalizer.getInstance(transformMethod);
                        manifestElementBytes = canonicalizer.canonicalize(manifestElementBytes);

                    } catch (SAXException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | IOException e) {

                        System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri kanonikalizacii");
                        return;
                    }
                }
            }

            MessageDigest messageDigest = null;

            try {
                messageDigest = MessageDigest.getInstance(digestMethod);

            } catch (NoSuchAlgorithmException e) {

                System.out.println("Check 4: Fail - Core validation zlyhala. Neznamy algoritmus " + digestMethod);
                return;
            }
            String actualDigestValue = new String(Base64.encode(messageDigest.digest(manifestElementBytes)));


            if (expectedDigestValue.equals(actualDigestValue) == false) {

                System.out.println("Check 4: Fail - Core validation zlyhala. " + "Hodnota ds:DigestValue elementu ds:Reference sa nezhoduje s hash hodnotou elementu ds:Manifest");
                return;
            }

        }

        verifyCoreSignatureValue();
        return;
    }

    /*
     * Core validation (podľa špecifikácie XML Signature)
     * Kanonikalizácia ds:SignedInfo a overenie hodnoty ds:SignatureValue
     * pomocou pripojeného podpisového certifikátu v ds:KeyInfo
     */
    public void verifyCoreSignatureValue() {

        Element signatureElement = (Element) mDocument.getElementsByTagName("ds:Signature").item(0);

        Element signedInfoElement = (Element) signatureElement.getElementsByTagName("ds:SignedInfo").item(0);
        Element canonicalizationMethodElement = (Element) signedInfoElement.getElementsByTagName("ds:CanonicalizationMethod").item(0);
        Element signatureMethodElement = (Element) signedInfoElement.getElementsByTagName("ds:SignatureMethod").item(0);
        Element signatureValueElement = (Element) signatureElement.getElementsByTagName("ds:SignatureValue").item(0);


        byte[] signedInfoElementBytes = null;
        try {
            signedInfoElementBytes = fromElementToString(signedInfoElement).getBytes();
        } catch (TransformerException e) {

            System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri tranformacii z Element do String");
            return;
        }

        String canonicalizationMethod = canonicalizationMethodElement.getAttribute("Algorithm");

        try {
            Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationMethod);
            signedInfoElementBytes = canonicalizer.canonicalize(signedInfoElementBytes);

        } catch (SAXException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | IOException e) {

            System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri kanonikalizacii");
            return;
        }

        Element x509Certificate = (Element) keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
        if (x509Certificate == null) {
            System.out.println("Check 4: Fail - element x509Certificate is missing");
            return;
        }

        Signature signer = null;
        X509Certificate certificate = null;
        try {


            byte[] bencoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(x509Certificate.getFirstChild().getNodeValue());

            InputStream certData = new ByteArrayInputStream(bencoded);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(certData);
//            certificate = getCertificate();

            if (certificate == null) {
                System.out.println("Check 4: Fail - X509 certifikát sa v dokumente nepodarilo nájsť");
                return;
            }

//        } catch (XPathExpressionException e) {
//
//            System.out.println("Check 4: Fail - X509 certifikát sa v dokumente nepodarilo nájsť");
//            return;
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        String signatureMethod = signatureMethodElement.getAttribute("Algorithm");
        signatureMethod = SIGN_ALG.get(signatureMethod);


        if (signatureMethod == null) {
            System.out.println("Check 4 : Fail - Chyba pri inicializacii signeru");
            return;
        }


        try {

            com.sun.org.apache.xml.internal.security.Init.init();
            signer = Signature.getInstance(signatureMethod);
//            System.out.println("Public key " + certificate.getPublicKey());
            signer.initVerify(certificate.getPublicKey());
            signer.update(signedInfoElementBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri inicializacii prace s digitalnym podpisom");
            return;
        }

        byte[] signatureValueBytes = signatureValueElement.getTextContent().getBytes();
        byte[] decodedSignatureValueBytes = Base64.decode(signatureValueBytes);

        boolean verificationResult = false;

        try {
            verificationResult = signer.verify(decodedSignatureValueBytes);

        } catch (SignatureException e) {

            System.out.println("Check 4: Fail - Core validation zlyhala. Chyba pri verifikacii digitalneho podpisu");
            return;
        }

        if (verificationResult == false) {

            System.out.println("Check 4: Fail - Podpisana hodnota ds:SignedInfo sa nezhoduje s hodnotou v elemente ds:SignatureValue");
            return;
        }

        System.out.println("Check 4 : OK - verifyCore is valid");
        return;
    }


    void verifySignature() {

        if (!signature.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - signature id attribute is missing");
            return;
        }
        if (!signature.hasAttribute("xmlns:ds")) {
            System.out.println("Check 5: Fail - signature xmlns:ds attribute is missing");
            return;
        }
        // 	ds:SignatureValue
        if (!signatureValue.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - signatureValue id attribute is missing");
            return;
        }


    }

    void verifySignatureValue() {


        Element signatureValueElement = (Element) root.getElementsByTagName("ds:SignatureValue").item(0);

        if (signatureValueElement == null) {
            System.out.println("Check 6: Fail - Element ds:SignatureValue sa nenašiel");
            return;

        }

        if (!signatureValueElement.hasAttribute("Id")) {
            System.out.println("Check 6: Fail - Element ds:SignatureValue neobsahuje atribút Id ");
            return;
        }

        System.out.println("Check 6 : OK - verifySignatureValue is valid");
    }

    void verifySignedInfoReferences() {

        NodeList references = signedInfo.getElementsByTagName("ds:Reference");
        boolean keyInfoPresent = false;
        boolean signaturePropertiesPresent = false;
        boolean signedPropertiesPresent = false;


        for (int i = 0; i < references.getLength(); i++) {
            Element reference = (Element) references.item(i);
            if (!reference.hasAttribute("URI")) {
                System.out.println("Check 7: Fail - URI attribute of reference is missing");
                return;
            }
            Node referencedNode = null;

            String URI = reference.getAttribute("URI").substring(1);
            try {
                referencedNode = XPathAPI.selectSingleNode(mDocument.getDocumentElement(), "//*[@Id=\"" + URI + "\"]");
            } catch (TransformerException e) {
                e.printStackTrace();
            }
            if (referencedNode == null) {
                System.out.println("Check 7: Fail - Referenced element doesnt exist");
                return;
            }

            if (referencedNode.getNodeName().equals("xades:SignedProperties")) {
                signedPropertiesPresent = true;
            }
            if (referencedNode.getNodeName().equals("ds:SignatureProperties")) {
                signaturePropertiesPresent = true;
            }
            if (referencedNode.getNodeName().equals("ds:KeyInfo")) {
                keyInfoPresent = true;
            }

            if (!validReferences.contains(referencedNode.getNodeName())) {
                System.out.println("Check 7: Fail - Referenced element is not a valid object");
                return;
            }
        }
        if (!signedPropertiesPresent || !signaturePropertiesPresent || !keyInfoPresent) {
            System.out.println("Check 7: Fail - One of the mandatory references is missing in signed info");
            return;
        }
        System.out.println("Check 7 : OK - verifySignedInfoReferences is valid");
    }

    void verifyKeyInfo() {
        if (!keyInfo.hasAttribute("Id")) {
            System.out.println("Check 8: Fail - keyInfo id attribute is missing");
            return;
        }

        Element x509Data = (Element) keyInfo.getElementsByTagName("ds:X509Data").item(0);
        Element x509Certificate = (Element) keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
        Element x509IssuerSerial = (Element) keyInfo.getElementsByTagName("ds:X509IssuerSerial").item(0);
        Element x509IssuerSerialNumber = (Element) x509IssuerSerial.getElementsByTagName("ds:X509SerialNumber").item(0);
        Element x509SubjectName = (Element) keyInfo.getElementsByTagName("ds:X509SubjectName").item(0);

        if (x509Data == null) {
            System.out.println("Check 8: Fail - element x509Data is missing");
            return;
        }


        if (x509Certificate == null) {
            System.out.println("Check 8: Fail - element x509Certificate is missing");
            return;
        }
        if (x509IssuerSerial == null) {
            System.out.println("Check 8: Fail - element x509IssuerSerial is missing");
            return;
        }
        if (x509SubjectName == null) {
            System.out.println("Check 8: Fail - element x509SubjectName is missing");
            return;
        }

        if (x509IssuerSerialNumber == null) {
            System.out.println("Check 8: Fail - element X509SerialNumber is missing");
            return;
        }

        StreamResult result = new StreamResult(new StringWriter());
        Transformer transformer = null;
        InputStream certData = null;
        X509Certificate certificate = null;

        try {
//
            byte[] bencoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(x509Certificate.getFirstChild().getNodeValue());
            certData = new ByteArrayInputStream(bencoded);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(certData);
        } catch (java.security.cert.CertificateException e) {
            System.out.println("Check 8: Fail - It was impossible to construct certificate from file");
            return;
        }

        if (certificate != null) {
//            String certificateIssuerName = certificate.getIssuerDN().toString();
            String certificateSerialNumber = certificate.getSerialNumber().toString();
            String certificateSubjectName = certificate.getSubjectDN().toString();
            if (!certificateSerialNumber.equals(x509IssuerSerialNumber.getFirstChild().getNodeValue())) {
                System.out.println("Check 8: Fail - Serial number is not in certificate");
                return;
            }
            if (!certificateSubjectName.equals(x509SubjectName.getFirstChild().getNodeValue())) {
                System.out.println("Check 8: Fail - Subject name is not in certificate");
                return;
            }
        }
        System.out.println("Check 8 : OK - verifyKeyInfo is valid");
    }

    void verifySignatureProperties() {


        // 	overenie obsahu ds:SignatureProperties
        if (!signatureProperties.hasAttribute("Id")) {
            System.out.println("Check 9: Fail - signatureProperties id is missing");
            return;
        }

        boolean sigVersion = false;
        boolean productInfo = false;

        Element sigProperty1 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(0);
        Element sigProperty2 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(1);

        if (sigProperty1 == null) {
            System.out.println("Check 9: Fail - element signatureProperty is missing");
            return;
        }
        if (sigProperty2 == null) {
            System.out.println("Check 9: Fail - element signatureProperty is missing");
            return;
        }

        if (sigProperty1 != null && sigProperty2 != null) {
            if (sigProperty1.getElementsByTagName("xzep:SignatureVersion") != null) {
                sigVersion = true;
            }
            if (sigProperty1.getElementsByTagName("xzep:ProductInfos") != null) {
                productInfo = true;
            }

            if (sigProperty2.getElementsByTagName("xzep:SignatureVersion") != null) {
                sigVersion = true;
            }
            if (sigProperty2.getElementsByTagName("xzep:ProductInfos") != null) {
                productInfo = true;
            }

            if (!sigVersion) {
                System.out.println("Check 9: Fail - element xzep:SignatureVersion  is missing");
                return;
            }
            if (!productInfo) {
                System.out.println("Check 9: Fail - xzep:ProductInfos");
                return;
            }
        }

        if (!sigProperty1.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
            System.out.println("Check 9: Fail - SignatureProperty 1 does not have target attribute or is not referencing signature id");
            return;

        }

        if (!sigProperty2.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
            System.out.println("Check 9: Fail - SignatureProperty 2 does not have target attribute or is not referencing signature id");
            return;
        }


        System.out.println("Check 9 : OK - verifySignatureProperties is valid");
    }

    void verifyManifest() {
        boolean manifestReferences = false;
        NodeList manifests = signature.getElementsByTagName("ds:Manifest");

        for (int i = 0; i < manifests.getLength(); i++) {
            Element manifest = (Element) manifests.item(i);
            if (!manifest.hasAttribute("Id")) {
                System.out.println("Check 10: Fail - manifest id attribute is missing");
                return;
            }


            NodeList references = manifest.getElementsByTagName("ds:Reference");

            if (references.getLength() != 1) {
                System.out.println("Check 10: Fail - incorrect number of references in manifest element");
                return;
            }

            Map<String, String> digestAlgMap;
            digestAlgMap = new HashMap<String, String>();
            digestAlgMap.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
            digestAlgMap.put("http://www.w3.org/2001/04/xmldsig-more#sha224", "SHA-224");
            digestAlgMap.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
            digestAlgMap.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
            digestAlgMap.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");

            for (int j = 0; j < references.getLength(); j++) {
                Element reference = (Element) references.item(j);
                Element referencedObject = null;
                String digAlg = null;
                String digestMethod = null;
                String transformMethod = null;
                byte[] objectElementBytes = null;
                boolean canonicalizationSuccessful = false;

                if (!reference.hasAttribute("Type") || !reference.getAttribute("Type").equals("http://www.w3.org/2000/09/xmldsig#Object")) {
                    System.out.println("Check 10: Fail - Type attribute of reference is missing");
                    return;
                }

                if (!reference.hasAttribute("URI")) {
                    System.out.println("Check 10: Fail - URI attribute of reference is missing");
                    return;
                } else {

                    String URI = reference.getAttribute("URI").substring(1);
                    NodeList objects = root.getElementsByTagName("ds:Object");
                    for (int k = 0; k < objects.getLength(); k++) {
                        Element object = (Element) objects.item(k);
                        if (object.getAttribute("Id").equals(URI)) {
                            referencedObject = object;
                        }
                    }
                }


                if (referencedObject == null) {
                    System.out.println("Check 11: Fail - Referenced object from manifest is either missing or has missing or invalid Id");
                    return;
                } else {

                    StreamResult result = new StreamResult(new StringWriter());
                    Transformer transformer = null;
                    try {
                        transformer = TransformerFactory.newInstance().newTransformer();
                        transformer.transform(new DOMSource(referencedObject), result);
                        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                        objectElementBytes = result.getWriter().toString().getBytes();
                    } catch (TransformerConfigurationException e) {
                        e.printStackTrace();
                    } catch (TransformerException e) {
                        e.printStackTrace();
                    }
                }

                Element digest = (Element) reference.getElementsByTagName("ds:DigestMethod").item(0);

                if (digest.hasAttribute("Algorithm") && digestMethods.contains(digest.getAttribute("Algorithm"))) {
                    digAlg = digest.getAttribute("Algorithm");

                } else {
                    System.out.println("Check 11: Fail - Digest algorithm is missing or is not supported");
                    return;
                }
                Element digestValueElement = (Element) reference.getElementsByTagName("ds:DigestValue").item(0);
                if (digestValueElement == null) {
                    System.out.println("Check 11: Fail - Digest value is missing from a reference element");
                    return;
                }

                Canonicalizer canonicalizer = null;
                Element transform = (Element) reference.getElementsByTagName("ds:Transform").item(0);
                if(!transform.hasAttribute("Algorithm") || !transformMethods.contains(transform.getAttribute("Algorithm"))){
                    System.out.println("Check 11: Fail - Transform algorithm is invalid");
                    return;
                }

                transformMethod = transform.getAttribute("Algorithm");

                if (transformMethod.equals("http://www.w3.org/2000/09/xmldsig#base64"))
                    objectElementBytes = Base64.decode(String.valueOf(objectElementBytes));
                if (transformMethod.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {

                    try {
                        Init.init();
                        canonicalizer = Canonicalizer.getInstance(transformMethod);
                        objectElementBytes = canonicalizer.canonicalize(objectElementBytes);
                        canonicalizationSuccessful = true;

                    } catch (InvalidCanonicalizerException e1) {
                        System.out.println("Check 11: Fail - Invalid Canonicalizing method");
                        return;
                    } catch (CanonicalizationException e) {
                        e.printStackTrace();
                    } catch (SAXException e) {
                        e.printStackTrace();
                    } catch (ParserConfigurationException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }



                if (referencedObject != null && digAlg != null && transformMethod != null && objectElementBytes != null && digestValueElement != null && canonicalizationSuccessful != false) {
                    digestMethod = digestAlgMap.get(digAlg);
                    MessageDigest messageDigest = null;
                    try {
                        messageDigest = MessageDigest.getInstance(digestMethod);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                    String actualDigestValue = new String(Base64.encode(messageDigest.digest(objectElementBytes)));
                    String digestValue = digestValueElement.getTextContent();
                    manifestReferences = true;
                    if (digestValue.equals(actualDigestValue) == false) {
                        System.out.println("Check 11: Fail - Digest Value in ds:Reference object is not equal with the hash content of the referenced object");
                        return;
                    }


                }
            }
        }


        System.out.println("Check 10: OK - verifyManifest is valid");
        if (manifestReferences == true) {
            System.out.println("Check 11: OK - verifyManifestReferences is valid");
        }

    }

    //    toto je v tom vyssom, je to validne preist oba naraz
    void verifyManifestReferences() {

    }

    void verifyTimestamp() {

        X509CertificateHolder signer = null;
        if(token == null){
            System.out.println("Check 12: Fail -token not found ");
            return;
        }
        Store certHolders = token.getCertificates();

        ArrayList<X509CertificateHolder> certList = new ArrayList<>(certHolders.getMatches(null));

        BigInteger serialNumToken = token.getSID().getSerialNumber();
        X500Name issuerToken = token.getSID().getIssuer();



        for (X509CertificateHolder certHolder : certList) {
            if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)) {
                signer = certHolder;
                break;
            }
        }

        if (signer == null) {
            System.out.println("Check 12: Fail - Timestamp certificate not present in document.");
            return;
        }

        if (!signer.isValidOn(new Date())) {
            System.out.println("Check 12: Fail - Timestamp signature certificate is not valid at the given time.");
            return;
        }

        if (crl.getRevokedCertificate(signer.getSerialNumber()) != null) {
            System.out.println("Check 12: Fail - Latest signature timestamp certificate is not valid against the latest valid CRL.");
            return;
        }
        System.out.println("Check 12: OK - verifyTimestamp is valid");
    }

    void verifyMessageImprint() {

        if(token == null){
            System.out.println("Check 13: Fail -token not found ");
            return;
        }
        byte[] messageImprint = token.getTimeStampInfo().getMessageImprintDigest();
        String hashAlg = token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

        Map<String, String> nsMap = new HashMap<>();
        nsMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");

        Node signatureValueNode = null;

        try {
            signatureValueNode = signature.getElementsByTagName("ds:SignatureValue").item(0);
        } catch (XPathException e) {
            System.out.println("Check 13: Fail - Element ds:SignatureValue not found.");
            e.printStackTrace();
            return;
        }

        if (signatureValueNode == null) {
            System.out.println("Check 13: Fail - Element ds:SignatureValue not found.");
            return;
        }

        byte[] signatureValue = Base64.decode(signatureValueNode.getTextContent());

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Check 13: Fail - Unsupported algorithm in message digest.");
            return;
        }

        if (!Arrays.equals(messageImprint, messageDigest.digest(signatureValue))) {
            System.out.println("Check 13: Fail - MessageImprint from timestamp does not match ds:SignatureValue.");
            return;
        }

        System.out.println("Check 13: OK - verifyMessageImprint is valid");
    }

    void verifyCertificate() {

        Node certificateNode = null;

        if (token == null) {
            System.out.println("Check 14: Fail - Failed to get timestamp token.");
        }

        if (crl == null) {
            System.out.println("Check 14: Fail - Failed to get CRL.");
        }

        try {
            certificateNode = signature.getElementsByTagName("ds:X509Certificate").item(0);
        } catch (XPathException e) {
            e.printStackTrace();
            System.out.println("Check 14: Fail - invalid path to certificate");
            return;
        }

        if (certificateNode == null) {
            System.out.println("Check 14: Fail - Element ds:X509Certificate not found.");
            return;
        }

        X509CertificateObject cert = null;
        ASN1InputStream asn1is = null;

        try {
            asn1is = new ASN1InputStream(new ByteArrayInputStream(Base64.decode(certificateNode.getTextContent())));
            ASN1Sequence sq = (ASN1Sequence) asn1is.readObject();
            cert = new X509CertificateObject(Certificate.getInstance(sq));
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Check 14: Fail - Creating certificate object failed.");
            return;
        } catch (CertificateParsingException e) {
            e.printStackTrace();
            System.out.println("Check 14: Fail - Parsing certificate object failed.");
            return;
        } finally {
            if (asn1is != null) {
                try {
                    asn1is.close();
                } catch (IOException e) {
                    System.out.println("Check 14: Fail - Cannot read document certificate.");
                    return;
                }
            }
        }

        try {
            if(token == null){
                System.out.println("Check 14: Fail - Token not found ");
                return;
            }
            cert.checkValidity(token.getTimeStampInfo().getGenTime());
        } catch (CertificateNotYetValidException e) {
            System.out.println("Check 14: Fail - Document certificate had not been valid at the time of signing.");
            return;
        } catch (CertificateExpiredException e) {
            System.out.println("Check 14: Fail - Document certificate has expired.");
            return;
        }

        X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
        if (entry != null && entry.getRevocationDate().before(token.getTimeStampInfo().getGenTime())) {
            System.out.println("Check 14: Fail - Certificate was terminated at the time of signing.");
            return;
        }

        System.out.println("Check 14: OK - verifyCertificate is valid");
    }

    private TimeStampToken getTimestampToken() {

        TimeStampToken token = null;

        Node timestamp = null;
        Map<String, String> nsMap = new HashMap<>();
        nsMap.put("xades", "http://uri.etsi.org/01903/v1.3.2#");
        Node ns;

        try {
            //timestamp = XPathAPI.selectSingleNode(this.mDocument, "//xades:EncapsulatedTimeStamp");
            timestamp = signature.getElementsByTagName("xades:EncapsulatedTimeStamp").item(0);
        } catch (XPathException e) {
            e.printStackTrace();
        }

        if (timestamp == null) {
            System.out.println("Document doesn't contain a timestamp.");
            return null;
        }

        try {
            token = new TimeStampToken(new CMSSignedData(Base64.decode(timestamp.getTextContent())));
        } catch (TSPException | IOException | CMSException e) {
            e.printStackTrace();
        }

        return token;
    }

    private X509CRL getCRL() {

        ByteArrayInputStream crlData = getDataFromUrl("http://test.ditec.sk/DTCCACrl/DTCCACrl.crl");
        CertificateFactory certFactory = null;
        X509CRL crl = null;

        if (crlData == null) {
            System.out.println("Downloading CRL failed.");
            return null;
        }

        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            System.out.println("Creating CertificateFactory instance failed.");
        }

        try {
            crl = (X509CRL) certFactory.generateCRL(crlData);
        } catch (CRLException e) {
            System.out.println("Failed to get CRL from the data received.");
        }

        return crl;
    }

    private ByteArrayInputStream getDataFromUrl(String url) {

        URL urlHandler = null;
        try {
            urlHandler = new URL(url);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = null;
        try {
            is = urlHandler.openStream();
            byte[] byteChunk = new byte[4096];
            int n;

            while ((n = is.read(byteChunk)) > 0) {
                baos.write(byteChunk, 0, n);
            }
        } catch (IOException e) {
            System.err.printf("Failed while reading bytes from %s: %s", urlHandler.toExternalForm(), e.getMessage());
            return null;
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return new ByteArrayInputStream(baos.toByteArray());
    }

    boolean assertElementAttributeValue(Element element, String attribute, String expectedValue) {

        String actualValue = element.getAttribute(attribute);

        if (actualValue != null && actualValue.equals(expectedValue)) {

            return true;

        }
        return false;
    }

//    boolean assertElementAttributeValue(Element element, String attribute, List<String> expectedValues) {
//
//        for (String expectedValue : expectedValues) {
//
//            if (assertElementAttributeValue(element, attribute, expectedValue)) {
//
//                return true;
//            }
//        }
//        return false;
//    }

//    boolean assertElementAttributeValue(Element element, String attribute, String expectedValue) {
//
//        String actualValue = element.getAttribute(attribute);
//
//        if (actualValue != null && actualValue.equals(expectedValue)) {
//
//            return true;
//
//        }
//        return false;
//    }

    boolean assertElementAttributeValue(Element element, String attribute, List<String> expectedValues) {

        for (String expectedValue : expectedValues) {

            if (assertElementAttributeValue(element, attribute, expectedValue)) {

                return true;
            }
        }
        return false;
    }

    public Element findByAttributeValue(String elementType, String attributeName, String attributeValue) {

        NodeList elements = this.mDocument.getElementsByTagName(elementType);

        for (int i = 0; i < elements.getLength(); i++) {

            Element element = (Element) elements.item(i);

            if (element.hasAttribute(attributeName) && element.getAttribute(attributeName).equals(attributeValue)) {

                return element;
            }
        }

        return null;
    }

    public String fromElementToString(Element element) throws TransformerException {

        StreamResult result = new StreamResult(new StringWriter());

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(element), result);
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        return result.getWriter().toString();

    }

    public X509CertificateObject getCertificate() throws XPathExpressionException {

        Element keyInfoElement = (Element) mDocument.getElementsByTagName("ds:KeyInfo").item(0);

        if (keyInfoElement == null) {
//            System.out.println("Chyba pri ziskavani certifikatu: Dokument neobsahuje element ds:KeyInfo");
            return null;
        }

        Element x509DataElement = (Element) keyInfoElement.getElementsByTagName("ds:X509Data").item(0);

        if (x509DataElement == null) {
//            System.out.println("Chyba pri ziskavani certifikatu: Dokument neobsahuje element ds:X509Data");
            return null;
        }

        Element x509Certificate = (Element) x509DataElement.getElementsByTagName("ds:X509Certificate").item(0);

        if (x509Certificate == null) {
//            System.out.println("Chyba pri ziskavani certifikatu: Dokument neobsahuje element ds:X509Certificate");
            return null;
        }

        X509CertificateObject certObject = null;
        ASN1InputStream inputStream = null;

        try {
            inputStream = new ASN1InputStream(new ByteArrayInputStream(Base64.decode(x509Certificate.getTextContent())));
            ASN1Sequence sequence = (ASN1Sequence) inputStream.readObject();
            certObject = new X509CertificateObject(Certificate.getInstance(sequence));

        } catch (IOException | java.security.cert.CertificateParsingException e) {

            System.out.println("Certifikát nebolo možné načítať");
            return null;
        } finally {

            closeQuietly(inputStream);
        }

        return certObject;
    }


    private void closeQuietly(ASN1InputStream inputStream) {

        if (inputStream == null) {
            return;
        }

        try {
            inputStream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}


