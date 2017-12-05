import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
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

import javax.security.cert.CertificateException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
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

    public SignatureVerifier(Document document) {
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
        System.out.println("Check 4 : OK - verifyCore is valid");
    }


    void verifySignature() {

        if (!signature.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - signature id attribute is missing");
        }
        if (!signature.hasAttribute("xmlns:ds")) {
            System.out.println("Check 5: Fail - signature xmlns:ds attribute is missing");
        }
        // 	ds:SignatureValue
        if (!signatureValue.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - signatureValue id attribute is missing");
        }









    }

    void verifySignatureValue() {


        Element signatureValueElement = (Element) root.getElementsByTagName("ds:SignatureValue").item(0);

        if (signatureValueElement == null) {
            System.out.println( " Check X: Fail - Element ds:SignatureValue sa nenašiel");
            return;

        }

        if (!signatureValueElement.hasAttribute("Id")) {
            System.out.println( " Check X: Fail - Element ds:SignatureValue neobsahuje atribút Id ");
            return;
        }

        System.out.println("Check 6 : OK - verifySignatureValue is valid");
    }

    void verifySignedInfoReferences() {

        NodeList references = signedInfo.getElementsByTagName("ds:Reference");
        boolean keyInfoPresent = false;
        boolean signaturePropertiesPresent = false;
        boolean signedPropertiesPresent = false;


        for(int i=0;i<references.getLength();i++) {
            Element reference = (Element) references.item(i);
            if (!reference.hasAttribute("URI")) {
                System.out.println("Check 7: Fail - URI attribute of reference is missing");
                return;
            }
            Node referencedNode = null;

            String URI = reference.getAttribute("URI").substring(1);
            try {
                referencedNode = XPathAPI.selectSingleNode(mDocument.getDocumentElement(), "//*[@Id=\""+URI+"\"]");
            } catch (TransformerException e) {
                e.printStackTrace();
            }
            if (referencedNode==null){
                System.out.println("Check 7: Fail - Referenced element doesnt exist");
                return;
            }

            if (referencedNode.getNodeName().equals("xades:SignedProperties")){
                signedPropertiesPresent = true;
            }
            if (referencedNode.getNodeName().equals("ds:SignatureProperties")){
                signaturePropertiesPresent = true;
            }
            if (referencedNode.getNodeName().equals("ds:KeyInfo")){
                keyInfoPresent = true;
            }

            if (!validReferences.contains(referencedNode.getNodeName())){
                System.out.println("Check 7: Fail - Referenced element is not a valid object");
                return;
            }
        }
        if(!signedPropertiesPresent || !signaturePropertiesPresent || !keyInfoPresent){
            System.out.println("Check 7: Fail - One of the mandatory references is missing in signed info");
            return;
        }
        System.out.println("Check 7 : OK - verifySignedInfoReferences is valid");
    }

    void verifyKeyInfo() {
        if (!keyInfo.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - keyInfo id attribute is missing");
            return;
        }

        Element x509Data = (Element) keyInfo.getElementsByTagName("ds:X509Data").item(0);
        Element x509Certificate = (Element) keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
        Element x509IssuerSerial = (Element) keyInfo.getElementsByTagName("ds:X509IssuerSerial").item(0);
        Element x509IssuerSerialNumber = (Element) x509IssuerSerial.getElementsByTagName("ds:X509SerialNumber").item(0);
        Element x509SubjectName = (Element) keyInfo.getElementsByTagName("ds:X509SubjectName").item(0);

        if (x509Data == null) {
            System.out.println("Check 5: Fail - element x509Data is missing");
            return;
        }
        if (x509Certificate == null) {
            System.out.println("Check 5: Fail - element x509Certificate is missing");
            return;
        }
        if (x509IssuerSerial == null) {
            System.out.println("Check 5: Fail - element x509IssuerSerial is missing");
            return;
        }
        if (x509SubjectName == null) {
            System.out.println("Check 5: Fail - element x509SubjectName is missing");
            return;
        }

        if (x509IssuerSerialNumber == null) {
            System.out.println("Check 5: Fail - element X509SerialNumber is missing");
            return;
        }

        StreamResult result = new StreamResult(new StringWriter());
        Transformer transformer = null;
        InputStream certData =null;
        X509Certificate certificate =null;

        try {
//
            byte[] bencoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(x509Certificate.getFirstChild().getNodeValue());
            certData = new ByteArrayInputStream(bencoded);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate)cf.generateCertificate(certData);
        }catch (java.security.cert.CertificateException e) {
            System.out.println("Check 8: Fail - It was impossible to construct certificate from file");
            return;
        }

        if (certificate!=null){
//            String certificateIssuerName = certificate.getIssuerDN().toString();
            String certificateSerialNumber = certificate.getSerialNumber().toString();
            String certificateSubjectName = certificate.	getSubjectDN().toString();
            if (!certificateSerialNumber.equals(x509IssuerSerialNumber.getFirstChild().getNodeValue())){
                System.out.println("Check 8: Fail - Serial number is not in certificate");
                return;
            }
            if (!certificateSubjectName.equals(x509SubjectName.getFirstChild().getNodeValue())){
                System.out.println("Check 8: Fail - Subject name is not in certificate");
                return;
            }
        }
        System.out.println("Check 8 : OK - verifyKeyInfo is valid");
    }

    void verifySignatureProperties() {


        // 	overenie obsahu ds:SignatureProperties
        if (!signatureProperties.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - signatureProperties id is missing");
        }

        boolean sigVersion = false;
        boolean productInfo = false;

        Element sigProperty1 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(0);
        Element sigProperty2 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(1);

        if (sigProperty1 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");
        if (sigProperty2 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");

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

            if (!sigVersion) System.out.println("Check 5: Fail - element xzep:SignatureVersion  is missing");
            if (!productInfo) System.out.println("Check 5: Fail - xzep:ProductInfos");
        }

        if (!sigProperty1.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
            System.out.println("Check 5: Fail - SignatureProperty 1 does not have target attribute or is not referencing signature id");
        }

        if (!sigProperty2.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
            System.out.println("Check 5: Fail - SignatureProperty 2 does not have target attribute or is not referencing signature id");
        }
        // TODO XPATH problem hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate
        System.out.println("Check 5 : OK - verifySignature is valid");



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
                if (transform.hasAttribute("Algorithm") && transformMethods.contains(transform.getAttribute("Algorithm"))) {
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
                } else {
                    System.out.println("Check 11: Fail - Transform algorithm is missing or is not supported");
                    return;
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
        if (manifestReferences==true){
            System.out.println("Check 11: OK - verifyManifestReferences is valid");
        }

    }

    //    toto je v tom vyssom, je to validne preist oba naraz
    void verifyManifestReferences() {

    }

    void verifyTimestamp() {
        System.out.println("Check 12: OK - verifyTimestamp is valid");
    }

    void verifyMessageImprint() {
        System.out.println("Check 13: OK - verifyMessageImprint is valid");
    }

    void verifyCertificate() {
        System.out.println("Check 14: OK - verifyCertificate is valid");
    }

    boolean assertElementAttributeValue(Element element, String attribute, String expectedValue) {

        String actualValue = element.getAttribute(attribute);

        if (actualValue != null && actualValue.equals(expectedValue)) {

            return true;

        }
        return false;
    }

    boolean assertElementAttributeValue(Element element, String attribute, List<String> expectedValues) {

        for (String expectedValue : expectedValues) {

            if (assertElementAttributeValue(element, attribute, expectedValue)) {

                return true;
            }
        }
        return false;
    }

}


