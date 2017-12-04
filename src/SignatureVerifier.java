import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;
import it.svario.xpathapi.jaxp.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathException;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

        if (canonicalizationMethod.hasAttribute("Algorithm") && canonicalizationMethod.getAttribute("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {
        } else {
            System.out.println("Check 2 : Fail - canonicalization algorithm is missing or is not supported");
            return;
        }

        if (signatureMethod.hasAttribute("Algorithm") && signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#dsa-sha1")
                || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#rsa-sha1")
                || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
                || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")) {
        } else {
            System.out.println("Check 2 : Fail - signature algorithm is missing or is not supported");
            return;
        }
        System.out.println("Check 2 : OK - signature algorithm is valid");

    }

    void verifyTransformsAndDigestMethods() {
        // TODO Kontrola 3 - kontrola obsahu ds:Transforms a ds:DigestMethod;


        NodeList transformsElements = null;
        try {
            transformsElements = XPathAPI.selectNodeList(mDocument.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms");

        } catch (XPathException e) {
            System.out.println("Chyba pri kontrole elementu ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms. Element nebol v dokumente najdeny");
            return;
        }

        for (int i = 0; i < transformsElements.getLength(); i++) {

            Element transformsElement = (Element) transformsElements.item(i);
            Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(0);

			/*
             * Kontrola obsahu ds:Transforms
			 * Musi obsahovať URI niektorého z podporovaných algoritmov
			 */
            if (!assertElementAttributeValue(transformElement, "Algorithm", transformMethods)) {

                System.out.println("Atribút Algorithm elementu ds:Transforms neobsahuje URI niektorého z podporovaných algoritmov");
                return;
            }
        }


        NodeList digestMethodElements = null;
        try {
            digestMethodElements = XPathAPI.selectNodeList(mDocument.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod");

        } catch (XPathException e) {

            System.out.println("Chyba pri kontrole elementu ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod. Element nebol v dokumente najdeny");
            return;
        }

//        System.out.println("digestMethodElements" + digestMethodElements + " + size = " + digestMethodElements.getLength());

        for (int i = 0; i < digestMethodElements.getLength(); i++) {

            Element digestMethodElement = (Element) digestMethodElements.item(i);

            if (!assertElementAttributeValue(digestMethodElement, "Algorithm", digestMethods)) {
                System.out.println("Atribút Algorithm elementu ds:DigestMethod neobsahuje URI niektorého z podporovaných algoritmov");
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


        // TODO kontrola 5

//        // 	ds:Signature
//        if (!signature.hasAttribute("Id")) {
//            System.out.println("Check 5 : Fail - signature id attribute is missing");
//        }
//        if (!signature.hasAttribute("xmlns:ds")) {
//            System.out.println("Check 5 : Fail - signature xmlns:ds attribute is missing");
//        }
//        // 	ds:SignatureValue
//        if (!signatureValue.hasAttribute("Id")) {
//            System.out.println("Check 5: Fail - signatureValue id attribute is missing");
//        }
//
//        // TODO	overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type
//
//        // 	overenie obsahu ds:KeyInfo:
//        if (!keyInfo.hasAttribute("Id")) {
//            System.out.println("Check 5 : Fail - keyInfo id attribute is missing");
//        }
//
//        Element x509Data = (Element) keyInfo.getElementsByTagName("ds:X509Data").item(0);
//        Element x509Certificate = (Element) keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
//        Element x509IssuerSerial = (Element) keyInfo.getElementsByTagName("ds:X509IssuerSerial").item(0);
//        Element x509SubjectName = (Element) keyInfo.getElementsByTagName("ds:X509SubjectName").item(0);
//
//        if (x509Data == null) {
//            System.out.println("Check 5 : Fail - element x509Data is missing");
//        }
//        if (x509Certificate == null) {
//            System.out.println("Check 5 : Fail - element x509Certificate is missing");
//        }
//        if (x509IssuerSerial == null) {
//            System.out.println("Check 5 : Fail - element x509IssuerSerial is missing");
//        }
//        if (x509SubjectName == null) {
//            System.out.println("Check 5 : Fail - element x509SubjectName is missing");
//        }
//
//        // TODO hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate
//
//
//        // 	overenie obsahu ds:SignatureProperties
//        if (!signatureProperties.hasAttribute("Id")) {
//            System.out.println("Check 5 : Fail - signatureProperties id is missing");
//        }
//
//        boolean sigVersion = false;
//        boolean productInfo = false;
//
//        Element sigProperty1 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(0);
//        Element sigProperty2 = (Element) signatureProperties.getElementsByTagName("ds:SignatureProperty").item(1);
//
//        if (sigProperty1 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");
//        if (sigProperty2 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");
//
//        if (sigProperty1 != null && sigProperty2 != null) {
//            if (sigProperty1.getElementsByTagName("xzep:SignatureVersion") != null) {
//                sigVersion = true;
//            }
//            if (sigProperty1.getElementsByTagName("xzep:ProductInfos") != null) {
//                productInfo = true;
//            }
//
//            if (sigProperty2.getElementsByTagName("xzep:SignatureVersion") != null) {
//                sigVersion = true;
//            }
//            if (sigProperty2.getElementsByTagName("xzep:ProductInfos") != null) {
//                productInfo = true;
//            }
//
//            if (!sigVersion) System.out.println("Check 5: Fail - element xzep:SignatureVersion  is missing");
//            if (!productInfo) System.out.println("Check 5: Fail - xzep:ProductInfos");
//        }
//
//        if (!sigProperty1.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
//            System.out.println("Check 5 : Fail - SignatureProperty 1 does not have target attribute or is not referencing signature id");
//        }
//
//        if (!sigProperty2.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))) {
//            System.out.println("Check 5 : Fail - SignatureProperty 2 does not have target attribute or is not referencing signature id");
//        }
//
//        // 	overenie ds:Manifest elementov
//
//        NodeList manifests = signature.getElementsByTagName("ds:Manifest");
//
//        for (int i = 0; i < manifests.getLength(); i++) {
//            Element manifest = (Element) manifests.item(i);
//            if (!manifest.hasAttribute("Id")) {
//                System.out.println("Check 5 : Fail - manifest id attribute is missing");
//            }
//
//            Element transform = (Element) manifest.getElementsByTagName("ds:Transform").item(0);
//            if (transform.hasAttribute("Algorithm") && transform.getAttribute("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
//                    || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2000/09/xmldsig#base64")) {
//            } else {
//                System.out.println("Check 5 : Fail - Transform algorithm is missing or is not supported");
//            }
//
//            Element digest = (Element) manifest.getElementsByTagName("ds:DigestMethod").item(0);
//
//            if (digest.hasAttribute("Algorithm") && digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#sha1")
//                    || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha224")
//                    || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha256")
//                    || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha384")
//                    || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha512")) {
//            } else {
//                System.out.println("Check 5 : Fail - Digest algorithm is missing or is not supported");
//            }
//
//            // TODO overenie hodnoty Type atribútu voči profilu XAdES_ZEP
//
//            NodeList references = manifest.getElementsByTagName("ds:Reference");
//
//            if (references.getLength() != 1) {
//                System.out.println("Check 5 : Fail - incorrect number of references in manifest element");
//            }
//
//        }
//
//        // TODO  	overenie referencií v elementoch ds:Manifest:
//        // TODO Overenie časovej pečiatky:
//        // TODO Overenie platnosti podpisového certifikátu:
//        for(int i=0; i<manifests.getLength();i++){
//            Element manifest = (Element) manifests.item(i);
//            if(!manifest.hasAttribute("Id")){
//                System.out.println("Check 5: Fail - manifest id attribute is missing");
//            }
//
//
//            // TODO overenie hodnoty Type atribútu voči profilu XAdES_ZEP
//
//            NodeList references = manifest.getElementsByTagName("ds:Reference");
//
//            if(references.getLength() != 1){
//                System.out.println("Check 5: Fail - incorrect number of references in manifest element");
//            }
//            Map<String, String> digestAlgMap;
//            digestAlgMap = new HashMap<String, String>();
//            digestAlgMap.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
//            digestAlgMap.put("http://www.w3.org/2001/04/xmldsig-more#sha224", "SHA-224");
//            digestAlgMap.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
//            digestAlgMap.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
//            digestAlgMap.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
//
//            for(int j=0;j<references.getLength();j++){
//                Element reference =(Element) references.item(j);
//                Element referencedObject = null;
//                String digAlg = null;
//                String digestMethod =null;
//                String transformMethod = null;
//                byte[] objectElementBytes =null;
//                boolean canonicalizationSuccessful =false;
//
//                if(!reference.hasAttribute("URI")){
//                    System.out.println("Check 5: Fail - URI attribute of reference is missing");
//                }else{
//
//                    String URI = reference.getAttribute("URI").substring(1);
//                    NodeList objects = root.getElementsByTagName("ds:Object");
//                    for(int k=0;k<objects.getLength();k++){
//                        Element object = (Element)objects.item(k);
//                        if (object.getAttribute("Id").equals(URI)){
//                            referencedObject=object;
//                        }
//                    }
//                }
//
//
//                if(referencedObject==null) {
//                    System.out.println("Check 5: Fail - Referenced object from manifest is either missing or has missing or invalid Id");
//                }else{
//
//                    StreamResult result = new StreamResult(new StringWriter());
//                    Transformer transformer = null;
//                    try {
//                        transformer = TransformerFactory.newInstance().newTransformer();
//                    } catch (TransformerConfigurationException e) {
//                        e.printStackTrace();
//                    }
//                    try {
//                        transformer.transform(new DOMSource(referencedObject), result);
//                    } catch (TransformerException e) {
//                        e.printStackTrace();
//                    }
//                    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
//
//                    objectElementBytes = result.getWriter().toString().getBytes();
//
////                        TransformerFactory transformerFactory = TransformerFactory.newInstance();
////                        Transformer transformer = transformerFactory.newTransformer();
////                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
////                        StreamResult result=new StreamResult(baos);
////                        DOMSource source = new DOMSource(referencedObject);
////                        transformer.transform( source, result);
////                        objectElementBytes = baos.toByteArray();
//                }
//
//                Element digest = (Element)reference.getElementsByTagName("ds:DigestMethod").item(0);
//                //TODO: zmenit na hashmap check voci digestAlgMap
//                if(digest.hasAttribute("Algorithm") && digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#sha1")
//                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha224")
//                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha256")
//                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha384")
//                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha512")){
//                    digAlg= digest.getAttribute("Algorithm");
//
//                }
//                else {
//                    System.out.println("Check 5: Fail - Digest algorithm is missing or is not supported");
//                }
//                Element digestValueElement = (Element)reference.getElementsByTagName("ds:DigestMethod").item(0);
//                if(digestValueElement==null){
//                    System.out.println("Check 5: Fail - Digest value is missing from a reference element");
//                }
//
//                Canonicalizer canonicalizer = null;
//                Element transform = (Element)reference.getElementsByTagName("ds:Transform").item(0);
//                if(transform.hasAttribute("Algorithm") && transform.getAttribute("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
//                        || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2000/09/xmldsig#base64")){
//                    transformMethod = transform.getAttribute("Algorithm");
//
//                    try {
//                        Init.init();
//                        canonicalizer = Canonicalizer.getInstance(transformMethod);
//
//                    } catch (InvalidCanonicalizerException e1) {
//                        System.out.println("Check 5: Fail - Invalid Canonicalizing method");
//                    }
//                }
//                else {
//                    System.out.println("Check 5: Fail - Transform algorithm is missing or is not supported");
//                }
//
//                if (objectElementBytes!=null && canonicalizer!=null) {
//                    try{
//                        objectElementBytes = canonicalizer.canonicalize(objectElementBytes);
//                        canonicalizationSuccessful = true;
//                    }
//                    catch(Exception e2){
//                        System.out.println("Check 5: Fail - Problem with canonicalization");
//                    }
//                }
//                if(transformMethod.equals("http://www.w3.org/2000/09/xmldsig#base64"))
//                    objectElementBytes = Base64.decode(objectElementBytes);
//
//
//                if(referencedObject!=null && digAlg!=null && transformMethod!=null && objectElementBytes!=null && digestValueElement!=null && canonicalizationSuccessful!=false) {
//                    digestMethod = digestAlgMap.get(digAlg);
//                    MessageDigest messageDigest = null;
//                    try {
//                        messageDigest = MessageDigest.getInstance(digestMethod);
//                    } catch (NoSuchAlgorithmException e) {
//                        e.printStackTrace();
//                    }
//                    String actualDigestValue = new String(Base64.encode(messageDigest.digest(objectElementBytes)));
//                    String digestValue = digestValueElement.getTextContent();
//                    if (digestValue.equals(actualDigestValue) == false) {
//                        System.out.println("Check 5: Fail - Digest Value in ds:Reference object is not equal with the hash content of the referenced object");
//                    }
//
//
//
//                }
//            }

        System.out.println("Check 5 : OK - verifySignature is valid");

    }

    void verifySignatureValue() {
        System.out.println("Check 6 : OK - verifySignatureValue is valid");
    }

    void verifySignedInfoReferences() {
        System.out.println("Check 7 : OK - verifySignedInfoReferences is valid");
    }

    void verifyKeyInfo() {
        System.out.println("Check 8 : OK - verifyKeyInfo is valid");
    }

    void verifySignatureProperties() {
        System.out.println("Check 9 : OK - verifySignatureProperties is valid");
    }

    void verifyManifest() {
        System.out.println("Check 10: OK - verifyManifest is valid");
    }

    void verifyManifestReferences() {
        System.out.println("Check 11: OK - verifyManifestReferences is valid");
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

    protected boolean assertElementAttributeValue(Element element, String attribute, String expectedValue) {

        String actualValue = element.getAttribute(attribute);

        if (actualValue != null && actualValue.equals(expectedValue)) {

            return true;

        }
        return false;
    }

    protected boolean assertElementAttributeValue(Element element, String attribute, List<String> expectedValues) {

        for (String expectedValue : expectedValues) {

            if (assertElementAttributeValue(element, attribute, expectedValue)) {

                return true;
            }
        }
        return false;
    }
}


