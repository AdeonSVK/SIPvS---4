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

import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import java.io.ByteArrayInputStream;

import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Store;

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
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRLEntry;
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
        // TODO Kontrola 3 - kontrola obsahu ds:Transforms a ds:DigestMethod;



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

        // TODO XPATH problem overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type

        // 	overenie obsahu ds:KeyInfo:
        if (!keyInfo.hasAttribute("Id")) {
            System.out.println("Check 5: Fail - keyInfo id attribute is missing");
        }

        Element x509Data = (Element) keyInfo.getElementsByTagName("ds:X509Data").item(0);
        Element x509Certificate = (Element) keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
        Element x509IssuerSerial = (Element) keyInfo.getElementsByTagName("ds:X509IssuerSerial").item(0);
        Element x509SubjectName = (Element) keyInfo.getElementsByTagName("ds:X509SubjectName").item(0);

        if (x509Data == null) {
            System.out.println("Check 5: Fail - element x509Data is missing");
        }
        if (x509Certificate == null) {
            System.out.println("Check 5: Fail - element x509Certificate is missing");
        }
        if (x509IssuerSerial == null) {
            System.out.println("Check 5: Fail - element x509IssuerSerial is missing");
        }
        if (x509SubjectName == null) {
            System.out.println("Check 5: Fail - element x509SubjectName is missing");
        }

        // TODO XPATH problem hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate


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

        System.out.println("Check 5 : OK - verifySignature is valid");

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
        System.out.println("Check 7 : OK - verifySignedInfoReferences is valid");
    }

    void verifyKeyInfo() {
        System.out.println("Check 8 : OK - verifyKeyInfo is valid");
    }

    void verifySignatureProperties() {
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

//                        TransformerFactory transformerFactory = TransformerFactory.newInstance();
//                        Transformer transformer = transformerFactory.newTransformer();
//                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                        StreamResult result=new StreamResult(baos);
//                        DOMSource source = new DOMSource(referencedObject);
//                        transformer.transform( source, result);
//                        objectElementBytes = baos.toByteArray();
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

        X509CertificateHolder signer = null;

        Store certHolders = token.getCertificates();
        ArrayList<X509CertificateHolder> certList = new ArrayList<>(certHolders.getMatches(null));

        BigInteger serialNumToken = token.getSID().getSerialNumber();
        X500Name issuerToken = token.getSID().getIssuer();

        for (X509CertificateHolder certHolder : certList) {
            if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)){
                signer = certHolder;
                break;
            }
        }

        if (signer == null){
            System.out.println("Check 12: Fail - Timestamp certificate not present in document.");
            return;
        }

        if (!signer.isValidOn(new Date())){
            System.out.println("Check 12: Fail - Timestamp signature certificate is not valid at the given time.");
            return;
        }

        if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
            System.out.println("Check 12: Fail - Latest signature timestamp certificate is not valid against the latest valid CRL.");
            return;
        }
        System.out.println("Check 12: OK - verifyTimestamp is valid");
    }

    void verifyMessageImprint() {

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

        if (signatureValueNode == null){
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

        if (!Arrays.equals(messageImprint, messageDigest.digest(signatureValue))){
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

        if (certificateNode == null){
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

        if (timestamp == null){
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

        if (crlData == null){
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

            while ( (n = is.read(byteChunk)) > 0 ) {
                baos.write(byteChunk, 0, n);
            }
        }
        catch (IOException e) {
            System.err.printf ("Failed while reading bytes from %s: %s", urlHandler.toExternalForm(), e.getMessage());
            return null;
        }
        finally {
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

    boolean assertElementAttributeValue(Element element, String attribute, List<String> expectedValues) {

        for (String expectedValue : expectedValues) {

            if (assertElementAttributeValue(element, attribute, expectedValue)) {

                return true;
            }
        }
        return false;
    }

}


