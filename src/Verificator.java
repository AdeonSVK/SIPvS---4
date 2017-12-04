import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import java.io.File;

class Verificator {
    public static void main(String[] args) {
        try {

            File fXmlFile = new File("documents/08XadesT.xml");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(fXmlFile);

            doc.getDocumentElement().normalize();
            Element root = doc.getDocumentElement();

            // Overenie dátovej obálky:
            // kontrola 1
            if(root.hasAttribute("xmlns:xzep") && (root.getAttribute("xmlns:xzep").equals("http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0"))){
            }
            else {
                System.out.println("Check 1: Fail - xmlns:xzep is missing or is not valid");
            }
            if(root.hasAttribute("xmlns:ds") && (root.getAttribute("xmlns:ds").equals("http://www.w3.org/2000/09/xmldsig#"))){
            }
            else {
                System.out.println("Check 1: Fail - xmlns:ds is missing or is not valid");
            }

            // nacitanie relevantnych elementov
            Element signature = (Element)root.getElementsByTagName("ds:Signature").item(0);
            Element signedInfo = (Element)signature.getElementsByTagName("ds:SignedInfo").item(0);
            Element signatureValue = (Element)signature.getElementsByTagName("ds:SignatureValue").item(0);
            Element keyInfo = (Element)signature.getElementsByTagName("ds:KeyInfo").item(0);
            Element signatureProperties = (Element)signature.getElementsByTagName("ds:SignatureProperties").item(0);


            // Overenie XML Signature:
            // kontrola 2
            Element signatureMethod = (Element)signature.getElementsByTagName("ds:SignatureMethod").item(0);
            Element canonicalizationMethod = (Element)signature.getElementsByTagName("ds:CanonicalizationMethod").item(0);

            if(canonicalizationMethod.hasAttribute("Algorithm") && canonicalizationMethod.getAttribute("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")){
            }
            else {
                System.out.println("Check 2: Fail - canonicalization algorithm is missing or is not supported");
            }

            if(signatureMethod.hasAttribute("Algorithm") && signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#dsa-sha1")
                    || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#rsa-sha1")
                    || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                    || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
                    || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")){
            }
            else {
                System.out.println("Check 2: Fail - signature algorithm is missing or is not supported");
            }



            // TODO Kontrola 3 - kontrola obsahu ds:Transforms a ds:DigestMethod;
            // TODO Kontrola 4 - Core validation

            // kontrola 5

            // 	ds:Signature
            if(!signature.hasAttribute("Id")){
                System.out.println("Check 5: Fail - signature id attribute is missing");
            }
            if(!signature.hasAttribute("xmlns:ds")){
                System.out.println("Check 5: Fail - signature xmlns:ds attribute is missing");
            }
            // 	ds:SignatureValue
            if(!signatureValue.hasAttribute("Id")){
                System.out.println("Check 5: Fail - signatureValue id attribute is missing");
            }

            // TODO	overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type

            // 	overenie obsahu ds:KeyInfo:
            if(!keyInfo.hasAttribute("Id")){
                System.out.println("Check 5: Fail - keyInfo id attribute is missing");
            }

            Element x509Data = (Element)keyInfo.getElementsByTagName("ds:X509Data").item(0);
            Element x509Certificate = (Element)keyInfo.getElementsByTagName("ds:X509Certificate").item(0);
            Element x509IssuerSerial = (Element)keyInfo.getElementsByTagName("ds:X509IssuerSerial").item(0);
            Element x509SubjectName = (Element)keyInfo.getElementsByTagName("ds:X509SubjectName").item(0);

            if(x509Data == null){
                System.out.println("Check 5: Fail - element x509Data is missing");
            }
            if(x509Certificate == null){
                System.out.println("Check 5: Fail - element x509Certificate is missing");
            }
            if(x509IssuerSerial == null){
                System.out.println("Check 5: Fail - element x509IssuerSerial is missing");
            }
            if(x509SubjectName == null){
                System.out.println("Check 5: Fail - element x509SubjectName is missing");
            }

            // TODO hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate


            // 	overenie obsahu ds:SignatureProperties
            if(!signatureProperties.hasAttribute("Id")){
                System.out.println("Check 5: Fail - signatureProperties id is missing");
            }

            boolean sigVersion = false;
            boolean productInfo = false;

            Element sigProperty1 = (Element)signatureProperties.getElementsByTagName("ds:SignatureProperty").item(0);
            Element sigProperty2 = (Element)signatureProperties.getElementsByTagName("ds:SignatureProperty").item(1);

            if(sigProperty1 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");
            if(sigProperty2 == null) System.out.println("Check 5: Fail - element signatureProperty is missing");

            if(sigProperty1 != null && sigProperty2 != null) {
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

            if(!sigProperty1.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))){
                System.out.println("Check 5: Fail - SignatureProperty 1 does not have target attribute or is not referencing signature id");
            }

            if(!sigProperty2.hasAttribute("Target") || !sigProperty1.getAttribute("Target").substring(1).equals(signature.getAttribute("Id"))){
                System.out.println("Check 5: Fail - SignatureProperty 2 does not have target attribute or is not referencing signature id");
            }

            // 	overenie ds:Manifest elementov

            NodeList manifests = signature.getElementsByTagName("ds:Manifest");

            for(int i=0; i<manifests.getLength();i++){
                Element manifest = (Element) manifests.item(i);
                if(!manifest.hasAttribute("Id")){
                    System.out.println("Check 5: Fail - manifest id attribute is missing");
                }

                Element transform = (Element)manifest.getElementsByTagName("ds:Transform").item(0);
                if(transform.hasAttribute("Algorithm") && transform.getAttribute("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                        || signatureMethod.getAttribute("Algorithm").equals("http://www.w3.org/2000/09/xmldsig#base64")){
                }
                else {
                    System.out.println("Check 5: Fail - Transform algorithm is missing or is not supported");
                }

                Element digest = (Element)manifest.getElementsByTagName("ds:DigestMethod").item(0);

                if(digest.hasAttribute("Algorithm") && digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig#sha1")
                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha224")
                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha256")
                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmldsig-more#sha384")
                        || digest.getAttribute("Algorithm").equals("http://www.w3.org/2001/04/xmlenc#sha512")){
                }
                else {
                    System.out.println("Check 5: Fail - Digest algorithm is missing or is not supported");
                }

                // TODO overenie hodnoty Type atribútu voči profilu XAdES_ZEP

                NodeList references = manifest.getElementsByTagName("ds:Reference");

                if(references.getLength() != 1){
                    System.out.println("Check 5: Fail - incorrect number of references in manifest element");
                }

            }

            // TODO  	overenie referencií v elementoch ds:Manifest:


            // TODO Overenie časovej pečiatky:
            // TODO Overenie platnosti podpisového certifikátu:


            System.out.println("Verification completed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}