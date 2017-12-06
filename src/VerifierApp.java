import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

class VerifierApp {

    static Document openFile(String filename) {
        File fXmlFile = new File(filename);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        ;
        Document doc = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(fXmlFile);
        } catch (Exception e) {
            System.out.println("Exception " + e);
        }
        return doc;
    }

    static void runTests(Document doc) {
        SignatureVerifier verifier = new SignatureVerifier(doc);

        verifier.verifyRootElement();
        verifier.verifySignatureAndCanonicalizationMethods();
        verifier.verifyTransformsAndDigestMethods();
        verifier.verifyCore();
        verifier.verifySignature();
        verifier.verifySignatureValue();
        verifier.verifySignedInfoReferences();
        verifier.verifyKeyInfo();
        verifier.verifySignatureProperties();
        verifier.verifyManifest();
        verifier.verifyManifestReferences();
        verifier.verifyTimestamp();
        verifier.verifyMessageImprint();
        verifier.verifyCertificate();

        System.out.println("Verification completed.");
    }


    public static void main(String[] args) {
        Document doc = openFile("documents/XadesT.xml");
        runTests(doc);
    }
}