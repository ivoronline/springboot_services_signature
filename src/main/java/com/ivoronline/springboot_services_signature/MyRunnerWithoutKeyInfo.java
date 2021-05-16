package com.ivoronline.springboot_services_signature;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;

@Component
public class MyRunnerWithoutKeyInfo implements CommandLineRunner {

  //KEY STORE
  String keyStore  = "src/main/resources/ClientKeyStore.jks";
  String keyAlias  = "clientkeys1";
  String password  = "mypassword";

  //XML DOCUMENTS
  String xmlInput  = "src/main/resources/Person.xml";
  String xmlOutput = "src/main/resources/PersonSignedWithoutKeyInfo.xml";

  @Override
  public void run(String... args) throws Exception {

    //LOG
    System.out.println("MyRunner");

    //CREATE XML SIGNATURE FACTORY
    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

    //GET KEY STORE, PRIVATE & PUBLIC KEY (CERTIFICATE)
    KeyStore                    keyStore    = KeyStore.getInstance("JKS");
                                keyStore.load(new FileInputStream(this.keyStore), password.toCharArray());
    KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password.toCharArray());
    KeyStore.PrivateKeyEntry    keyPair     = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, keyPassword);
    X509Certificate             certificate = (X509Certificate) keyPair.getCertificate();

    //LOAD INPUT XML DOCUMENT
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
                           documentFactory.setNamespaceAware(true);
    Document               inputDocument   = documentFactory.newDocumentBuilder().parse(new FileInputStream(xmlInput));

    // Create a DOMSignContext and specify the RSA PrivateKey and location of the resulting XMLSignature's parent element.
    DOMSignContext domSignContext = new DOMSignContext(keyPair.getPrivateKey(), inputDocument.getDocumentElement());

    //CREATE REFERENCE
    Reference reference = factory.newReference(
      "",
      factory.newDigestMethod(DigestMethod.SHA1, null),
      Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),null, null
    );

    //SPECIFY SIGNATURE TYPE
    SignedInfo signedInfo = factory.newSignedInfo(
      factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec) null),
      factory.newSignatureMethod       (SignatureMethod.RSA_SHA1, null),Collections.singletonList(reference)
    );

    //SIGN DOCUMENT
    XMLSignature signature = factory.newXMLSignature(signedInfo, null);
                 signature.sign(domSignContext);

    //CREATE OUTPUT XML DOCUMENT
    OutputStream       outputStream       = new FileOutputStream(xmlOutput);
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer        transformer        = transformerFactory.newTransformer();
                       transformer.transform(new DOMSource(inputDocument), new StreamResult(outputStream));

  }

}