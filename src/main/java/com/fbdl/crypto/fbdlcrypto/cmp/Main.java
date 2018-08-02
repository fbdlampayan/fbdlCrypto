/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fbdl.crypto.fbdlcrypto.cmp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author fbdl
 */
public class Main {
    
    public static void main(String[] args) throws PEMException, IOException, CRMFException, CMPException, OperatorCreationException {
        System.out.println("cmp-client!");
        
        //loading public and private
        Security.addProvider(new BouncyCastleProvider());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        
        PEMParser privateKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/private_key.pem"))));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) privateKeyPemParser.readObject();
        
        PEMParser publicKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/public_key.pem"))));
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) publicKeyPemParser.readObject();
        
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
        PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
        
        
        //target CA and Client's CN
        X509NameEntryConverter dnConverter = new X509DefaultEntryConverter();
        X500Name issuerDN = X500Name.getInstance(new X509Name("C=FI, ST=Finland, O=Nokia, CN=Nokia Digital Automation Sub CA").toASN1Object());
        X500Name subjectDN = X500Name.getInstance(new X509Name("C=FI,CN=Mashiro", dnConverter).toASN1Object());
        
        
        CertificateRequestMessageBuilder messageBuilder = new CertificateRequestMessageBuilder(BigInteger.ZERO); //value is certReqId=0 (in the guide it was transactionId?)
        
        messageBuilder.setSerialNumber(BigInteger.ZERO);
        messageBuilder.setSubject(subjectDN);
        
        
        final byte[] bytes = publicKey.getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
        
        messageBuilder.setPublicKey(keyInfo);
        
        GeneralName sender = new GeneralName(subjectDN);
        messageBuilder.setAuthInfoSender(sender);
        
        //RAVerified POP
//        messageBuilder.setProofOfPossessionRaVerified();

        //DigitalSignature POP
        ContentSigner msgSigner = new JcaContentSignerBuilder("sha1WithRSAEncryption").setProvider("BC").build(privateKey);
        messageBuilder.setProofOfPossessionSigningKeySigner(msgSigner);
        
        CertificateRequestMessage message = messageBuilder.build();
        
        GeneralName recipient = new GeneralName(issuerDN);
        
        ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(sender, recipient);
//        pbuilder.setMessageTime(new Date());
        
        //senderNonce
        byte[] senderNonce = "1".getBytes();
        pbuilder.setSenderNonce(senderNonce);
        
        //transactionId
        pbuilder.setTransactionID("1".getBytes());
        
        //KeyID
        pbuilder.setSenderKID("keyId".getBytes());
        
        CertReqMessages msgs = new CertReqMessages(message.toASN1Structure());
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
        
        pbuilder.setBody(pkiBody);
        
        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        
        AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
        
        jcePkmacCalc.setup(digAlg, macAlg);
        
        PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
        MacCalculator macCalculator = macbuilder.build("54980:this_is_very_secret".toCharArray());
        
//        ContentSigner msgSigner = new JcaContentSignerBuilder("sha1WithRSAEncryption").setProvider("BC").build(privateKey);
        ProtectedPKIMessage m = pbuilder.build(macCalculator);
        
        String url = "http://172.17.0.6:8888/pkix/"; //pod: insta-1011466520-jp8zq
        
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(url);
        
        post.setHeader("Pragma", "no-cache");
        post.setHeader("Content-Type", "application/pkixcmp");
        
        HttpEntity entityBody = new ByteArrayEntity(m.toASN1Structure().getEncoded());
        post.setEntity(entityBody);
        
        
        CloseableHttpResponse response = httpClient.execute(post);
        try{
            System.out.println("status line" + response.getStatusLine());
            HttpEntity entity1 = response.getEntity();
            
            System.out.println(response.getAllHeaders().length);
            System.out.println("response body:");
            System.out.println(EntityUtils.toString(entity1));
            
            EntityUtils.consume(entity1);
        } finally {
            response.close();
        }
    }
    
}
