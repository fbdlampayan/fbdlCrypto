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
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ThreadLocalRandom;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author fbdl
 */
public class Main {
    
    public static void main(String[] args) throws PEMException, IOException, CRMFException, CMPException, OperatorCreationException, CertificateException {
        System.out.println("cmp-client!");
        
        //loading public and private
        final Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", bcProvider);
        
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
        Integer x = new Integer(ThreadLocalRandom.current().nextInt(4, 100));
        System.out.println("request trid: " + x);
        pbuilder.setTransactionID(x.toString().getBytes());
        
        //KeyID: key id in CA
        pbuilder.setSenderKID("54980".getBytes());
        
        CertReqMessages msgs = new CertReqMessages(message.toASN1Structure());
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
        
        pbuilder.setBody(pkiBody);
        
        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        
        AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1.2"));
        
        jcePkmacCalc.setup(digAlg, macAlg);
        
        PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
        MacCalculator macCalculator = macbuilder.build("this_is_very_secret".toCharArray()); //PSK of keyid in CA
        
//        ContentSigner msgSigner = new JcaContentSignerBuilder("sha1WithRSAEncryption").setProvider("BC").build(privateKey);
        ProtectedPKIMessage m = pbuilder.build(macCalculator);
        
        String url = "http://10.0.0.52:8888/pkix/"; //k8s service
        
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
            System.out.println("response body: " + entity1.getContentLength());
//            System.out.println(EntityUtils.toString(entity1));
            
            
//            PKIMessage r = PKIMessage.getInstance(ASN1Primitive.fromByteArray(IOUtils.toByteArray(entity1.getContent())));
//            System.out.println("R: " + new String(r.getBody().getEncoded()));

            ASN1InputStream asn1InputStream = new ASN1InputStream(entity1.getContent());
            final PKIMessage respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            
            //header
            final PKIHeader header = respObject.getHeader();
            System.out.println("header: " + header.getTransactionID());
            
            //signer (the CA)
            final X500Name name = X500Name.getInstance(header.getSender().getName());
            System.out.println("CA: " + name.toString());
            
            //body
            final PKIBody body = respObject.getBody();
            final CertRepMessage c = (CertRepMessage) body.getContent();
            final CertResponse resp = c.getResponse()[0];
            final CertifiedKeyPair kp = resp.getCertifiedKeyPair();
            final CertOrEncCert cc = kp.getCertOrEncCert();
            final CMPCertificate cmpcert = cc.getCertificate();
            final byte encoded[] = cmpcert.getEncoded();
            final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
            
            System.out.println("cert: " + new String(cert.getEncoded()).toLowerCase());
            
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.close();
            System.out.println("content: " + writer.toString());
            
            EntityUtils.consume(entity1);
        } finally {
            response.close();
        }
    }
    
}
