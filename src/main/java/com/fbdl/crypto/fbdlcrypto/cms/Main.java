/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fbdl.crypto.fbdlcrypto.cms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OutputEncryptor;

/**
 *
 * @author fbdl
 */
public class Main {
    
    public static void main(String[] args) throws FileNotFoundException, IOException, CertificateException, CMSException {
        //TODO: use JKS for the keys
        Security.addProvider(new BouncyCastleProvider());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        
        PEMParser privateKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/private_key.pem"))));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) privateKeyPemParser.readObject();
        
        
        PEMParser publicKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/public_key.pem"))));
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) publicKeyPemParser.readObject();
        
        
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
        PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo); 
        
        byte[] encryptedData = null;
        
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream("/home/fbdl/Desktop/VBXShared/keys/certificate.cert");
        
        X509Certificate cert = (X509Certificate)factory.generateCertificate(is);
        
        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(cert);
        
        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
        
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        CMSTypedData msg = new CMSProcessableByteArray(data.getBytes());
        
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
        
        CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor);
        
        encryptedData = cmsEnvelopedData.getEncoded();
        
        String cipherText = Base64.getEncoder().encodeToString(encryptedData);
        System.out.println("encrypted string: " + cipherText);
        
        //decrypt
        byte[] decryptedData = null;
        
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
        
        Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
        
        KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
        
        JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
        
        String plainText = new String(recipientInfo.getContent(recipient));//Base64.getEncoder().encodeToString(recipientInfo.getContent(recipient));
        System.out.println("plaintext: " + plainText);
        
    }
    
}
