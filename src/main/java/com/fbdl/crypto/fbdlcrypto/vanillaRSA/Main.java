/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fbdl.crypto.fbdlcrypto.vanillaRSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 *
 * @author fbdl
 */
public class Main {
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("fbdl");
        
        //TODO: use JKS for the keys
        Security.addProvider(new BouncyCastleProvider());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        
        PEMParser privateKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/private_key.pem"))));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) privateKeyPemParser.readObject();
        
        
        PEMParser publicKeyPemParser = new PEMParser(new InputStreamReader(new FileInputStream(new File("/home/fbdl/Desktop/VBXShared/keys/public_key.pem"))));
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) publicKeyPemParser.readObject();
        
        
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
        PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
        
        
        
        //encrypt
        System.out.println("Encrypting: Hello World");
        String plainText = "Hello World";
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        cipher.update(plainText.getBytes());
        byte[] result = cipher.doFinal();
        
        String ciphertext = Base64.getEncoder().encodeToString(result);
        System.out.println("encrypted string: " + ciphertext);
        
        //decrypt
        System.out.println("Decrypting...");
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptCipher.update(Base64.getDecoder().decode(ciphertext));
        byte[] decrypted = decryptCipher.doFinal();
        
        System.out.println("word is: " + new String(decrypted));
        
        
    }
    
}
