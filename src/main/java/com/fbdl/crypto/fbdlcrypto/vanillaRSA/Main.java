/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fbdl.crypto.fbdlcrypto.vanillaRSA;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import sun.misc.BASE64Decoder;

/**
 *
 * @author fbdl
 */
public class Main {
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("fbdl");
        
        ///////////////////// can be replaced by BouncyCastle READPEM
        //load files
        File privateFile = new File("/home/fbdl/Desktop/VBXShared/keys/private_key.pem");
        FileInputStream privateFis = new FileInputStream(privateFile);
        DataInputStream privateDis = new DataInputStream(privateFis);
        byte[] privateKeyBytes = new byte[(int) privateFile.length()];
        privateDis.readFully(privateKeyBytes);
        privateDis.close();
        
        File publicFile = new File("/home/fbdl/Desktop/VBXShared/keys/public_key.pem");
        FileInputStream publicFis = new FileInputStream(publicFile);
        DataInputStream publicDis = new DataInputStream(publicFis);
        byte[] publicKeyBytes = new byte[(int) publicFile.length()];
        publicDis.readFully(publicKeyBytes);
        publicDis.close();
        
        //strip off the string
        String privFull = new String(privateKeyBytes);
        String privateKeyPEM = privFull.replace("-----BEGIN PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        
        String pubFull = new String(publicKeyBytes);
        String publicKeyPEM = pubFull.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        //clear off old bytes after here.
        
       
        //TODO: replace with vanilla base64 decoder or bouncycastle
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKeyPEM)));
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(publicKeyPEM)));
        ///////////////////////////////
        
        
        System.out.println("Encrypting: Hello World");
        String plainText = "Hello World";
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        cipher.update(plainText.getBytes("UTF-8"));
        byte[] result = cipher.doFinal();
        
        String encryptResult = new String(result, "UTF-8");
        System.out.println("encrypted string: " + encryptResult);
        
        
        System.out.println("Decrypting...");
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        //yung byte or string ba dapat?
        decryptCipher.update(result);
        byte[] decrypted = decryptCipher.doFinal();
        
        System.out.println("word is: " + new String(decrypted, "UTF-8"));
        
        
    }
    
}
