/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fbdl.crypto.fbdlcrypto.nacl;

import java.util.Arrays;
import java.util.Base64;
import org.abstractj.kalium.crypto.Box;
import org.abstractj.kalium.encoders.Encoder;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import org.abstractj.kalium.encoders.Raw;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

/**
 *
 * @author fbdl
 */
public class FbdlKalium {
    
    public static void main(String[] args) {
        System.out.println("salt!");
        
        Encoder encoder = new Raw();
        String plaintext = "This_data_is_secret";
        
        System.out.println(encoder.encode(plaintext.getBytes()));
        
        Box box = new Box(new PublicKey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), new PrivateKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        byte[] nonce = HEX.decode("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"); //maaring dahil dito kaya pareparehas eh
        System.out.println(nonce.length);
        byte[] message = plaintext.getBytes();
        byte[] ciphertext = HEX.decode("f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
            "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
            "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
            "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
            "7973f622a43d14a6599b1f654cb45a74e355a5");
        
        //calls crypto_box_curve25519xsalsa20poly1305_afternm which is a Public-key authenticated encryption crypto_box alternative
        //after nm means https://github.com/jedisct1/libsodium/issues/426
        //https://cryptojedi.org/papers/coolnacl-20111201.pdf "C NaCl allows crypto_box to be split into two steps, crypto_box_beforenm and crypto_box_afternm""
        byte[] result = box.encrypt(nonce, message); // based on https://github.com/abstractj/kalium/blob/master/src/test/java/org/abstractj/kalium/crypto/BoxTest.java
        String s = Base64.getEncoder().encodeToString(result);
        System.out.println(s);
        System.out.println(Arrays.equals(result, ciphertext));
        
        Box pandora = new Box(new PublicKey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), new PrivateKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        byte[] secret = pandora.decrypt(nonce, result);
        
        System.out.println("decrypted: " + new String(secret));
        
        
    }
    
}
