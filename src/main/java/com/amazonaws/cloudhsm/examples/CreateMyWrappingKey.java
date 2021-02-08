package com.amazonaws.cloudhsm.examples;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.Key;
import java.security.Security;

/**
 *
 */
public class CreateMyWrappingKey {
    public static void main(String[] args) throws Exception, CFM2Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        Key wrappingKey = createAESWrappingKey();
        System.out.println("Created wrapping key: " + wrappingKey.toString());
    }

    // Creates a non-extractable, persistent AES wrapping key
    public static Key createAESWrappingKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");
        keyGen.init(new CaviumAESKeyGenParameterSpec(256, "master", false, true));
        SecretKey aesKey = keyGen.generateKey();
        return aesKey;
    }
}