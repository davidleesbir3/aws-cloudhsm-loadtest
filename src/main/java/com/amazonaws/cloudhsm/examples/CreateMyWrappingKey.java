package com.amazonaws.cloudhsm.examples;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;

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

        String keyLabel = args.length > 0 ? args[0] : "master";
        Key wrappingKey = createAESWrappingKey(keyLabel);
        System.out.printf("Generated key label: %s, key handle: %d.\n", ((CaviumKey) wrappingKey).getLabel(), ((CaviumKey) wrappingKey).getHandle());
    }

    // Creates a non-extractable, persistent AES wrapping key
    public static Key createAESWrappingKey(String label) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");
        keyGen.init(new CaviumAESKeyGenParameterSpec(256, label, false, true));
        SecretKey aesKey = keyGen.generateKey();
        return aesKey;
    }
}