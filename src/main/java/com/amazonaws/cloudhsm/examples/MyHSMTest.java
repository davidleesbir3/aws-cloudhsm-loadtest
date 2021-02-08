package com.amazonaws.cloudhsm.examples;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.parameter.CaviumECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.UUID;

/**
 *
 */
public class MyHSMTest {
    public static void main(String[] args) throws Exception, CFM2Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Retrieve the private key
        int keyHandle = 789730;
        CaviumKey hsmWrappingKey = retrieveWrappingKeyFromHSM(keyHandle);
        System.out.printf("\n\nRetrieved AES wrapping key (%d) from HSM: %s\n", keyHandle, hsmWrappingKey);

        // Creates key pair 1
        String alias1 = UUID.randomUUID().toString();
        KeyPair myKeyPair1 = generateKeyPair(alias1);

        byte[] wrappedKeyMaterial1 = wrapSigningKey(myKeyPair1, hsmWrappingKey);
        PrivateKey unwrappedPrivateKey1 = unwrapSigningKey(wrappedKeyMaterial1, hsmWrappingKey);
        System.out.printf("Generated key pair %s, wrapped and unwrapped it.\n", alias1);

        // Creates key pair 2
        String alias2 = UUID.randomUUID().toString();
        KeyPair myKeyPair2 = generateKeyPair(alias2);

        byte[] wrappedKeyMaterial2 = wrapSigningKey(myKeyPair2, hsmWrappingKey);
        PrivateKey unwrappedPrivateKey2 = unwrapSigningKey(wrappedKeyMaterial2, hsmWrappingKey);
        System.out.printf("Generated key pair %s, wrapped and unwrapped it.\n", alias2);

        // This step introduced a lot more CN_WRAP_KEY2 entries and CN_NIST_AES_WRAP_UNWRAP2 in CloudWatch logs
        // assert (Arrays.equals(myKeyPair.getPrivate().getEncoded(), unwrappedPrivateKey.getEncoded()));
        // System.out.printf("Verified key when using the HSM to wrap and unwrap with AESWrap/ECB/PKCS5Padding:\n %s\n",
        //         Base64.getEncoder().encodeToString(unwrappedPrivateKey.getEncoded()));


        byte[] payload = getSmallPayload();
        Signature signature = Signature.getInstance("SHA256withECDSA", "Cavium");
        signature.initSign(unwrappedPrivateKey1);
        signature.update(payload);
        byte[] signedPayload = signature.sign();
        System.out.printf("Signed the payload of %d bytes with unwrapped key.\n%s\n", payload.length, Base64.getEncoder().encodeToString(signedPayload));

        Util.deleteKey((CaviumKey) myKeyPair1.getPrivate());
        Util.deleteKey((CaviumKey) myKeyPair1.getPublic());
        Util.deleteKey((CaviumKey) unwrappedPrivateKey1);
        Util.deleteKey((CaviumKey) myKeyPair2.getPrivate());
        Util.deleteKey((CaviumKey) myKeyPair2.getPublic());
        Util.deleteKey((CaviumKey) unwrappedPrivateKey2);
    }

    public static KeyPair generateKeyPair(String keyLabel) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "Cavium");
            keyPairGen.initialize(
                    new CaviumECGenParameterSpec(
                            "secp256r1",
                            keyLabel + ":public",
                            keyLabel + ":private",
                            true,
                            false));
            KeyPair keyPair = keyPairGen.generateKeyPair();
            return keyPair;

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                System.out.println("Detected invalid credentials");
            } else if (CFM2Exception.isClientDisconnectError(e)) {
                System.out.println("Detected daemon network failure");
            }

            e.printStackTrace();
        }

        return null;
    }

    public static byte[] wrapSigningKey (KeyPair keyPair, Key hsmWrappingKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        // "AESWrap/ECB/PKCS5Padding" does not work, probably not supported in JCE 3.0
        // Cipher cipher = Cipher.getInstance("AESWrap/ECB/PKCS5Padding", "Cavium");
        Cipher cipher = Cipher.getInstance("AES", "Cavium");
        cipher.init(Cipher.WRAP_MODE, hsmWrappingKey);

        // Wrap the extractable key using the wrappingKey
        return cipher.wrap(keyPair.getPrivate());
    }

    public static PrivateKey unwrapSigningKey (byte[] wrappedKeyMaterial, Key hsmWrappingKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException{

        Cipher cipher = Cipher.getInstance("AES", "Cavium");
        // Unwrap using the HSM
        cipher.init(Cipher.UNWRAP_MODE, hsmWrappingKey);
        return (PrivateKey) cipher.unwrap(wrappedKeyMaterial, "EC", Cipher.PRIVATE_KEY);
    }

    public static CaviumAESKey retrieveWrappingKeyFromHSM(int handle) throws Exception{
        byte[] keyAttribute = Util.getKeyAttributes(handle);
        CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
        CaviumAESKey wrappingKey = new CaviumAESKey(handle, cka);
        return wrappingKey;
    }


    private static byte[] getPayload() throws IOException {
        // String message = "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +;
        // return message.getBytes();

        String filePath = "/home/ubuntu/aws-cloudhsm-jce-examples/dummydata.xml";

        // file to byte[], Path
        byte[] bytes = Files.readAllBytes(Paths.get(filePath));

        // file to byte[], File -> Path
        File file = new File(filePath);
        return Files.readAllBytes(file.toPath());
    }

    private static byte[] getSmallPayload() throws IOException {
        String message = "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering)." +
                "Both WireTransaction and FilteredTransaction inherit from TraversableTransaction, so access to the transaction components is exactly the same. Note that unlike WireTransaction, FilteredTransaction only holds data that we wanted to reveal (after filtering).";

        return message.getBytes();
    }
}