package sample;

import java.security.*;
import java.util.Base64;
import javax.crypto.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Demo {
    public static SecretKey secretKey;
    public static PrivateKey privateKey;
    public static PublicKey publicKey;
    public static PublicKey yashPublicKey;
    // Method to encrypt data using AES
    public static String getEncryptedData(String data) {
        byte[] byteData = data.getBytes();
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);  // AES key size
            secretKey = keyGenerator.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(byteData);
            String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
            return encodedEncryptedData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Method to decrypt data using AES
    public static String getDecryptedData(String encodedEncryptedData) {
        byte[] encryptedData = Base64.getDecoder().decode(encodedEncryptedData);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);
            String originalData = new String(decryptedData);
            return originalData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Method to sign data using RSA private key
     public static String signData(String data) {
    	try {
    	 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048); // RSA key size
         KeyPair keyPair = keyPairGenerator.generateKeyPair();
         privateKey = keyPair.getPrivate();
         publicKey = keyPair.getPublic();
        
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            byte[] signedData = signature.sign();
            return Base64.getEncoder().encodeToString(signedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    } 
    
   
  
	// Method to verify the signed data using RSA public key
    public static String verifySignature(String data, String signatureStr) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            return signature.verify(signatureBytes)+"";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false+"";
    }

    public static void main(String[] args) {
        try {
            // Generate RSA keys (Alice's keys)
            //KeyPair keyPair = generateKeyPair();
           
            
            String originalData = "Hello, Bob!";
         // Sign the original message using RSA private key
            String signedData = signData(originalData);
            System.out.println("Signed Data: " + signedData);
            
            // Encrypt the message using AES
            
            String encryptedData = getEncryptedData(originalData);
            System.out.println("Encrypted Data: " + encryptedData);

            

            // Combine the encrypted message and signed data (you would likely bundle this together in a real use case)
            //String combinedData = encryptedData + ":" + signedData;

            // Decrypt the message using AES
            String decryptedData = getDecryptedData(encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);
            
            //sample
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair yashKeyPair = keyPairGenerator.generateKeyPair();
            yashPublicKey = yashKeyPair.getPublic();
            // Verify the signature using RSA public key
            String isSignatureValid = verifySignature(originalData, signedData);
            System.out.println("Signature Valid: " + isSignatureValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
