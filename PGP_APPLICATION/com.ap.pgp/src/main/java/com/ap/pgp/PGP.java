package com.ap.pgp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PGP {
	
	public static String digitalSign (String reqData) {
		
		String signature = " ";
        try {
          
        // Load private and public keys
        PrivateKey privateKey = loadPrivateKey("C:\\Users\\Sreenivas Bandaru\\Desktop\\PGP\\A_keys\\privateKey.pem");
      
        // Sign the JSON
        signature = signJSON(reqData, privateKey);
        
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signature;
    }
	

	public static SecretKey secretKey;
	public static String getEncryptedData(String data) {
		byte[] byteData = data.getBytes();
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
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
	
	//Get Session Key
	   public static String getSecretKeyBase64() {
	        // Check if the secret key is available
	        if (secretKey != null) {
	            return Base64.getEncoder().encodeToString(secretKey.getEncoded());  // Return the key as Base64 string
	        }
	        return null;  // Return null if the secret key has not been set
	    }
	
	   
	   //Encrypting Session Key
	   public static String encryptSessionKey() {
	        try {
	            // Step 1: Get the secret AES key in Base64 format
	            String sessionKeyBase64 = getSecretKeyBase64();

	            if (sessionKeyBase64 == null) {
	                throw new Exception("AES secret key is not generated or available.");
	            }

	            // Step 2: Load the RSA public key (you need to provide the public key file path)
	            PublicKey publicKey = loadPublicKey("C:\\Users\\Sreenivas Bandaru\\Desktop\\PGP\\B_keys\\publicKey.pem");

	            // Step 3: Encrypt the AES session key using RSA
	            Cipher cipher = Cipher.getInstance("RSA");
	            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	            byte[] encryptedSessionKey = cipher.doFinal(Base64.getDecoder().decode(sessionKeyBase64));

	            // Step 4: Return the encrypted session key as Base64 string
	            return Base64.getEncoder().encodeToString(encryptedSessionKey);

	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }
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


    // Method to sign JSON using a private key
    public static String signJSON(String json, PrivateKey privateKey) {
        Signature signature;
		try {
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
	        signature.update(json.getBytes(StandardCharsets.UTF_8));
	        byte[] signedBytes = signature.sign();
	        return Base64.getEncoder().encodeToString(signedBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			e.printStackTrace();
			return null;
		}
        
    }

    // Method to verify JSON using a public key
    public static Boolean verifyHash(String json, String signature) {
    	PublicKey publicKey = loadPublicKey("C:\\Users\\Sreenivas Bandaru\\Desktop\\PGP\\A_keys\\publicKey.pem");
        Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(publicKey);
	        sig.update(json.getBytes(StandardCharsets.UTF_8));
	        byte[] signedBytes = Base64.getDecoder().decode(signature);
	        return sig.verify(signedBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		}
        
    }

    // Method to load a private key from a PEM file
    public static PrivateKey loadPrivateKey(String privateKey) {
        String key;
		try {
			key = new String(Files.readAllBytes(Paths.get(privateKey)), StandardCharsets.UTF_8);
			key = key.replace("-----BEGIN PRIVATE KEY-----", "")
	                 .replace("-----END PRIVATE KEY-----", "")
	                 .replaceAll("\\s", "");
	        byte[] keyBytes = Base64.getDecoder().decode(key);
	        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        return kf.generatePrivate(spec);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
        
    }

    // Method to load a public key from a PEM file
    public static PublicKey loadPublicKey(String publicKey) {
        String key;
		try {
			key = new String(Files.readAllBytes(Paths.get(publicKey)), StandardCharsets.UTF_8);
			key = key.replace("-----BEGIN PUBLIC KEY-----", "")
	                 .replace("-----END PUBLIC KEY-----", "")
	                 .replaceAll("[\\r\\n]+", "") // Removes all newlines and carriage returns
	                 .trim(); // Remove leading/trailing spaces
	        byte[] keyBytes = Base64.getDecoder().decode(key);
	        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        return kf.generatePublic(spec);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
        
    }
}