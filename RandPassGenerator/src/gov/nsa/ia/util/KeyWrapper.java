package gov.nsa.ia.util;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyWrapper is a class that encrypts a generated hexadecimal key using 256 bit AES encryption key derived from random password.
 * Saves encrypted key as .enc file.
 * 
 * @author amsagos
 */

public class KeyWrapper {
	
	//256-bit salt generated from DRNG
	private static String saltinput = "762043c38a8e1ad1c8502ec6e53d8c503fe9b28bf73f583e4fadd5888737a5ae";
	

	/**
	 * Minimum length of a key encryption password, in characters.
	 */
	public static final int MIN_PASSWORD_LENGTH = 16;

	 /**
	  * Encrypt a key to a file, prompting on the console for a new
	  * password if the supplied one is shorter than 16 characters.
	  */
	 public static void fileProcessor(char[] pass,String inputKey,File encryptedFile){
		while (pass.length < MIN_PASSWORD_LENGTH) {
	    	   System.out.println("Password must be at least 16 characters, failed to encrypt key");
	    	   System.out.print("Provide a random password of at leaset 16 characters: ");  
	    	   //BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	    	   Console br = System.console();
	    	pass = br.readPassword();
		 }
		wrapKeyToFile(pass, inputKey, encryptedFile);
	 }

	 /**
	  * Encrypt a key to a file using a key encryption key derived from
	  * the supplied password.  Never prompts on the console.
	  *
	  * @param pass password of at least 16 characters
	  * @param inputKey the key to wrap
	  * @param encryptedFile destination file
	  * @return true if the encrypted file was written, false otherwise
	  */
	 public static boolean wrapKeyToFile(char[] pass,String inputKey,File encryptedFile){
		 try {
			//DPKDF2  NIST SP 800-132
			// salt value
			 byte[] salt = new String(saltinput).getBytes();
			  
			 // iteration count
			 int iterCount = 100000;
			  
			 int derivedKeyLength = 256 ; // Should be at least 256 bits.
			  
			 KeySpec spec = new PBEKeySpec(pass, salt, iterCount, derivedKeyLength);
			 SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			 
			 SecretKey secretKey = f.generateSecret(spec);
			 SecretKey cipherKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
			 
			 //RFC 3394
			 int cipherMode = Cipher.WRAP_MODE;
			 Cipher cipher = Cipher.getInstance("AESWrap", "SunJCE");
			   
			// setup the key encryption key and the to-be-wrapped key

		        byte[] newKey = new String(inputKey).getBytes();
		        SecretKey WrapThisKey = new SecretKeySpec(newKey, "AES");

		      
		       if (pass.length < MIN_PASSWORD_LENGTH) {
		    	   System.out.println("Password must be at least 16 characters, failed to encrypt key");
		    	   return false;
		       }else {
		    	   cipher.init(cipherMode, cipherKey); 
		       }
		       byte[] outputBytes = cipher.wrap(WrapThisKey);
		       try (FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
		    	   outputStream.write(outputBytes);
		       }
		       return true;
		    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | IOException | NoSuchProviderException | InvalidKeySpecException e) {
		    	e.printStackTrace();
		    	return false;
			}
	 }
		
	 //test
	 private static String DATA ="6b6c315f62b0453608169c73893d8f0abe79fdf63a078d5c2bc9bdcb57fa028c";
	 private static char[] KEKPW ="9fXMi5JvoHDIGQBM9fXMi5JvoHDIGQBM".toCharArray();
	 private static File EFile = new File("test.enc");
     
		 
	 public static void main(String[] args) {
		try {
			KeyWrapper.fileProcessor(KEKPW,DATA,EFile);
		    System.out.println("Test Successfull");
		 } catch (Exception ex) {
		     System.out.println(ex.getMessage());
	             ex.printStackTrace();
		 }
	 }

}
