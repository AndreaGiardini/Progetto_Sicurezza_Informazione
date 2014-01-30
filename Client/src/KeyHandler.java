import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

import javax.crypto.Cipher;

public class KeyHandler {
		/**
	* Encryption algorithm
	*/
	public final String ALGORITHM;
	
	/**
	* Key size
	*/
	public final int KEY_SIZE;

	/**
	* String to hold the name of the private key file
	*/
	public final String PRIVATE_KEY;

	/**
	* String to hold name of the public key file
	*/
	public final String PUBLIC_KEY;
	
	/**
	 * Hold users public keys (Username - PublicKey)
	 */
	public final HashMap<String,PublicKey> keyDb;

	/**
	* Constructor
	*/
	public KeyHandler(String ALGORITHM, int KEY_SIZE, String PRIVATE_KEY, String PUBLIC_KEY){
		this.ALGORITHM = ALGORITHM; this.KEY_SIZE = KEY_SIZE;
		this.PRIVATE_KEY = PRIVATE_KEY; this.PUBLIC_KEY = PUBLIC_KEY;
		this.keyDb = new HashMap<String,PublicKey>(); 
	}

	/**
	* Generate keys
	*/
	public void generateKeys() {
		try {
	
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(KEY_SIZE);
			final KeyPair key = keyGen.generateKeyPair();
	
			File privateKeyFile = new File(PRIVATE_KEY);
			File publicKeyFile = new File(PUBLIC_KEY);
	
			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();
	
			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();
	
			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();
	
			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
	
		} catch (Exception e) {
		  e.printStackTrace();
		}

	}

	/**
	* The method checks if the pair of public and private key has been generated.
	*/
	public boolean areKeysPresent() {

		File privateKey = new File(PRIVATE_KEY);
		File publicKey = new File(PUBLIC_KEY);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	* Encrypt the plain text using public key.
	*/
	public byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			  e.printStackTrace();
		}
		return cipherText;
	}

	/**
	* Decrypt text using private key.
	*/
	public String decrypt(byte[] text, PrivateKey key) {
	    byte[] dectyptedText = null;
	    try {
	    	// get an RSA cipher object and print the provider
	    	final Cipher cipher = Cipher.getInstance(ALGORITHM);

	    	// decrypt the text using the private key
	    	cipher.init(Cipher.DECRYPT_MODE, key);
	    	dectyptedText = cipher.doFinal(text);
	    } catch (Exception ex) {
	    	ex.printStackTrace();
	    }
	    return new String(dectyptedText);
	}
}