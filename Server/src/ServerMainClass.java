import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerMainClass {

	public static void main(String[] args) {
		/**
		* RSA key, 1024 bit, private key location, public key location
		*/
		KeyHandler kh = new KeyHandler("RSA", 1024, "./private_server.key", "./public_server.key");

		//final String originalText = "Text to be encrypted ";
	  	//ObjectInputStream inputStream = null;

		try{

			// Check if the pair of keys are present else generate those.
			if (!kh.areKeysPresent()) {
				// Method generates a pair of keys using the RSA algorithm and stores it
				// in their respective files
				kh.generateKeys();
			}
			
			// Socket listening on localhost
			ServerSocket server = new ServerSocket(8412);
			System.out.println("Server listening on 8412\n");
			
			// Infinite loop
			while(true)
			{
				Socket newClient = server.accept();
				
				// New connection handled by ClientHandler
				System.out.println("New Connection on port : " + newClient.getLocalPort());
				ClientHandler ch = new ClientHandler(newClient, kh);
				ch.start();
			}
			
			/*
			// Encrypt the string using the public key
			inputStream = new ObjectInputStream(new FileInputStream(kh.PUBLIC_KEY));
			final PublicKey publicKey = (PublicKey) inputStream.readObject();
			final byte[] cipherText = kh.encrypt(originalText, publicKey);
			inputStream.close();
			
			// Decrypt the cipher text using the private key.
			inputStream = new ObjectInputStream(new FileInputStream(kh.PRIVATE_KEY));
			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
			final String plainText = kh.decrypt(cipherText, privateKey);
			inputStream.close();
			
			// Printing the Original, Encrypted and Decrypted Text
			System.out.println("Original Text: " + originalText);
			System.out.println("Encrypted Text: " +cipherText.toString());
			System.out.println("Decrypted Text: " + plainText);
			*/
		} catch (Exception e) {
				e.printStackTrace();
		}
	}
}