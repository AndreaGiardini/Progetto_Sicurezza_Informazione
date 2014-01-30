import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;


public class ClientMainClass {
	
	/**
	* RSA key, 1024 bit, private key location, public key location
	*/
	static KeyHandler kh = new KeyHandler("RSA", 1024, "./private_client.key", "./public_client.key");
	static String serverAddr = "localhost";
	static int serverPort = 8412;
	static SecureRandom random = new SecureRandom();
	static String userName = new BigInteger(130, random).toString(32);
	static PublicKey serverPubKey;
	
	static ObjectOutputStream outSocket;
	static ObjectInputStream inSocket;
	
	private static void userRegistration(){
		
		try {

			// Send: "REG userName"
			outSocket.writeUTF("REG " + userName + "\n"); outSocket.flush();
			
			System.out.println("REG userName : sent");
			
			// Receive: Server's public key
			Frame frame = (Frame) inSocket.readObject();
			byte[] pubKey = frame.data;                 
			X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
			serverPubKey = KeyFactory.getInstance("RSA").generatePublic(ks);
			
			System.out.println("Server public key : received");
			
			// Send: User's public key
			frame = new Frame();
			ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(kh.PUBLIC_KEY));
			PublicKey publicKey = (PublicKey) inputStream.readObject();
			frame.data = publicKey.getEncoded();
			outSocket.writeObject(frame); outSocket.flush();
			inputStream.close();
			
			System.out.println("User public key : sent");
			
			// Receive: "OK"
			String answer = inSocket.readUTF();
			
			System.out.println("Operation confirmed: " + answer);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}	

	private static void userAuthentication(){
		
		try {
			
			// Sending username (AUTH username)		
			outSocket.writeUTF("AUTH " + userName); outSocket.flush();
			
			System.out.println("AUTH " + userName + " : sent");
			
			// Receive crypted message
			Frame fr = (Frame) inSocket.readObject();			
			ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(kh.PRIVATE_KEY));
			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
			final String plainText = kh.decrypt(fr.data, privateKey);
			inputStream.close();
			
			System.out.println("Ricevuto nonce : " + plainText);			
			
			// Send crypted answer
			//nputStream = new ObjectInputStream(new FileInputStream(kh.PUBLIC_KEY));
			//final PublicKey publicKey = (PublicKey) inputStream.readObject();
			fr.data = kh.encrypt(plainText, serverPubKey);
			outSocket.writeObject(fr); outSocket.flush();
			
			System.out.println("Inviato nonce");
			
			// Receive confirmation			
			System.out.println("Ricevuto : " + inSocket.readUTF());
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void main(String[] args) {

		try{
		
			// Check if the pair of keys are present else generate those.
			if (!kh.areKeysPresent()) {
				// Method generates a pair of keys using the RSA algorithm and stores it
				// in their respective files
				kh.generateKeys();
			}
			
			// Socket initialization
			Socket server = new Socket( serverAddr, serverPort );
			
			System.out.println("Socket connected");			
			System.out.println("User " + userName + " : Registration");
			
			// Build in/out streams
			outSocket = new ObjectOutputStream(server.getOutputStream());
			inSocket = new ObjectInputStream(server.getInputStream());
			
			// Registration process
			userRegistration();
			
			//Close socket
			outSocket.close(); inSocket.close(); server.close();			
			
			System.out.println("\nStarting authentication in 2 seconds...\n");
			Thread.sleep(2000);
			
			//Reconnect
			// Socket initialization
			server = new Socket( serverAddr, serverPort );
						
			System.out.println("Socket connected");			
			System.out.println("User " + userName + " : Authentication");
						
			// Build in/out streams
			outSocket = new ObjectOutputStream(server.getOutputStream());
			inSocket = new ObjectInputStream(server.getInputStream());
			
			// Authentication process
			userAuthentication();
						
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
