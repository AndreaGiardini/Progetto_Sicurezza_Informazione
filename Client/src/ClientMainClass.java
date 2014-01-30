import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
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
	
	private static void userRegistration(Socket socket){
		
		try {

			ObjectOutputStream outSocket = new ObjectOutputStream(socket.getOutputStream());
			
			// Send: "REG userName"
			//PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
			outSocket.writeUTF("REG " + userName + "\n"); outSocket.flush();
			
			System.out.println("REG userName : sent");
			
			// Receive: Server's public key
			ObjectInputStream inSocket = new ObjectInputStream(socket.getInputStream());
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
			
			System.out.println("User public key : sent");
			
			// Receive: "OK"
			//BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String answer = inSocket.readUTF();
			
			System.out.println("Operation confirmed: " + answer);
			
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
			
			// Registration process
			userRegistration(server);
			

			
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
