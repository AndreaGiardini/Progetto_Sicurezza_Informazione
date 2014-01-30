import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


public class ClientHandler extends Thread {
	
	private Socket socket;
	private ObjectOutputStream outSocket;
	private ObjectInputStream inSocket;
	private enum Actions { REG, AUTH };
	private KeyHandler kh;
	
	/**
	 * Constructor
	 */
	public ClientHandler (Socket socket, KeyHandler kh){
		this.socket=socket; this.kh = kh;
		try {

			outSocket = new ObjectOutputStream(socket.getOutputStream());
			inSocket = new ObjectInputStream(socket.getInputStream());
			
		} catch (IOException e) {
			System.out.println("Unable to get socket streams");
			e.printStackTrace();
		}
	}
	
	/**
	 * User authentication
	 */
	private void authUser(String userName) {
		
		
	}

	/**
	 * User registration
	 */
	private void regUser(String userName) {
		
		try {
			
			System.out.println("New user registration : " + userName);
			
			// Send server public key to client
			Frame frame = new Frame();
			ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(kh.PUBLIC_KEY));
			PublicKey publicKey = (PublicKey) inputStream.readObject();
			frame.data = publicKey.getEncoded();
			
			//ObjectOutputStream outSocket = new ObjectOutputStream(socket.getOutputStream());
			outSocket.writeObject(frame); outSocket.flush();
			
			System.out.println("Server's key: sent");
			
			//inputStream.close();
			
			System.out.println("KEY SENT - " + publicKey.toString());
			
			// Wait for user public key
			frame = (Frame) inSocket.readObject();
			byte[] pubKey = frame.data;                 
			X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);	
			kh.keyDb.put(userName, KeyFactory.getInstance("RSA").generatePublic(ks));
			System.out.println("KEY RECEIVED - " + userName + " - " + kh.keyDb.get(userName).toString());
			System.out.println("User registered");
			
			// Confirm
			outSocket.writeUTF("OK"); outSocket.flush();
			
			System.out.println("confirmation : sent");
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Main workflow
	 */
	public void run(){
		
		/**
		 * Select action:
		 *  - Registration - REG $USER
		 *  - Authentication - AUTH $USER
		 */
		
		try {
			
			//out.flush();
			//in.read(); in.read();
			
			String operation = inSocket.readUTF(); System.out.println("Received: " + operation);
			String[] splitString = operation.split("\\s");
			Actions act = Actions.valueOf(splitString[0].trim());

			switch (act){
			
				case REG:
					regUser(splitString[1]);
					break;
				case AUTH:
					authUser(splitString[1]);
					break;
			
			}
				
			// Close streams and socket
			inSocket.close();
			outSocket.close();
			socket.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
