import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server_CP2 {
    public static void main(String[] args) throws Exception {
        //initiate the server socket
    	String fileName = "server.crt";
   	    String privateKeyFileName = "privateServer.der";
   	 
   	   if (args.length > 0) fileName = args[0];
   	
       ServerSocket serverSocket = null;
       long startTime = System.nanoTime();
       Socket clientSocket = null;
       byte[] byteFile=null;
     
      
       
       String name="default"; //setting default name for uploaded file


try
{
	
	//================================Establishing connections==============================================
	
	
	
	serverSocket = new ServerSocket(4321);
	clientSocket = serverSocket.accept();
	 FileInputStream fileInputStream = null;
     InputStream fromClient = clientSocket.getInputStream();
     InputStreamReader isr = new InputStreamReader(fromClient);
     BufferedReader in = new BufferedReader(isr);

     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);
     Cipher eCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");

	System.out.println("Client connected");
	
	
  
	//================================CA Authentication================================
	File file_to_client = new File(fileName);
    
    byteFile = new byte[(int) file_to_client.length()];
    int fileLength= byteFile.length;
    try {
       
        fileInputStream = new FileInputStream(file_to_client);
        fileInputStream.read(byteFile);
        fileInputStream.close();
    } catch (Exception e) {
        e.printStackTrace();
    }

   
    String byteFile_string = DatatypeConverter.printBase64Binary(byteFile);

    out.write(byteFile_string+"\n");
    out.flush();
    System.out.println("server certificate sent");  




//---------------------------2. Authentication (nonce)--------------------------------//

    String nonce = in.readLine();
    System.out.println("plain nonce received: "+nonce);

  
    Path path = Paths.get(privateKeyFileName);
    byte[] privKeyByteArray = Files.readAllBytes(path);
    
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PrivateKey serverPKey = keyFactory.generatePrivate(keySpec);

    // encrypt nonce with private key
    eCipher.init(Cipher.ENCRYPT_MODE, serverPKey);
    byte[] encrypted_nonce= eCipher.doFinal((nonce.getBytes()));
    
    // convert encrypted nonce into String (base64binary)
    String encryptedNonceString = DatatypeConverter.printBase64Binary(encrypted_nonce);
    System.out.println("encrypt nonce: "+encryptedNonceString);

    out.write(encryptedNonceString+"\n");
    out.flush();
    System.out.println("encrypt nonce sent");
        



//---------------------------3. Confidentiality (RSA+AES)--------------------------------//
    String fname="";
   
    
    
    fname=in.readLine();

    Integer numberBytes = new Integer(in.readLine());

    byte[] fileReceived_byte = new byte[numberBytes];

 
    BufferedInputStream bufferedInputStream= new BufferedInputStream(fromClient);
    
    bufferedInputStream.read(fileReceived_byte, 0, numberBytes);
    System.out.println("file received and read");

    String secrete_key_byte_encrypted_string = in.readLine();
    System.out.println(secrete_key_byte_encrypted_string);
    out.write("uploaded file\n");
    out.flush();

    byte[] secrete_key_byte_encrypted = DatatypeConverter.parseBase64Binary(secrete_key_byte_encrypted_string);

  
    Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, serverPKey);
    byte[] decryptedBytes = rsaCipher_decrypt.doFinal(secrete_key_byte_encrypted);
    SecretKey key = new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "AES");

    Cipher cipher_decrypt = Cipher.getInstance("AES");
    cipher_decrypt.init(Cipher.DECRYPT_MODE, key); 
    
    byte[] decryptedFile = cipher_decrypt.doFinal(fileReceived_byte);

    FileOutputStream create_file= new FileOutputStream(fname);
    create_file.write(decryptedFile);
    create_file.close();
    fromClient.close();

 }
        catch(Exception e)
    {
        	e.printStackTrace();
    }



        
        long endTime = System.nanoTime();
        long duration = (endTime - startTime); 
        
        System.out.println("Time taken for file transfer [CP2] is: "+duration/1000000+" ms");          
    }
}
    
