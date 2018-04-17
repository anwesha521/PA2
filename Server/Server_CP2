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
        ServerSocket serverSocket = new ServerSocket(43211);

        //handshake with client
        Socket clientSocket = serverSocket.accept();
        System.out.println("client connected");  

        //initiate IO
        InputStream inputStream_from_client = clientSocket.getInputStream();   
        InputStreamReader isr = new InputStreamReader(inputStream_from_client);
        BufferedReader in = new BufferedReader(isr);
        OutputStream outputStream_to_client = clientSocket.getOutputStream();         
        PrintWriter out = new PrintWriter(outputStream_to_client, true);




//---------------------------1. Authentication (CA)--------------------------------//

        //server send its own certificate to client
        String fileName = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\src\\server.crt";
        File file_to_client = new File(fileName);
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
        while ((line = bufferedReader.readLine()) != null) {
            data = data + "\n" + line;
        }

        FileInputStream fileInputStream = null;
        byte[] input_file_as_byte_array = new byte[(int) file_to_client.length()];
        int file_byte_length= input_file_as_byte_array.length;
        try {
            //convert file into byte array
            fileInputStream = new FileInputStream(file_to_client);
            fileInputStream.read(input_file_as_byte_array);
            fileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //convert byte array file (server certificate) to base64 format
        String input_file_as_byte_array_string = DatatypeConverter.printBase64Binary(input_file_as_byte_array);

        //send file to client
        out.write(input_file_as_byte_array_string+"\n");
        out.flush();
        System.out.println("server certificate sent");    




//---------------------------2. Authentication (nonce)--------------------------------//

        // receive plain nonce broadcasted by client
        String nonce = in.readLine();
        System.out.println("plain nonce received: "+nonce);

        // generate private key
        String privateKeyFileName = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\src\\privateServer.der";
        Path path = Paths.get(privateKeyFileName);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey server_privateKey = keyFactory.generatePrivate(keySpec);

        // encrypt nonce with private key
        Cipher rsaCipher_encrypt_nonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_encrypt_nonce.init(Cipher.ENCRYPT_MODE, server_privateKey);
        byte[] encrypted_nonce= rsaCipher_encrypt_nonce.doFinal((nonce.getBytes()));
        
        // convert encrypted nonce into String (base64binary)
        String encrypted_nonce_string = DatatypeConverter.printBase64Binary(encrypted_nonce);
        System.out.println("encrypt nounce: "+encrypted_nonce_string);
        System.out.println("encrypt nounce size: "+encrypted_nonce.length);

        // send encrypted nonce to client
        out.write(encrypted_nonce_string+"\n");
        out.flush();
        System.out.println("encrypt nonce sent");
        



//---------------------------3. Confidentiality (RSA+AES)--------------------------------//

        Integer numberBytes = new Integer(in.readLine());
        //initialize fileReceived_bytes
        byte[] fileReceived_byte = new byte[numberBytes];

        //convert buffinputstream into byte array
        BufferedInputStream bufferedInputStream= new BufferedInputStream(inputStream_from_client);
        
        //then simply read over from stream into byte array
        bufferedInputStream.read(fileReceived_byte, 0, numberBytes);
        System.out.println("file received and read");

        // start time for file transfer
        long startTime = System.nanoTime();
       
        
        String secrete_key_byte_encrypted_string = in.readLine();
      
        out.write("uploaded file\n");
        out.flush();

        // convert String received from client to byte[]
        byte[] secrete_key_byte_encrypted = DatatypeConverter.parseBase64Binary(secrete_key_byte_encrypted_string);

        // decrypt the encrypted AES session key in byte[] format useing private key
        Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, server_privateKey);
        byte[] decryptedBytes = rsaCipher_decrypt.doFinal(secrete_key_byte_encrypted);
        SecretKey key = new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "AES");

        //create cipher object, initialize the ciphers with the given key, choose decryption mode as AES
        Cipher cipher_decrypt = Cipher.getInstance("AES");
        cipher_decrypt.init(Cipher.DECRYPT_MODE, key); //init as decrypt mode

        //do decryption, by calling method Cipher.doFinal().
        byte[] decryptedFile = cipher_decrypt.doFinal(fileReceived_byte);

        //write decrypted bytes into a image file using FileOuputStream
        FileOutputStream create_file= new FileOutputStream("serverFileCP2");
        create_file.write(decryptedFile);
        create_file.close();

        // end time for file transfer
        long endTime = System.nanoTime();
        long duration = (endTime - startTime); 
        // the time may include time to enter the name of the file to be transferred
        System.out.println("Time taken for file transfer [CP2] is: "+duration/1000000+" ms");          
    }
}
