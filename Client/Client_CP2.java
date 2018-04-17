import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;

public class Client_CP2 {

    public static void main(String args[]) {

        String hostName = "10.12.136.138";
        int portNumber = 4321;
    
        String my_nonce = "noncey";
        String name="test";

        
        
        FileInputStream fileInputStream = null;
        String fileName = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\testLarge.txt"
        		+ "";
       
        boolean file_sent = false;
     
        try {
        	 Socket clientSocket = new Socket(hostName, portNumber);

             //initiate IO
             InputStream inputStream_from_server = clientSocket.getInputStream();
             InputStreamReader isr = new InputStreamReader(inputStream_from_server);
             BufferedReader in = new BufferedReader(isr);
             OutputStream toServer = clientSocket.getOutputStream();
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);
            clientSocket = new Socket(hostName, portNumber);

            
            


          //============================Certificate verification=======================================

            //receive certificate from server
            String serverCert_string = in.readLine();
            byte[] serverCert_byte = DatatypeConverter.parseBase64Binary(serverCert_string);

            //new file to store the certificate received from client
            File file = new File("cert.crt");
            FileWriter writer = new FileWriter(file);
            writer.write(new String(serverCert_byte));
            writer.close();

            InputStream caCertInputStream= new FileInputStream("C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\CA.crt"); 
            CertificateFactory cf_ca= CertificateFactory.getInstance("X.509");
            X509Certificate CAcert= (X509Certificate) cf_ca.generateCertificate(caCertInputStream);

          
            try{
                CAcert.checkValidity();
                System.out.println("CA certificate valid");
            }catch (CertificateExpiredException e){
                e.printStackTrace();
            } catch (CertificateNotYetValidException e){
                e.printStackTrace();
            }

            InputStream certFileInputStream = new FileInputStream("cert.crt");
            CertificateFactory cf_myself = CertificateFactory.getInstance("X.509");
            X509Certificate MyCert = (X509Certificate) cf_myself.generateCertificate(certFileInputStream);
            
            //check validity of server signed cert, if not valid an exception will be thrown
            try{
                MyCert.checkValidity();
                System.out.println("server certificate valid");
            }
            //CertificateExpiredException - if the certificate has expired.
            catch (Exception e){
                e.printStackTrace();
            }
            

            //verify server cert using CA's public key
            PublicKey CA_Key = CAcert.getPublicKey();
            try {
                MyCert.verify(CA_Key);
                System.out.println("server certificate verified");
            }catch (Exception e){
                e.printStackTrace();
            }
             
            //extract public key from X509 cert object
            PublicKey server_publicKey = MyCert.getPublicKey();



//---------------------------2. Authentication (nonce)--------------------------------// 

            out.println("noncey"); 
            out.flush();
            System.out.println("plain nonce sent");

            String encrypted_nonce_string = in.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
        
            Cipher decryptNonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptNonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            byte[] decrypted_nonce= decryptNonce.doFinal(encrypted_nonce);
            
            System.out.println("decrypted_nonce: "+new String(decrypted_nonce));

            
            if(new String(decrypted_nonce).equals("noncey"))
            	System.out.println("nonce matched");
         



//---------------------------3. Confidentiality (RSA+AES)--------------------------------//

           while(true)
           {
                if(!file_sent){
                   
                    File file_to_server = new File(fileName);
                    

                    Cipher eCipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    eCipherRSA.init(Cipher.ENCRYPT_MODE, server_publicKey);
                    
        			out.println(name);
        			
                    out.flush();
                   
                    fileInputStream = null;
                    byte[] input_file_as_byte_array = new byte[(int) file_to_server.length()];
                    
                    try {
                        //convert file into byte array
                        fileInputStream = new FileInputStream(file_to_server);
                        fileInputStream.read(input_file_as_byte_array);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                
                    SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                    Cipher cipher_encrypt = Cipher.getInstance("AES");
                    cipher_encrypt.init(Cipher.ENCRYPT_MODE, key); //init as encrypt mode

                  
                    byte[] encryptedBytes = cipher_encrypt.doFinal(input_file_as_byte_array);

                    out.println(encryptedBytes.length);
                    out.flush();

                   
                    BufferedOutputStream bufferedOutputStream= new BufferedOutputStream(toServer);
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length);
                    System.out.println("stream size is: "+encryptedBytes.length);
                    bufferedOutputStream.flush();

                    System.out.println("AES encrypted file sent");  
                                
                   
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_publicKey);

                    //convert secrete AES session key to byte[]
                    byte[] secrete_key_byte = key.getEncoded();

                    //encrypt message
                    byte[] secrete_key_byte_encrypted = rsaCipher_encrypt.doFinal(secrete_key_byte);

                    //convert encrypted AES session key to base64 format
                    String secrete_key_byte_encrypted_string = DatatypeConverter.printBase64Binary(secrete_key_byte_encrypted);

                    out.println(secrete_key_byte_encrypted_string);
                    out.flush();
                    file_sent = true;
                }
                else{
                  
                    String server_bytes_to_string= new String(in.readLine());
                    if(server_bytes_to_string.equals("uploaded file")){
                     
                        
                        System.out.println("File uploaded successfully");
                        inputStream_from_server.close();
                        toServer.close();
                        clientSocket.close();
                        break;
                    }
                    else {
                        System.out.println("File was not uploaded successfully");
                        System.exit(1);
                    }
           }
           }
           

        } catch (FileNotFoundException e) {
            System.out.println("File not found");
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

}
