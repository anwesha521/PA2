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

	@SuppressWarnings("deprecation")
    public static void main(String args[]) {
		
		String fileName = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\test.txt";
        String hostName = "localhost";
        String name="test";
        int portNumber = 43211;
    

        boolean file_sent = false;
        
        Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
        BufferedOutputStream bufferedOutputStream =null;
        FileInputStream fileInputStream = null;
       
     
        try {
        	System.out.println("Establishing connection to server...");

            clientSocket = new Socket(hostName, portNumber);

            //initiate IO
            fromServer = new DataInputStream(clientSocket.getInputStream());
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            
         
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);


//============================Certificate verification=======================================

            String serverCert_string = fromServer.readLine();
            byte[] serverCert_byte = DatatypeConverter.parseBase64Binary(serverCert_string);

            //new file to store the certificate received from client
            File file = new File("cert.crt");
            FileWriter writer = new FileWriter(file);
            writer.write(new String(serverCert_byte));
            writer.close();

            InputStream caCertInputStream= new FileInputStream("C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\src\\CA.crt"); 
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
            catch (CertificateExpiredException e){
                e.printStackTrace();
            }
            //CertificateNotYetValidException - if the certificate is not yet valid.
            catch (CertificateNotYetValidException e){
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


//===============================Nonce====================================

            out.println("noncey"); 
            out.flush();
            System.out.println("plain nonce sent");

            String encrypted_nonce_string = fromServer.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
        
            Cipher decryptNonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptNonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            byte[] decrypted_nonce= decryptNonce.doFinal(encrypted_nonce);
            
            System.out.println("decrypted_nonce: "+new String(decrypted_nonce));

            
            if(new String(decrypted_nonce).equals("noncey"))
            	System.out.println("nonce matched");



//=============================RSA+AES========================================

            
            while(true){
                if(!file_sent){
                    
                   
                    File serverFile = new File(fileName);
                    
                    fileInputStream = new FileInputStream(fileName);
                    fileInputStream.close();
                    
                    //generating secret key using AES
                    SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                    Cipher eCipherAES = Cipher.getInstance("AES");
                    eCipherAES.init(Cipher.ENCRYPT_MODE, key);
                    
                    Cipher eCipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    eCipherRSA.init(Cipher.ENCRYPT_MODE, server_publicKey);
                    
                    byte[] byteFile = new byte[(int) serverFile.length()];
                    
                    try {
                        //convert file into byte array
                        fileInputStream = new FileInputStream(serverFile);
                        fileInputStream.read(byteFile);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    
                    
                    //convert secrete AES session key to byte[]
                    byte[] byteKey = key.getEncoded();

                    //encrypt message
                    byte[] byteKeyEncrypted = eCipherRSA.doFinal(byteKey);

                    //convert encrypted AES session key to base64 format
                    String byteKeyEncryptedString = DatatypeConverter.printBase64Binary(byteKeyEncrypted);

                    toServer.writeInt(0);
                    toServer.writeChars(byteKeyEncryptedString);
                    toServer.flush();

                    
                    toServer.writeInt(1); //sending packet type =0 for file name
        			byte[] n=eCipherAES.doFinal(name.getBytes());
        			
        			toServer.writeInt(n.length);
        			bufferedOutputStream= new BufferedOutputStream(toServer);
                    bufferedOutputStream.write(n, 0, n.length); //sending name of file to be saved
                    bufferedOutputStream.flush();
        			toServer.flush();

                    //do encryption, by calling method Cipher.doFinal().
                    byte[] encryptedBytes = eCipherAES.doFinal(byteFile);
                    toServer.writeInt(2);
                    toServer.writeInt(encryptedBytes.length);
                    toServer.flush();

             
                    bufferedOutputStream= new BufferedOutputStream(toServer);
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length);
                    System.out.println("stream size is: "+encryptedBytes.length);
                    bufferedOutputStream.flush();

                    System.out.println("AES encrypted file sent");  
   
                   

                   
                    file_sent = true;
                    
                } 

                else{
                	
                	 String serverMsg= new String(fromServer.readLine());
                     
                     if(serverMsg.trim().equals("uploaded file")){
                     	 toServer.writeInt(3);
                        
                         System.out.println("File uploaded successfully");
                         
                         break;
                     }
                     else {
                         System.out.println("File was not uploaded successfully");
                         System.exit(1);
                     }

                }
                
                fromServer.close();
                toServer.close();
                clientSocket.close();
            } 
        } 
        catch (Exception e) {
            e.printStackTrace();
        }

    }

}
