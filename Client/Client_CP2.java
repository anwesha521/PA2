import java.io.BufferedInputStream;
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
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class Client_CP2 {

    @SuppressWarnings("deprecation")
	public static void main(String args[]) {

    	String filename = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\test.txt";
    	if (args.length > 0) filename = args[0];
    	
        String serverAddress = "localhost";
        int port = 43211;

        Socket clientSocket = null;
        
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
        
        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
        BufferedOutputStream bufferedOutputStream= null;
      
        
        boolean file_sent = false;
      
        try {

        	System.out.println("Establishing connection to server...");
        	
            clientSocket = new Socket(serverAddress, port);

            
            fromServer = new DataInputStream(clientSocket.getInputStream());
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            bufferedOutputStream= new BufferedOutputStream(toServer);

         
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);


//---------------------------1. Authentication (CA)--------------------------------//

            //receive certificate from server
            String serverCert_string = fromServer.readLine();
            byte[] serverCert_byte = DatatypeConverter.parseBase64Binary(serverCert_string);

            //new file to store the certificate received from client
            File file = new File("cert.crt");
            FileWriter writer = new FileWriter(file);
            writer.write(new String(serverCert_byte));
            writer.close();

            //creating X509 Certificate object
            InputStream caCertInputStream= new FileInputStream("C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\src\\CA.crt"); 
            CertificateFactory cf_ca= CertificateFactory.getInstance("X.509");
            X509Certificate CAcert= (X509Certificate) cf_ca.generateCertificate(caCertInputStream);

            //check CA cert validity
            try{
                CAcert.checkValidity();
                System.out.println("CA certificate valid");
            }catch (CertificateExpiredException e){
                e.printStackTrace();
            } catch (CertificateNotYetValidException e){
                e.printStackTrace();
            }

            InputStream certFileInputStream = new FileInputStream("C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\src\\server.crt");
            CertificateFactory cf_myself = CertificateFactory.getInstance("X.509");
            X509Certificate MyCert = (X509Certificate) cf_myself.generateCertificate(certFileInputStream);
            
            //check validity of server signed cert
            try{
                MyCert.checkValidity();
                System.out.println("server certificate valid");
            }
          
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
             
    
            PublicKey serverKey = MyCert.getPublicKey();



//================================NONCE===========================================

            out.println("myNoncas"); //sending my nonce to the server
            out.flush();
            System.out.println("plain nonce sent");

            String encrypted_nonce_string = fromServer.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
        
            Cipher decryptNonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptNonce.init(Cipher.DECRYPT_MODE, serverKey);
            byte[] decrypted_nonce= decryptNonce.doFinal(encrypted_nonce);
            
            System.out.println("decrypted_nonce: "+new String(decrypted_nonce));

            
            if(new String(decrypted_nonce).equals("myNoncas")){
                System.out.println("nonce matched");
            }



//==================================AES encryption/decryption==================================

            //sending the file
            while(true)
                if(!file_sent){
                    
                	File serverFile = new File(filename);
                    
                    fileInputStream = new FileInputStream(filename);
        			bufferedFileInputStream = new BufferedInputStream(fileInputStream);
        			fileInputStream.close();
        			
        			
        			
                    byte[] inputByteFile = new byte[(int) serverFile.length()];
                  
                    try {
                       
                        fileInputStream = new FileInputStream(serverFile);
                        fileInputStream.read(inputByteFile);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                  
                    SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                    
                    Cipher cipher_encrypt = Cipher.getInstance("AES");
                    cipher_encrypt.init(Cipher.ENCRYPT_MODE, key); //init as encrypt mode

                    byte[] encryptedBytes = cipher_encrypt.doFinal(inputByteFile);

                    
                    //send the encryptedBytes.length
                    out.println(encryptedBytes.length);
                    out.flush();
                    
                  
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length); //sending encrypted file
                    bufferedOutputStream.flush();


                    System.out.println("AES encrypted file sent");  
                                
                  
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, serverKey);

                   
                    byte[] secrete_key_byte = key.getEncoded();

                    byte[] secrete_key_byte_encrypted = rsaCipher_encrypt.doFinal(secrete_key_byte);

             
                    String secret_key_byte_encrypted_string = DatatypeConverter.printBase64Binary(secrete_key_byte_encrypted);

                    out.println(secret_key_byte_encrypted_string);
                    out.flush();
                    file_sent = true;
                }  

                else{
                    
                    String serverMsg= new String(fromServer.readLine());
                    if(serverMsg.equals("uploaded file")){
                       
                        System.out.println("File uploaded successfully");
                        fromServer.close();
                        toServer.close();
                        clientSocket.close();
                        break;
                    }
                    else {
                        System.out.println("File was not uploaded successfully");
                        System.exit(1);
                    }

                }
            

        } catch (FileNotFoundException e) {
            System.out.println("File not found");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}