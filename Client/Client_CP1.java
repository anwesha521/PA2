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
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class Client_CP1 {

    @SuppressWarnings("deprecation")
	public static void main(String args[]) {

    	String filename = "C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\testLarge.txt";
    	String name="test";
    	if (args.length > 0) filename = args[0];
    	
       // String serverAddress = "10.12.136.138";
    	//String serverAddress = "localhost";
    	String serverAddress = "10.12.73.233";
    	
        int port = 4321;
     
       
        FileInputStream fileInputStream = null;
        boolean file_sent = false;
        Socket clientSocket;
        
        try {

        	System.out.println("Establishing connection to server...");
        	
            clientSocket = new Socket(serverAddress, port);

            InputStream inputStream_from_server = clientSocket.getInputStream();
            InputStreamReader isr = new InputStreamReader(inputStream_from_server);
            BufferedReader in = new BufferedReader(isr);
            OutputStream toServer = clientSocket.getOutputStream();
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);
           clientSocket = new Socket(serverAddress, port);


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



//================================NONCE===========================================

            out.println("noncey"); 
            out.flush();
            System.out.println("plain nonce sent");

            String encrypted_nonce_string = in.readLine();;
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
        
            Cipher decryptNonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptNonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            byte[] decrypted_nonce= decryptNonce.doFinal(encrypted_nonce);
            
            System.out.println("decrypted_nonce: "+new String(decrypted_nonce));

            
            if(new String(decrypted_nonce).equals("noncey"))
            	System.out.println("nonce matched");
         



//==================================RSA encryption/decryption==================================

            //sending the file
            while(true)
                if(!file_sent){
                	

                	out.println(name);
        			
                    out.flush();
                    File serverFile = new File(filename); //creating my file test.txt
                  
                    fileInputStream = new FileInputStream(filename);
        		
        			fileInputStream.close();
        			
        			
        			
                    byte[] inputByteFile = new byte[(int) serverFile.length()];

                    try {
                       
                        fileInputStream = new FileInputStream(serverFile);
                        fileInputStream.read(inputByteFile);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    
                   
                    Cipher eCipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    eCipherRSA.init(Cipher.ENCRYPT_MODE, server_publicKey);
                   
                    
                    
        			
                    
        			int length= inputByteFile.length;
                   
                    int blockSize= (int) Math.ceil(length/117.0);
                    
                    byte[][] byteBlocks= new byte[blockSize][]; //reading file in blocks of 117 bytes
                    byte[][] encryptedByteBlocks= new byte[blockSize][];
                    int i=0;
                    for (i=0; i<byteBlocks.length-1; i++) {
                       
                       
                        	byteBlocks[i] = Arrays.copyOfRange(inputByteFile, i * 117, (i + 1) * 117);
                         
                        
                    }
                    
                    byteBlocks[i] = Arrays.copyOfRange(inputByteFile, i * 117, inputByteFile.length);
                    
                    for (i=0; i<byteBlocks.length; i++) {
                        encryptedByteBlocks[i]= eCipherRSA.doFinal(byteBlocks[i]);
                    }
                  
                    ByteArrayOutputStream joining_encrypted_blocks= new ByteArrayOutputStream();

                    for (byte[] block: encryptedByteBlocks) {
                        joining_encrypted_blocks.write(block, 0, block.length);
                    }
                    byte[] encryptedBytes= joining_encrypted_blocks.toByteArray();
                 
                    out.println(encryptedBytes.length);
                    out.flush();
    
                    BufferedOutputStream bufferedOutputStream= new BufferedOutputStream(toServer);
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length);
                   
                    bufferedOutputStream.flush();

                    file_sent = true;
                } 

                else{
                    
                    String serverMsg= new String(in.readLine());
                  
                    if(serverMsg.trim().equals("uploaded file")){
                     System.out.println("File uploaded successfully");
                        
                        break;
                    }
                    else {
                        System.out.println("File was not uploaded successfully");
                        System.exit(1);
                    }

                }
          
            toServer.close();
            clientSocket.close();
            

        } catch (FileNotFoundException e) {
            System.out.println("File not found");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        

    }

}
