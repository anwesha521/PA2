
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

public class ClientCP1 {

    public static void main(String args[]) {

        String hostName = "10.12.73.233";
        
        System.out.println("hello");
        int portNumber = 4321;
        
        InputStream fromClient=null;
        InputStreamReader isr=null;
        BufferedReader in=null;
        OutputStream toServer=null;
        PrintWriter out=null;
        
        String fileName="C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\test.txt";
    
        String my_nonce = "noncey";

        boolean file_sent = false;
       
        try {

            //setting up connections
            Socket clientSocket = new Socket(hostName, portNumber);
            fromClient = clientSocket.getInputStream();
            isr = new InputStreamReader(fromClient);
            in = new BufferedReader(isr);
            toServer = clientSocket.getOutputStream();
            out = new PrintWriter(clientSocket.getOutputStream(),true);


//==============================Cetificate verification===========================

            //receive certificate from server
            String serverCert_string = in.readLine();
            byte[] serverCert_byte = DatatypeConverter.parseBase64Binary(serverCert_string);

            //create a new file to store the certificate received from client
            File file = new File("cert.crt");
            FileWriter writer = new FileWriter(file);
            writer.write(new String(serverCert_byte));
            writer.close();

            //create X509 Certificate object
            InputStream caCertInputStream= new FileInputStream("C:\\Users\\ASUS\\eclipse-workspace\\Assignment2\\CA.crt"); //TODO: REPLACE WITH ADDRESS
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



//---------------------------2. Authentication (nonce)--------------------------------// 

           
            out.println(my_nonce);
            out.flush();
            System.out.println("plain nonce sent");

       
            String encrypted_nonce_string = in.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
            Cipher deCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            deCipher.init(Cipher.DECRYPT_MODE, server_publicKey);
            byte[] decrypted_nonce= deCipher.doFinal(encrypted_nonce);
            System.out.println("decrypted_nonce: "+decrypted_nonce);

            //convert byte[] into String and check if matches the original nonce
            String decrypted_nonce_string= new String(decrypted_nonce);
            if(decrypted_nonce_string.equals(my_nonce)){
                System.out.println("nonce matched");
            }



//---------------------------3. Confidentiality (RSA)--------------------------------//

           
            while(true)
            {
                if(!file_sent){
                   
                   
                   
                    File file_to_server = new File(fileName);
                    String data = "";
                    String line;
                    BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
                    //parse file content into byte array
                    while ((line = bufferedReader.readLine()) != null) {
                        data = data + "\n" + line;
                    }
                    FileInputStream fileInputStream = null;
                    byte[] input_file_as_byte_array = new byte[(int) file_to_server.length()];

                    try {
                        //convert file into byte array
                        fileInputStream = new FileInputStream(file_to_server);
                        fileInputStream.read(input_file_as_byte_array);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    
                    
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_publicKey);

                  
                    int file_byte_length= input_file_as_byte_array.length;
                    System.out.println("input file byte array length= "+ input_file_as_byte_array.length);
                    int number_of_blocks= (int) Math.ceil(file_byte_length/117.0);


                    byte[][] blocks_of_fileBytes= new byte[number_of_blocks][];
                    byte[][] blocks_of_encryptedBytes= new byte[number_of_blocks][];
                    
                    int i=0;

                    for (i=0; i<blocks_of_fileBytes.length-1; i++) {
                       
                            blocks_of_fileBytes[i] = Arrays.copyOfRange(input_file_as_byte_array, i * 117, (i + 1) * 117);
                      
                   }
                    blocks_of_fileBytes[i] = Arrays.copyOfRange(input_file_as_byte_array, i * 117, input_file_as_byte_array.length);
                   
                    for (i=0; i<blocks_of_fileBytes.length; i++) {
                        blocks_of_encryptedBytes[i]= rsaCipher_encrypt.doFinal(blocks_of_fileBytes[i]);
                    }
                   
                    ByteArrayOutputStream joining_encrypted_blocks= new ByteArrayOutputStream();

                    for (byte[] block: blocks_of_encryptedBytes) {
                        joining_encrypted_blocks.write(block, 0, block.length);
                    }
                    byte[] encryptedBytes= joining_encrypted_blocks.toByteArray();

                   
                    String encryptedBytes_string = DatatypeConverter.printBase64Binary(encryptedBytes);
                    
                    out.println(encryptedBytes.length);
                    out.flush();

                   
                    BufferedOutputStream bufferedOutputStream= new BufferedOutputStream(toServer);
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length);
                    System.out.println("stream size is: "+encryptedBytes.length);
                    bufferedOutputStream.flush();

                    file_sent = true;
                } 

                else{
                   
                    String server_bytes_to_string= new String(in.readLine());
                    if(server_bytes_to_string.equals("uploaded file")){
                       
                        System.out.println("File uploaded successfully");
                        fromClient.close();
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
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
