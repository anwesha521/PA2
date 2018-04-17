package Server;

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server_CP2 {
    public static void main(String[] args) throws Exception {

        String serverCertN = "server.crt";
        String privateKeyN = "privateServer.der";

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket clientSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedInputStream = null;

        Cipher enCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher aesCipher = Cipher.getInstance("AES");

        int numBytes;
        byte[] byteFile;
        String name = null;

        long startTime = 0;
        long endTime;
        long duration;


        try {

//================================Establishing connections==============================================

            System.out.println("Establishing connection to client... ....");
            clientSocket = new ServerSocket(port);
            connectionSocket = clientSocket.accept();
            System.out.println("Client connected");

            InputStream inputStream = connectionSocket.getInputStream();
            fromClient = new DataInputStream(inputStream);
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            BufferedReader in = new BufferedReader(inputStreamReader);

//================================CA Authentication================================

            //server send its own certificate to client
            File serverCert = new File(serverCertN);
            numBytes = (int) serverCert.length();
            byte[] serverCert_bytes = new byte[numBytes];

            try {
                //convert file into byte array
                fileInputStream = new FileInputStream(serverCertN);
                fileInputStream.read(serverCert_bytes, 0, numBytes);
                fileInputStream.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

            String serverCert_base64 = DatatypeConverter.printBase64Binary(serverCert_bytes);

            toClient.writeChars(serverCert_base64+"\n");
            toClient.flush();
            System.out.println("Server certificate sent");

//=============================Nonce===================================================

            String nonce = in.readLine();
            System.out.println("Nonce Received: "+nonce);

            byte[] privateKey_bytes = Files.readAllBytes(Paths.get(privateKeyN));

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey_bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            enCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] en_nonce_bytes= enCipher.doFinal((nonce.getBytes()));

            String en_nonce = DatatypeConverter.printBase64Binary(en_nonce_bytes);
            System.out.println("Encrypted nonce: "+en_nonce);
            System.out.println("Encrypted nonce size: "+en_nonce_bytes.length);

            toClient.writeChars(en_nonce_bytes+"\n");
            toClient.flush();
            System.out.println("Encrypted nonce sent");

//=============================RSA===============================================
            while (!connectionSocket.isClosed()) {

                bufferedInputStream = new BufferedInputStream(inputStream);

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {
                    numBytes = fromClient.readInt();
                    byte[] enSecretKey_bytes = new byte[numBytes];
                    bufferedInputStream.read(enSecretKey_bytes, 0, numBytes);
                    System.out.println("Secret Key Received and Read");

                    deCipher.init(Cipher.DECRYPT_MODE, privateKey);
                    // decrypt the encrypted AES session key in byte[] format using private key
                    byte[] secretKey_bytes = deCipher.doFinal(enSecretKey_bytes);
                    SecretKey secretKey = new SecretKeySpec(secretKey_bytes, 0, secretKey_bytes.length, "AES");
                    //create cipher object, initialize the ciphers with the given key, choose decryption mode as AES
                    aesCipher.init(Cipher.DECRYPT_MODE, secretKey); //init as decrypt mode

                } else if (packetType==1) {
                    System.out.println("Receiving file...");
                    numBytes = fromClient.readInt();
                    byte[] filename = new byte[numBytes];

                    bufferedInputStream.read(filename, 0, numBytes);

                    byte[] n = aesCipher.doFinal(filename);

                    name=new String(n);
                    System.out.println("name="+name);

                } else if (packetType==2) {

                    numBytes = fromClient.readInt();

                    byteFile = new byte[numBytes];

                    bufferedInputStream.read(byteFile, 0, numBytes);
                    System.out.println("File Received and Read");

                    startTime = System.nanoTime();

                    toClient.writeUTF("Uploaded File\n");
                    toClient.flush();


                    int num= (int) Math.ceil((byteFile.length)/128.0); //decrypting in blocks of 128 as per RSA

                    byte[][] fileBytesArray= new byte[num][];
                    byte[][] decryptedBytesArray= new byte[num][];

                    int len = fileBytesArray.length;

                    for (int i=0; i<len-1; i++) {
                        fileBytesArray[i] = Arrays.copyOfRange(byteFile, i * 128, (i + 1) * 128);
                    }
                    fileBytesArray[len] = Arrays.copyOfRange(byteFile, len * 128, byteFile.length);

                    ByteArrayOutputStream joinedBytes= new ByteArrayOutputStream();

                    //decrypted file per block
                    for (int i=0; i<fileBytesArray.length; i++) {
                        decryptedBytesArray[i]= aesCipher.doFinal(fileBytesArray[i]);
                        joinedBytes.write(decryptedBytesArray[i], 0,  decryptedBytesArray[i].length);
                    }

                    byte[] decryptedBytes=joinedBytes.toByteArray();

                    FileOutputStream file= new FileOutputStream(name+"_CP2"); //creating output file
                    file.write(decryptedBytes);
                    file.close();

                } else if (packetType==3) {
                    System.out.println("Closing connection...");
                    fromClient.close();
                    toClient.close();
                }
            }

            // end time for file transfer
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            // the time may include time to enter the name of the file to be transferred
            System.out.println("Time taken for Server_CP2 file transfer is: "+duration/1000000+" ms");

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
