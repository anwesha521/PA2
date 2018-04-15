package Server;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server_CP1 {

    public static void main(String[] args) {

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket clientSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileInputStream fileInputStream = null;
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        long startTime = System.nanoTime();
        long endTime;
        long duration;

        int numBytes;

        try {

            System.out.println("Establishing connection to client...");

            //Establish connection with client socket
            clientSocket = new ServerSocket(port);
            connectionSocket = clientSocket.accept();
            System.out.println("clientSocket accepted");

            //Initialise input/output stream with client
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            //=====================================================Authentication

            //server send its own certificate to client
            //Read file and convert to byte array
            String serverCertN = "server.crt";
            File serverCert = new File(serverCertN);
            InputStream inputStream= new FileInputStream(serverCert);
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            numBytes = (int) serverCert.length();
            byte[] serverCertByteArray = new byte[numBytes];
            dataInputStream.readFully(serverCertByteArray, 0, numBytes);

            toClient.write(serverCertByteArray, 0, numBytes);
            toClient.flush();
            System.out.println("Server certificate sent");

            //============================================================Nonce

            //Receive nonce by client
            InputStreamReader inputStreamReader = new InputStreamReader(fromClient);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            String nonce = bufferedReader.readLine();
            System.out.println("Nonce: "+nonce);

            //Generate private key
            String privateKeyN = "privateServer.der";
            Path path = Paths.get(privateKeyN);
            byte[] privateKeyByteArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            //Encrypt nonce
            Cipher rsaCipher_en = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_en.init(Cipher.ENCRYPT_MODE, privateKey);
            //byte[] encryptedNonceByteArray = rsaCipher_en.doFinal(nonce.getBytes()); //or
            byte[] encryptedNonceByteArray = rsaCipher_en.doFinal(nonce.getBytes());
            numBytes = encryptedNonceByteArray.length;

            String encryptedNonce = DatatypeConverter.printBase64Binary(encryptedNonceByteArray);

            //Send encrypted nonce to client
            toClient.write(encryptedNonceByteArray, 0, numBytes);
            toClient.flush();
            System.out.println("Encrypted Nonce sent");

            //===========================================================Confidentiality

            Cipher rsaCipher_de = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_de.init(Cipher.DECRYPT_MODE, privateKey);

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    startTime = System.nanoTime();

                    System.out.println("Receiving file...");

                    numBytes = fromClient.readInt();
                    byte[] encryptedFilename = new byte[numBytes];
                    fromClient.readFully(encryptedFilename, 0, numBytes);

                    byte[] filename = rsaCipher_de.doFinal(encryptedFilename);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    numBytes = fromClient.readInt();
                    byte [] encryptedBlock = new byte[numBytes];
                    fromClient.readFully(encryptedBlock, 0, numBytes);

                    byte[] block = rsaCipher_de.doFinal(encryptedBlock);

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(block, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }
            }

            endTime = System.nanoTime();
            duration = (endTime - startTime);
            // the time may include time to enter the name of the file to be transferred
            System.out.println("Time taken for file transfer [CP1] is: "+duration/1000000+" ms");

        } catch (Exception e) {e.printStackTrace();}

    }

}
