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

            //Read file and convert to byte array
            String serverCertN = "server.crt";
            File serverCert = new File(serverCertN);
            InputStream inputStream= new FileInputStream(serverCertN);
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            numBytes = dataInputStream.readInt();
            byte[] serverCertByteArray = new byte[numBytes];
            dataInputStream.readFully(serverCertByteArray, 0, numBytes);

            //convert server cert byte array to Base64
            String serverCertBase64 = DatatypeConverter.printBase64Binary(serverCertByteArray);

            toClient.write(serverCertByteArray, 0, numBytes);
            toClient.flush();
            System.out.println("Server certificate sent");

            //============================================================Nonce

            //Receive nonce by client
            numBytes = fromClient.readInt();
            byte[] nonceByteArray = new byte[numBytes];
            fromClient.readFully(nonceByteArray, 0, numBytes);

            String nonce = DatatypeConverter.printBase64Binary(nonceByteArray);
            System.out.println("Nonce: "+nonce);

            //Generate private key
            String privateKeyN = "privateServer.der";
            Path path = Paths.get(privateKeyN);
            byte[] privateKeyByteArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            //Encrypt nonce
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedNonceByteArray = rsaCipher.doFinal(nonceByteArray); //or
            //byte[] encryptedNonce = rsaCipher.doFinal(nonce.getBytes());
            numBytes = encryptedNonceByteArray.length;

            String encryptedNonce = DatatypeConverter.printBase64Binary(encryptedNonceByteArray);

            //Send encrypted nonce to client
            toClient.write(encryptedNonceByteArray, 0, numBytes);
            toClient.flush();
            System.out.println("Encrypted Nonce sent");

            //===========================================================Confidentiality
            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    startTime = System.nanoTime();

                    System.out.println("Receiving file...");

                    numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    numBytes = fromClient.readInt();
                    byte [] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);

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
