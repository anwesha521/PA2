

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class Server_CP1 {
    public static void main(String[] args) throws Exception {

        String fileName = "server.crt";
        String privateKeyFileName = "privateServer.der";

        if (args.length > 0) fileName = args[0];

        ServerSocket serverSocket = null;

        Socket clientSocket = null;

        long startTime = System.nanoTime();

       int fileLength;
        byte[] byteFile=null;
        String name="default"; //setting default name for uploaded file

        Cipher eCipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");


        try
        {

//================================Establishing connections==============================================



            serverSocket = new ServerSocket(4321);
            clientSocket = serverSocket.accept();



            System.out.println("Client connected");

            FileInputStream fileInputStream = null;
            InputStream fromClient = clientSocket.getInputStream();
            InputStreamReader isr = new InputStreamReader(fromClient);
            BufferedReader in = new BufferedReader(isr);

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);



//================================CA Authentication================================

            File file_to_client = new File(fileName);

            byteFile = new byte[(int) file_to_client.length()];

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





//=============================Nonce===================================================


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
            deCipher.init(Cipher.DECRYPT_MODE, serverPKey);

//=============================RSA===============================================




                    name=in.readLine();
                    System.out.println("name="+name);

                    Integer numberBytes = new Integer(in.readLine());


                    byteFile = new byte[numberBytes];

                    BufferedInputStream bufferedInputStream1= new BufferedInputStream(fromClient);

                    bufferedInputStream1.read(byteFile, 0, numberBytes);
                    System.out.println("file received and read");
                    out.write("uploaded file\n");
                    out.flush();

                    fileLength= byteFile.length;
                    int num= (int) Math.ceil(fileLength/128.0); //decrypting in blocks of 128 as per RSA

                    byte[][] fileBytesArray= new byte[num][];
                    byte[][] decryptedBytesArray= new byte[num][];

                    int i=0;
                    for (i=0; i<fileBytesArray.length-1; i++) {

                        fileBytesArray[i] = Arrays.copyOfRange(byteFile, i * 128, (i + 1) * 128);
                    }
                    fileBytesArray[i] = Arrays.copyOfRange(byteFile, i * 128, byteFile.length);

                    ByteArrayOutputStream joinedBytes= new ByteArrayOutputStream();

                    //decrypted file per block
                    for (i=0; i<fileBytesArray.length; i++) {
                        decryptedBytesArray[i]= deCipher.doFinal(fileBytesArray[i]);
                        joinedBytes.write( decryptedBytesArray[i], 0,  decryptedBytesArray[i].length);
                    }

                    byte[] decryptedBytes=joinedBytes.toByteArray();



                    FileOutputStream createFile= new FileOutputStream(name+"CP1"); //creating output file
                    createFile.write(decryptedBytes);
                    createFile.close();

                    System.out.println("Closing connection...");
                    fromClient.close();

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        // end time for file transfer
        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Time taken for file transfer [CP1] is: "+duration/1000000+" ms");
    }
}
