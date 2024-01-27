package clientPack;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * CryptoCipherClient class implements a client capable of encrypted communication with a server using AES encryption.
 */

public class CryptoCipherClient {
    /**
     * Encrypts the given text using AES encryption with the provided secret key.
     *
     * @param text      The plaintext to be encrypted
     * @param secretKey The secret key used for encryption
     * @return The Base64-encoded encrypted text
     * @throws IllegalBlockSizeException  If the block size is illegal
     * @throws BadPaddingException        If the padding is bad
     * @throws NoSuchPaddingException    If the padding is not available
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException       If the secret key is invalid
     */
    public static String encrypt(String text, SecretKey secretKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = text.getBytes();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedBytes = cipher.doFinal(bytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given Base64-encoded encrypted text using AES decryption with the provided secret key.
     *
     * @param encryptedText The Base64-encoded encrypted text
     * @param secretKey     The secret key used for decryption
     * @return The decrypted plaintext
     * @throws IllegalBlockSizeException  If the block size is illegal
     * @throws BadPaddingException        If the padding is bad
     * @throws NoSuchPaddingException    If the padding is not available
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException       If the secret key is invalid
     */
    public static String decrypt(String encryptedText,SecretKey secretKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptedBytes = cipher.doFinal(bytes);
        return  new String(decryptedBytes);
    }
    /**
     * Converts a Base64-encoded string into a SecretKey object.
     *
     * @param secretKeyBase64 The Base64-encoded secret key string
     * @return The SecretKey object
     */
    public static SecretKey getSecretKeyFromBase64String(String secretKeyBase64) {
        byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);

        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"); // stackoverflow
    }

    /**
     * Decodes a public key from its byte array representation.
     *
     * @param publicKeyBytes The byte array representing the public key
     * @return The decoded PublicKey object
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     * @throws InvalidKeySpecException  If the key specification is invalid
     */
    public static PublicKey decodePublicKey(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes)); // stackoverflow
    }

    /**
     * Encrypts the session key using RSA encryption with the provided public key.
     *
     * @param secretKey The session key to be encrypted
     * @param publicKey The public key used for encryption
     * @return The encrypted session key
     * @throws IllegalBlockSizeException  If the block size is illegal
     * @throws BadPaddingException        If the padding is bad
     * @throws NoSuchPaddingException    If the padding is not available
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException       If the public key is invalid
     */
    public static byte[] encryptSessionKeyWithPublicKey(SecretKey secretKey,PublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes =secretKey.getEncoded();
        Cipher cipher =Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return cipher.doFinal(bytes);
    }
    /**
     * Generates a new session key.
     *
     * @return The generated SecretKey object
     */
    public static SecretKey createSessionKey(){
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return keyGenerator.generateKey();
    }
    public static void main(String[] args) {
        try(Socket client = new Socket()) {
            client.connect(new InetSocketAddress(InetAddress.getLocalHost(),1234));
            Scanner readFromInput = new Scanner(System.in);
            Scanner readFromServer = new Scanner(client.getInputStream(), StandardCharsets.UTF_8);
            PrintWriter writeToServer = new PrintWriter(client.getOutputStream(),true,StandardCharsets.UTF_8);

            String publicKeyString =readFromServer.nextLine();
            PublicKey publicKey = decodePublicKey(Base64.getDecoder().decode(publicKeyString));

            SecretKey sessionKey = createSessionKey();
            byte[] encryptedSessionKeyWithPublicKey =encryptSessionKeyWithPublicKey(sessionKey,publicKey);
            writeToServer.println(Base64.getEncoder().encodeToString(encryptedSessionKeyWithPublicKey));

            while (true){
                System.out.print("> ");
                String request =readFromInput.nextLine();
                String encryptedRequest = encrypt(request,sessionKey);
                writeToServer.println(encryptedRequest);
                System.out.println("sent to server "+request+" encrypted as "+encryptedRequest);
                if (request.equalsIgnoreCase("quit")){
                    System.out.println("bye bye");
                    break;
                }
                String response = readFromServer.nextLine();
                String decryptedResponse = decrypt(response,sessionKey);
                System.out.println("read from server "+decryptedResponse+" decrypted as "+decryptedResponse);
            }

        }catch (IOException e){
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
