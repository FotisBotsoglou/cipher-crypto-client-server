package serverPack;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * CryptoCipherServer class implements a server capable of encrypted communication with clients using AES encryption.
 */
public class CryptoCipherServer {
    /**
     * Generates a self-signed X.509 certificate.
     *
     * @param keyPair    Key pair used for signing the certificate
     * @param subjectDN  Subject distinguished name for the certificate
     * @return           The self-signed X.509 certificate
     * @throws OperatorCreationException  If an error occurs during certificate creation
     * @throws CertificateException       If an error occurs during certificate handling
     * @throws IOException                If an I/O error occurs
     */
    // stackoverflow: https://stackoverflow.com/questions/29852290/self-signed-x509-certificate-with-bouncy-castle-in-java
    // https://www.youtube.com/watch?v=zZdSNEyMsV8&list=PLLMmbOLFy25GFF3fWoiJ56nM8Kqgr_Qe2&index=185 Psounis Java
    public static Certificate selfSign(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

        Date endDate = calendar.getTime();

        String signatureAlgorithm = "SHA1withRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        // Extensions --------------------------

        // Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }
    /**
     * Retrieves the KeyStore from a local file.
     *
     * @return The KeyStore loaded from the file
     * @throws FileNotFoundException    If the keystore file is not found
     */
    public static KeyStore getLocalKeyStore() throws FileNotFoundException {
        KeyStore keyStore = null;
        try {
            keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
        }catch (KeyStoreException e){
            e.printStackTrace();
        }

        try(InputStream in = new FileInputStream("keystore.ks")) {
            keyStore.load(in, "kspassword".toCharArray());
        }catch (FileNotFoundException exc){
            throw exc;
        }catch (IOException| CertificateException | NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return keyStore;
    }

    /**
     * Creates a new KeyStore.
     *
     * @return The newly created KeyStore
     */
    public static KeyStore createKeyStore(){
        KeyStore keyStore = null;
        try {
            keyStore =KeyStore.getInstance(KeyStore.getDefaultType());
        }catch (KeyStoreException e){
            e.printStackTrace();
        }
        try(OutputStream out = new FileOutputStream("keystore.ks")) {
            keyStore.load(null,null);
            keyStore.store(out,"kspassword".toCharArray());
        }catch (IOException|NoSuchAlgorithmException|KeyStoreException|CertificateException e){
            e.printStackTrace();
        }
        return keyStore;
    }
    /**
     * Saves the KeyStore to a local file.
     *
     * @param keyStore The KeyStore to be saved
     */
    public static void saveKeyStore(KeyStore keyStore){
        try(OutputStream out = new FileOutputStream("keystore.ks")) {
            keyStore.store(out,"kspassword".toCharArray());
        }catch (IOException|KeyStoreException|CertificateException|NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    /**
     * Creates a new RSA key pair.
     *
     * @return The generated RSA key pair
     */

    public static KeyPair createKeyPair(){
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        KeyPair keyPair= keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * Stores a KeyPair in the KeyStore under a specified alias.
     *
     * @param keyStore         The KeyStore to store the KeyPair
     * @param keyPair          The KeyPair to be stored
     * @param privateKeyName   The alias under which the private key is stored
     * @param privateKeyPassword The password to protect the private key entry in the KeyStore
     */
    public static void storeKeyPair(KeyStore keyStore,KeyPair keyPair,String privateKeyName,String privateKeyPassword){
        Certificate cert = null;
        try {
            String subjectDN = "CN=F Bots," +
                    "SURNAME=Bots," +
                    "SERIALNUMBER=716181-9876," +
                    "C=SE," +
                    "DC=bot.com";
            cert = selfSign(keyPair, subjectDN);
        } catch (OperatorCreationException | IOException | CertificateException e) {
            e.printStackTrace();
        }
        KeyStore.PrivateKeyEntry privateKeyEntry =new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),new Certificate[]{cert});
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(privateKeyPassword.toCharArray());

        try {
            keyStore.setEntry(privateKeyName,privateKeyEntry,protection);
        }catch (KeyStoreException e){
            e.printStackTrace();
        }
    }

    /**
     * Loads the PrivateKey from the KeyStore.
     *
     * @param keyStore           The KeyStore containing the private key entry
     * @param privateKeyName     The alias under which the private key is stored
     * @param privateKeyPassword The password to retrieve the private key entry from the KeyStore
     * @return The PrivateKey loaded from the KeyStore
     */
    public static PrivateKey loadPrivateKey(KeyStore keyStore,String privateKeyName,String privateKeyPassword){
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(privateKeyPassword.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry =(KeyStore.PrivateKeyEntry) keyStore.getEntry(privateKeyName,protection);
        }catch (NoSuchAlgorithmException|UnrecoverableEntryException|KeyStoreException e){
            e.printStackTrace();

        }
        return privateKeyEntry.getPrivateKey();
    }
    /**
     * Loads the Certificate from the KeyStore.
     *
     * @param keyStore           The KeyStore containing the certificate entry
     * @param privateKeyName     The alias under which the certificate is stored
     * @param privateKeyPassword The password to retrieve the certificate entry from the KeyStore
     * @return The Certificate loaded from the KeyStore
     */
    public static Certificate loadCertificate(KeyStore keyStore,String privateKeyName,String privateKeyPassword){
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(privateKeyPassword.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry =(KeyStore.PrivateKeyEntry) keyStore.getEntry(privateKeyName,protection);
        }catch (NoSuchAlgorithmException|UnrecoverableEntryException|KeyStoreException e){
            e.printStackTrace();

        }
        return privateKeyEntry.getCertificate();
    }
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
        byte[] bytes =text.getBytes();
        Cipher cipher =Cipher.getInstance("AES");
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
     * Decrypts the given encrypted secret key using RSA decryption with the provided private key.
     *
     * @param secretKeyEncrypted The encrypted secret key
     * @param privateKey         The private key used for decryption
     * @return The decrypted SecretKey
     * @throws NoSuchPaddingException    If the padding is not available
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException       If the private key is invalid
     * @throws IllegalBlockSizeException If the block size is illegal
     * @throws BadPaddingException       If the padding is bad
     */
    public static SecretKey decodeSecretKey(byte[] secretKeyEncrypted, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(secretKeyEncrypted);
        return new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "AES"); // stackoverflow
    }

    public static void main(String[] args) {
        KeyStore keyStore;
        PrivateKey privateKey;
        Certificate certificate;
        try {
            keyStore =getLocalKeyStore();
            privateKey =loadPrivateKey(keyStore,"nameforprivatekey","pkpassword");
            certificate = loadCertificate(keyStore,"nameforprivatekey","pkpassword");
        } catch (FileNotFoundException e){
            keyStore= createKeyStore();
            KeyPair keyPair =createKeyPair();
            privateKey =keyPair.getPrivate();
            storeKeyPair(keyStore,keyPair,"nameforprivatekey","pkpassword");
            saveKeyStore(keyStore);
            certificate = loadCertificate(keyStore,"nameforprivatekey","pkpassword");
        }

        try(ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.bind(new InetSocketAddress(1234));
            Socket server = serverSocket.accept();
            Scanner readFromClient = new Scanner(server.getInputStream(), StandardCharsets.UTF_8);
            PrintWriter writeToClient = new PrintWriter(server.getOutputStream(),true,StandardCharsets.UTF_8);

            PublicKey publicKey = certificate.getPublicKey();
            writeToClient.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            String secretKeyString = readFromClient.nextLine();
            SecretKey sessionKey = decodeSecretKey(Base64.getDecoder().decode(secretKeyString),privateKey );

            while (true) {
                try {
                    String encryptedText = readFromClient.nextLine();
                    String decryptedText = decrypt(encryptedText, sessionKey);
                    System.out.println("Read from Client decrypted Text: " + decryptedText + " from encrypted Text: " + encryptedText);
                    if (decryptedText.equalsIgnoreCase("quit")) {
                        System.out.println("Client is done.");
                        break;
                    }
                    String response = "<Server Echoing " + decryptedText + ">";
                    String encryptedResponse = encrypt(response, sessionKey);
                    writeToClient.println(encryptedResponse);
                    System.out.println("sent to client response: " + response + " encrypted as " + encryptedResponse);
                }catch (NoSuchElementException e){
                    break;
                }
            }
        }catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e){
            e.printStackTrace();
        }
    }
}
