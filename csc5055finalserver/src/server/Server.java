package server;

import Sealed.ServerMessage;
import Sealed.SealedMessage;
import csc5055.Base32;
import csc5055.flatdb.FlatDatabase;
import csc5055.flatdb.Record;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.swing.JOptionPane;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as an object to represent the Server, processing messages
 * sent from the Client and responding with the appropriate action.
 * </pre>
 */
public class Server extends Thread
{
    private ServerSocket serverSocket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private final PasswordDatabase PASSWORD_DB;
    private final PrivateKey PRIV_KEY;
    private final PublicKey PUB_KEY;
    private final X509Certificate X509_CERTIFICATE;
    private Cipher rsaCipher, aesCipher;
    private Signature signature;
    private static final String RSA_SIGN_ALGO = "SHA256withRSA",
            RSA_ALGO = "RSA/ECB/PKCS1Padding", AES_ALGO = "AES/GCM/NoPadding";
    private final SecretKey CHATROOM_KEY;
    private final HashMap<Integer, SecretKey> KEY_MAP;
    private final HashMap<Integer, ConnectionThread> NEW_CONNECTION_POOL;
    private final static int TAG_LENGTH = 128;

    /**
     * Constructs a new Server object.
     *
     * @param port The port number to listen on.
     */
    public Server(int port)
    {
        // Load the Public/Private key pair.
        Key[] keys = loadKeys();
        PUB_KEY = (PublicKey) keys[0];
        PRIV_KEY = (PrivateKey) keys[1];

        // Load the certificate.
        X509_CERTIFICATE = loadCertificate();

        // Generate a new session key to distribute to clients.
        CHATROOM_KEY = genSessionKey();

        // Initialize the password database.
        PASSWORD_DB = new PasswordDatabase();
        KEY_MAP = new HashMap<>();
        NEW_CONNECTION_POOL = new HashMap<>();

        initCiphers();

        try
        {
            // Start the Server's Socket.
            serverSocket = new ServerSocket(port);
        } catch (IOException ex)
        {
            JOptionPane.showMessageDialog(null, "Unable to start server. "
                    + "\nReason: " + ex.getMessage());
        }
    }

    /**
     * This method accepts new connections to the server and creates a new 
     * ConnectionThread for that connection.
     */
    @Override
    public void run()
    {
        // Infinite loop to grab any messages sent over the socket.
        while (true)
        {
            try
            {
                // Accept the socket off the ServerSocket.
                Socket sock = serverSocket.accept();

                outputStream = new ObjectOutputStream(sock.getOutputStream());
                inputStream = new ObjectInputStream(sock.getInputStream());

                // Read the object from the inputStream.
                Object readObj = inputStream.readObject();

                if (((String) readObj).equals("DO_DH_KEX"))
                {
                    final int UUID = performDHKEX();
                    ConnectionThread newConnection
                            = new ConnectionThread(sock, inputStream,
                                    outputStream);
                    newConnection.start();

                    NEW_CONNECTION_POOL.put(UUID, newConnection);
                }

            } catch (IOException | ClassNotFoundException ex)
            {
                JOptionPane.showMessageDialog(null, "Unable to accept socket. "
                        + "\nReason: " + ex.getMessage());
                return;
            }
        }
    }

    /**
     * This method will generate a new IV using SecureRandom.
     *
     * @return IV
     */
    private byte[] genIV()
    {
        SecureRandom rand = new SecureRandom();
        // Create new 12-byte IV.
        final byte[] IV = new byte[12];

        rand.nextBytes(IV);

        return IV;
    }

    /**
     * This method initializes the ciphers needed for communication.
     */
    private void initCiphers()
    {
        try
        {
            rsaCipher = Cipher.getInstance(RSA_ALGO);
            aesCipher = Cipher.getInstance(AES_ALGO);
            signature = Signature.getInstance(RSA_SIGN_ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex)
        {
            System.err.println(ex.getMessage());
        }
    }

    /**
     * This method will generate a session key using an instance of AES,
     * throwing an exception if there is an error creating the key.
     *
     * @return The session key if no errors occur, else null.
     */
    private SecretKey genSessionKey()
    {
        try
        {
            // Return an instance of the key.
            return KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException ex)
        {
            System.err.println("Error creating session key. -> " + ex
                    .getMessage());
        }

        return null;
    }

    /**
     * This method performs a Diffie-Hellman Key Exchange with the server to
     * establish a SecretKey to use for communications prior to receiving the
     * Session Key.
     *
     * @return The ephemeral key for the Client and Server to communicate with.
     */
    private int performDHKEX()
    {
        SecretKey sharedKey = null;
        final int UUID = genUUID();

        try
        {
            KeyAgreement ecdhKex = KeyAgreement.getInstance("ECDH");
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            KeyPair keyPair = gen.genKeyPair();

            // Read the Client's Certificate and send the Server's Certificate.
            X509Certificate clientCert = (X509Certificate) inputStream
                    .readObject();
            outputStream.writeObject(X509_CERTIFICATE);
            
            // Read the message.
            byte[][] recvMessage = (byte[][]) inputStream.readObject();
            
            // Decrypt the ciphertext.
            String plainText = new String(decrypt(
                    recvMessage[0]));

            // If the signature and certificate verify, complete the KEX.
            if (verify(recvMessage[1], recvMessage[0], clientCert))
            {
                // Send the Server's Public Value.
                String[] splitMessage = plainText.split(":");
                final String NONCE = splitMessage[1];
                final String MESSAGE = Base64.getEncoder()
                        .encodeToString(keyPair.getPublic()
                        .getEncoded()) + ":" + NONCE;
                byte[] cText = encrypt(MESSAGE.getBytes(), clientCert
                        .getPublicKey());
                byte[] sign = sign(cText);
                outputStream.writeObject(new byte[][] {cText, sign});
                
                PublicKey pub = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(Base64
                                .getDecoder().decode(splitMessage[0])));

                // Start the exchange with the server's Private Value and then
                // doPhase with the Client's public Value.
                ecdhKex.init(keyPair.getPrivate());
                ecdhKex.doPhase(pub, true);

                // Use the first 16 bytes of the generate secret for a key.
                sharedKey = new SecretKeySpec(Arrays.copyOfRange(ecdhKex
                        .generateSecret(), 0, 16), "AES");
            }

        } catch (IOException | ClassNotFoundException | IllegalStateException
                | InvalidKeyException | NoSuchAlgorithmException
                | InvalidKeySpecException ex)
        {
            System.err.println("Error during DH-KEX -> " + ex.getMessage());
        }

        try
        {
            /* Generate a new, unique UUID and add it to the KEY_MAP. Also send 
            it to the user. */
            KEY_MAP.put(UUID, sharedKey);
            outputStream.writeObject(UUID);
        } catch (IOException ex)
        {
            System.err.println("Error sending UUID to client. -> " + ex
                    .getMessage());
        }

        return UUID;
    }

    /**
     * This method will generates a random integer that represents a UUID. It
     * checks the KEY_MAP's entries to make sure the return UUID is truly
     * unique.
     *
     * @return A unique UUID.
     */
    private int genUUID()
    {
        SecureRandom rand = new SecureRandom();

        boolean isUnique = false;
        
        /* While the generated number is not unique, generate a number and 
        check against the HashMap. */
        while (!isUnique)
        {
            final int UUID = rand.nextInt(999999);

            int count = 0;
            
            // A simple loop that checks the UUID against the Map's keys.
            for (Integer key : KEY_MAP.keySet())
                if (key != UUID)
                    count++;

            // If the count matches the size of the map, we have a unique #.
            if (count == KEY_MAP.size())
                return UUID;
        }
        
        return 999999;
    }

    /**
     * This method will retrieve the signature object from the factory, update
     * it and then sign the message.
     *
     * @param message The message to sign.
     * @return The signed message.
     */
    private byte[] sign(byte[] message)
    {
        assert (message != null);

        // An array for the result and a Signature object.
        byte[] sign = null;

        try
        {
            // Get the signature object from the factory.
            signature.initSign(PRIV_KEY);

            // Update the signature and sign the message.
            signature.update(message);
            sign = signature.sign();

        } catch (InvalidKeyException | SignatureException e)
        {
            System.err.println(e.getMessage());
        }

        return sign;
    }

    /**
     * This method will verify a certificate with a public key and initialize a
     * verified signature.
     *
     * @param message The message to verify.
     * @param expectedMsg The message to check against.
     * @param cert The X509 Certificate to use for checking the signature.
     * @return A boolean representing whether to signature verified or not.
     */
    private boolean verify(byte[] message, byte[] expectedMsg,
            X509Certificate cert)
    {
        boolean signOK = false;

        try
        {
            // Verify the certificate with it's own PublicKey.
            cert.verify(cert.getPublicKey());

            // Init the signature with the PublickKey and verify.
            signature.initVerify(cert.getPublicKey());
            signature.update(expectedMsg);
            signOK = signature.verify(message);
        } catch (CertificateException | NoSuchAlgorithmException
                | InvalidKeyException | NoSuchProviderException
                | SignatureException ex)
        {
            System.err.println("Error verifying message. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }

        return signOK;
    }

    /**
     * This method will encrypt a message using the private key.
     *
     * @param message The message to encrypt.
     * @param key The public key to use for encryption.
     * @return The ciphertext.
     */
    private byte[] encrypt(byte[] message, PublicKey key)
    {
        byte[] cipherText = null;

        try
        {
            // Initialize encryption with the private key.
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = rsaCipher.doFinal(message);
        } catch (InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException ex)
        {
            System.err.println("Error encrypting message. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }

        return cipherText;
    }

    /**
     * This method will decrypt the ciphertext into plaintext.
     *
     * @param cipherText The message to decrypt.
     * @return The plaintext.
     */
    private byte[] decrypt(byte[] cipherText)
    {
        try
        {
            // Initialize decryption with a certificate.
            rsaCipher.init(Cipher.DECRYPT_MODE, PRIV_KEY);
            return rsaCipher.doFinal(cipherText);
        } catch (InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException ex)
        {
            System.err.println("Unable to decrypt ciphertext. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }

        return null;
    }

    /**
     * This method reads the certificate from the project directory and returns
     * a new X508EncodedKeySpec Object.
     */
    private X509Certificate loadCertificate()
    {
        X509Certificate cert = null;

        try
        {
            // New instance of an X509 from CertificateFactory
            cert = (X509Certificate) CertificateFactory
                    .getInstance("X509").generateCertificate(
                    new FileInputStream("serverx509.cert"));
        } catch (CertificateException | FileNotFoundException ex)
        {
            System.err.println("Unable to read server's certificate. -> "
                    + ex.getMessage());
        }

        return cert;
    }

    /**
     * This method will create a new thread and post the sealed message to the
     * thread.
     *
     * @param msg The {@code SealedMessage} to post to all Clients.
     */
    private void postToAll(SealedMessage msg)
    {
        for (Integer i : NEW_CONNECTION_POOL.keySet())
        {
            ConnectionThread thread = NEW_CONNECTION_POOL.get(i);
            if (thread.getStage() == 1)
            {
                thread.post(msg);
            }
        }
    }

    /**
     * This method will process a server message as an array
     *
     * @param msg The ServerMessage to process.
     * @param key The SecretKey to use.
     * @param sendStream The ObjectOutputStream to write to.
     * @param msgUUID The UUID.
     * @throws server.ExceptionFactory.VerificationException If the message 
     * fails to verify.
     */
    private void processMessage(ServerMessage msg, SecretKey key,
            ObjectOutputStream sendStream, int msgUUID)
            throws ExceptionFactory.VerificationException
    {
        assert (msg != null);

        // Get the message as an array.
        String[] msgArray = msg.toArray();
        final int NONCE = msg.getNonce();
        final byte[] iv = genIV();

        try
        {
            // Init the Cipher for encryption.
            aesCipher.init(Cipher.ENCRYPT_MODE, key,
                    new GCMParameterSpec(TAG_LENGTH, iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex)
        {
            System.err.println("Error initializing RSA Cipher for decryption. "
                    + "-> " + ex.getMessage());
        }

        switch (msgArray[0])
        {
            case "SAMPLE_OTP":
                try
                {
                    // Generate an OTP and send it to the user's email.
                    final int OTP = sampleOTP(PasswordDatabase
                            .getTOTPKey());
                    EmailProvider.sendEmail(msgArray[1], "Your OTP is: ", OTP);

                    // Send a message back to the socket with the OTP.
                    sendStream.writeObject(new SealedMessage(
                            new ServerMessage(String.valueOf(OTP),
                                    NONCE), aesCipher, 0, iv));
            } catch (NoSuchAlgorithmException | IOException
                    | IllegalBlockSizeException ex)
            {
                System.err.println("Unable to generate OTP. -> " + ex
                        .getMessage());
            }
            break;
            case "EXISTING_SAMPLE_OTP":
                try
                {
                    /* If the user has an account with the specified 
                    username/email, get their OTP. */
                    if (PASSWORD_DB.authenticateUser(msgArray[1],
                            msgArray[2]))
                    {
                        // Get the OTP using the user's TOTP Key and send it.
                        final int OTP = sampleOTP(PasswordDatabase
                                .getTOTPKey());
                        EmailProvider.sendEmail(msgArray[1], "Your OTP is: ",
                                OTP);
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("VALID:" + OTP, NONCE),
                                aesCipher, 0, iv));
                    } else
                    {
                        // Write a message saying the request was invalid.
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("INVALID", NONCE),
                                aesCipher, 0, iv));
                    }
            } catch (IOException | IllegalBlockSizeException
                    | NoSuchAlgorithmException ex)
            {
                System.err.println("Error while writing OTP message to "
                        + "server. -> " + ex.getMessage());
            }
            break;
            // Enroll a user
            case "ENROLL":              
                try
                {
                    boolean res = PASSWORD_DB.enrollUser(msgArray[1],
                            msgArray[2], msgArray[3]);
                    // Determine success of enrollment
                    if (res)
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("SUCCESS", NONCE),
                                aesCipher, 0, iv));
                    } else
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE),
                                aesCipher, 0, iv));
                    }
            } catch (IOException | IllegalBlockSizeException ex)
            {
                System.err.println("Error while enrolling user into "
                        + "database. -> " + ex.getMessage());
            }
            break;
            case "RESET":
                try
                {
                    // Determine success for a password change.
                    if (PASSWORD_DB.changePassword(msgArray[1], msgArray[2]))
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("SUCCESS", NONCE),
                                aesCipher, 0, iv));
                    } else
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE), aesCipher,
                                0, iv));
                    }
                } catch (ExceptionFactory.NoSuchUserException ex)
                {
                    try
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE), aesCipher,
                                0, iv));
                    } catch (IOException | IllegalBlockSizeException ex1)
                    {
                        System.err.println("Error while resetting user's "
                                + "password. "
                            + "-> " + ex1.getMessage());
                        ex1.printStackTrace();
                    }
                } catch (IOException | IllegalBlockSizeException ex)
                {
                    System.err.println("Error while resetting user's password. "
                            + "-> " + ex.getMessage());
                    ex.printStackTrace();
                }
            break;
            case "KEY_REQ":
                try
                {
                    if (PASSWORD_DB.authenticateUser(msgArray[1], msgArray[2]))
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage(Base64.getEncoder().
                                        encodeToString(CHATROOM_KEY.getEncoded()),
                                        NONCE), aesCipher, 0, iv));
                    } else
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE),
                                aesCipher, 0, iv));
                    }
            } catch (IOException | IllegalBlockSizeException ex)
            {
                System.err.println("Error sending session key to user. -> "
                        + "" + ex.getMessage());
            }

            NEW_CONNECTION_POOL.get(msgUUID).setStage(1);
            break;
            case "GET_USERNAME":
                final String USERNAME = PASSWORD_DB.getUsername(msgArray[1],
                        msgArray[2]);

                try
                {
                    if (USERNAME != null)
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage(USERNAME, NONCE),
                                aesCipher, 0, iv));
                    } else
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE), aesCipher,
                                0, iv));
                    }
                } catch (IOException | IllegalBlockSizeException ex)
                {
                    System.err.println("Error sending session key to user. -> "
                            + "" + ex.getMessage());
                }
                break;
            case "VERIFY_ACCOUNT":
                try
                {
                    if (PASSWORD_DB.authenticateUser(msgArray[1], msgArray[2]))
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("SUCCESS", NONCE),
                                aesCipher, 0, iv));
                    } else
                    {
                        sendStream.writeObject(new SealedMessage(
                                new ServerMessage("FAILED", NONCE),
                                aesCipher, 0, iv));
                    }
            } catch (IOException | IllegalBlockSizeException ex)
            {
                System.err.println("Error verifying user's account. -> "
                        + "" + ex.getMessage());
            }

            break;
            default:
                throw ExceptionFactory
                        .getVerificationException("Unknown Message Type!");
        }
    }

    /**
     * <pre>
     * This method loads the KeyStore and Private/Public key pairs from the
     * user's specified file location or user directory.
     *
     * CODE REFERENCED FROM: <a href = "http://tutorials.jenkov.com/java-
     * cryptography/keystore.html">WEBSITE</a>
     *
     * </pre>
     *
     * @return An array containing the Public and Private key pair.
     */
    private Key[] loadKeys()
    {
        // Constants needed for loading the keystore.
        final String SERVER_PWD = "server123", ALIAS = "server",
                TRUSTSTORE = "servertruststore.jks",
                KEYSTORE = "serverkeystore.jks";

        KeyStore keyStore = null;

        try
        {
            // Load the keystore, printing and loggin if an exception is thrown.
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream keyStoreData = new FileInputStream(KEYSTORE);
            keyStore.load(keyStoreData, SERVER_PWD.toCharArray());

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException
                | CertificateException ex)
        {
            System.err.println("Unable to load keystore. -> " + ex
                    .getMessage());
            JOptionPane.showMessageDialog(null, "Unable to start program. "
                    + "Please try again.");
            System.exit(0);
        }

        try
        {
            // Set the truststore property.
            System.setProperty("javax.net.ssl.trustStore", TRUSTSTORE);
            System.setProperty("javax.net.ssl.trustStorePassword", SERVER_PWD);
        } catch (Exception ex)
        {
            System.err.println("Unable to load truststore. -> " + ex
                    .getMessage());
        }

        PublicKey pubKey = null;
        PrivateKey privKey = null;

        try
        {
            // Attempt to load the Public and Private keys from the keystore. 
            privKey = ((KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS,
                    new KeyStore.PasswordProtection(SERVER_PWD.toCharArray())))
                    .getPrivateKey();
            pubKey = keyStore.getCertificate(ALIAS).getPublicKey();
        } catch (KeyStoreException | NoSuchAlgorithmException
                | UnrecoverableEntryException ex)
        {
            System.err.println("Error loading Private/Public Key. -> " + ex
                    .getMessage());
        }

        // Build a new array to hold the keys and return it.
        return new Key[]
        {
            pubKey, privKey
        };
    }

    /**
     * This method calculates a Time Based One Time Password by using HOTP with
     * a state.
     *
     * @param hmacKey The HMAC-SHA1 Key.
     * @return An integer representing the One Time Password.
     */
    private int sampleOTP(String hmacKey)
    {
        return new OneTimePassword(hmacKey).getOTP();
    }

    /**
    * <pre>
    * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
    * Course: CSC5055 - Network Security 1
    * Due Date: May 11, 2021 @ 11:30am
    *
    * This class serves an object to obtain a OneTimePassword.
    * </pre>
    */
    private final class OneTimePassword
    {

        private final byte[] HMAC_KEY;

        /**
         * Constructor which creates a new OneTimePassword with an SHA1-HMAC 
         * key.
         * 
         * @param hmacKey the SHA1-HMAC key. 
         */
        public OneTimePassword(String hmacKey)
        {
            HMAC_KEY = Base32.decode(hmacKey);
        }

        /**
         * This method calculates a Time Based One Time Password by using HOTP
         * with a state.
         *
         * @param hmacKey The HMAC-SHA1 Key.
         * @return An integer representing the One Time Password.
         */
        private int getOTP()
        {
            /* Get the time since January 1, 1970 in milliseconds and calculate 
           the state. */
            long state = (long) Math.floor(Instant.now().getEpochSecond() / 30);

            return hotp(longToBytes(state));
        }

        /**
         * This method calculates a one time password by using HOTP.
         *
         * @param hmacKey The HMAC-SHA1 key.
         * @param sinceEpoch The time since the Unix Epoch (January 1, 1970 @
         * 12AM).
         * @return An integer representing the OTP.
         */
        private int hotp(byte[] sinceEpoch)
        {
            // A key for signing.
            SecretKeySpec signKey = new SecretKeySpec(HMAC_KEY, "HmacSHA1");

            // Sign the byte array.
            byte[] hash = null;

            try
            {
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(signKey);
                hash = mac.doFinal(sinceEpoch);
            } catch (NoSuchAlgorithmException | InvalidKeyException e)
            {
                System.err.println("No Such Algorithm Exception");
            }

            // Pack the hash into a 4-bit integer.
            int shiftIdx = hash[19] & 0xF;

            // Pack the bytes into an integer.
            int result;

            result = (hash[shiftIdx] & 0x7F) << 24;
            result = result | ((hash[shiftIdx + 1] & 0xff) << 16);
            result = result | ((hash[shiftIdx + 2] & 0xff) << 8);
            result = result | (hash[shiftIdx + 3] & 0xff);

            return (result % 1000000);
        }

        /**
         * This method converts a long value into an 8-byte value .
         *
         * @author Zach Kissel - Code copied from Google Classroom (Problem Set
         * 5)
         * @param num the number to convert to bytes .
         * @return an array of 8 bytes representing the number num.
         */
        private byte[] longToBytes(long num)
        {
            byte[] res = new byte[8];

            // Decompose the a long type into byte components .
            for (int i = 7; i >= 0; i--)
            {
                res[i] = (byte) (num & 0xFF);
                num >>= 8;
            }

            return res;
        }
    }

    /**
    * <pre>
    * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
    * Course: CSC5055 - Network Security 1
    * Due Date: May 11, 2021 @ 11:30am
    *
    * This class serves as an object to hold the database of passwords. It uses 
    * a FlatDatabase object to manage users.
    * </pre>
    */
    private static final class PasswordDatabase
    {

        /**
         * The cost (size).
         */
        private static final int COST = 2048;

        /**
         * The Block Size.
         */
        private static final int BLK_SIZE = 8;

        /**
         * The parallelization
         */
        private static final int PARALLELIZATION = 1;

        /**
         * The key size.
         */
        private static final int KEY_SIZE = 128;

        /**
         * An object to hold the ScryptKey.
         */
        private static ScryptKeySpec scryptSpec;

        /**
         * A FlatDatabase object.
         */
        private static final FlatDatabase FLAT_DB = new FlatDatabase();

        /**
         * An array to hold the field names in the database.
         */
        private static final String[] FIELD_NAMES = {"USERNAME", "EMAIL",
            "SALT", "HASH", "TOTP_KEY"};

        /**
         * Default Constructor. Checks the integrity of the database before
         * allowing any operations to be performed.
         */
        public PasswordDatabase()
        {
            checkDB();
        }

        /**
         * This method checks to see if the database file exists. If it does
         * not, it is created.
         */
        private void checkDB()
        {
            // A temp file for the password.db file.
            File tempFile = new File("password.db");

            // Check if the file exists and if it doesn't, create it.
            if (tempFile.exists())
            {
                FLAT_DB.openDatabase(tempFile.getName());
            } else
            {
                FLAT_DB.createDatabase(tempFile.getName(), FIELD_NAMES);
            }

        }

        /**
         * This method uses a database record to authenticate a user.
         *
         * @param usernameOrEmail The username or email address.
         * @param password The password to authenticate.
         * @return result of the compared hash to the salt and password
         */
        public boolean authenticateUser(String usernameOrEmail,
                String password)
        {
            int result = checkType(usernameOrEmail);

            // Lookup the record from the database.
            Record dbRecord = FLAT_DB.lookupRecord(FIELD_NAMES[result],
                    usernameOrEmail);

            /* Return the result of comparing the hash and the hash of the 
            password and salt. */
            return (dbRecord != null) ? dbRecord
                    .getFieldValue("HASH").equals(Base64.getEncoder()
                    .encodeToString(hash(password, Base64.getDecoder()
                            .decode(dbRecord.getFieldValue("SALT"))))) : false;
        }

        /**
         * This method will enroll a user by creating a new record with their
         * information and adding it to a database.
         *
         * @param username The username to set.
         * @param emailAddress The email address to set.
         * @param password The password to set.
         * @return A boolean representing whether or not the operation was 
         * successful.
         */
        public boolean enrollUser(String username, String emailAddress,
                String password)
        {
            // Generate a uniformly random salt.
            byte[] salt = generateSalt();

            String[] arr = null;

            try
            {
                /* Create an array to hold the username, email, salt, hash and 
                TOTP key.*/
                arr = new String[]{emailAddress, username, Base64.getEncoder()
                    .encodeToString(salt), Base64.getEncoder()
                    .encodeToString(hash(password, salt)), getTOTPKey()};

            } catch (NoSuchAlgorithmException ex)
            {
                System.err.println("Unable to generate TOTP Key. Reason: " + ex
                        .getMessage());
            }

            // Insert the new record into the database and return the result.
            boolean result = FLAT_DB.insertRecord(new Record(FIELD_NAMES, arr));

            FLAT_DB.saveDatabase();

            return result;
        }

        /**
         * This method will allow a user to change their password using the
         * database record previously created.
         *
         * @param email The email address.
         * @param newPassword The new password to set.
         * @return a new record in the database holding the new password
         * @throws NoSuchUserException if passwords do not match
         */
        public boolean changePassword(String email, String newPassword)
                throws ExceptionFactory.NoSuchUserException
        {
            Record dbRecord = FLAT_DB.lookupRecord(FIELD_NAMES[1], email);
            
            if (dbRecord == null)
            {
                throw ExceptionFactory.getNoSuchUserException("Database does "
                        + "not have entry to match that username.");
            } else
            {
                dbRecord.setField("HASH", Base64.getEncoder()
                        .encodeToString(hash(newPassword, Base64.getDecoder()
                        .decode(dbRecord.getFieldValue("SALT")))));
            }

            boolean result = FLAT_DB.insertRecord(dbRecord);

            FLAT_DB.saveDatabase();

            return result;
        }

        /**
         * This method will retrieve a TOTP key from the database.
         *
         * @param usernameOrEmail The username or email address.
         * @param password The user's password.
         * @return the users TOTP key as a 32-bit string
         */
        public String getUserTOTPKey(String usernameOrEmail,
                String password)
        {
            final int RESULT = checkType(usernameOrEmail);

            // Lookup the record from the database.
            Record dbRecord = FLAT_DB.lookupRecord(FIELD_NAMES[RESULT],
                    usernameOrEmail);

            /* If the dbRecord isn't null and the user authenticates, return 
            the user's TOTP_KEY as a Base-32 String. */
            return (dbRecord == null && authenticateUser(dbRecord
                    .getFieldValue("USERNAME"), password)) ? null : dbRecord
                    .getFieldValue("TOTP_KEY");
        }

        /**
         * This method retrieves a username from the database
         *
         * @param email The email address.
         * @param password The password.
         * @return username value from database
         */
        public String getUsername(String email, String password)
        {
            assert (email != null) && (!email.equals("")) && (password != null)
                    && (!password.equals(""));
            //If email is found, retrieve username from database
            if (authenticateUser(email, password))
            {
                Record dbRecord = FLAT_DB.lookupRecord("EMAIL", email);
                return dbRecord.getFieldValue("USERNAME");
            } else
            {
                return null;
            }
        }

        /**
         * This method gets the TOTPKey in a Base32 String format.
         *
         * @return A String representing the TOTP Key.
         * @throws NoSuchAlgorithmException If "HmacSHA1" is an invalid
         * algorithm.
         */
        public static String getTOTPKey() throws NoSuchAlgorithmException
        {
            byte[] keyMaterial = KeyGenerator.getInstance("HmacSHA1")
                    .generateKey().getEncoded();

            return Base32.encodeToString(keyMaterial, true);
        }

        /**
         * This method hashes a salt and password together using SCRYPT.
         *
         * @param password The password the user entered.
         * @param salt The salt to hash with the password.
         * @return A byte representation of the hashed password and salt.
         */
        private static byte[] hash(String password, byte[] salt)
        {
            // Add the Bouncy Castle Provider.
            Security.addProvider(new BouncyCastleProvider());

            // The ScriptKeySpec object.
            scryptSpec = new ScryptKeySpec(password.toCharArray(), salt, COST,
                    BLK_SIZE, PARALLELIZATION, KEY_SIZE);

            SecretKey key = null;

            try
            {
                // Create the new SecretKey object.
                key = SecretKeyFactory.getInstance("SCRYPT")
                        .generateSecret(scryptSpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e)
            {
                System.err.println("Error creating Secret Key from password."
                        + e.getMessage());
                e.printStackTrace();
            }

            return key.getEncoded();
        }

        /**
         * This method generates a salt or IV uniformly at random using Java's
         * SecureRandom object.
         *
         * @return A random 16-bit byte array.
         */
        private static byte[] generateSalt()
        {
            SecureRandom rand = new SecureRandom();
            byte[] salt = new byte[16];
            rand.nextBytes(salt);

            return salt;
        }

        private static int checkType(String usernameOrEmail)
        {
            Pattern pattern = Pattern.compile(".*@");
            Matcher matcher = pattern.matcher(usernameOrEmail);

            /* Return 1 if the match was found, so this was an email. Return 0
             if the match was not found, which matches the indicies of 
            FIELD_NAMES. */
            return (matcher.find()) ? 1 : 0;
        }
    }

    /**
    * <pre>
    * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
    * Course: CSC5055 - Network Security 1
    * Due Date: May 11, 2021 @ 11:30am
    *
    * This class serves as an object that gets added to the thread pool to hold
    * a client's connection streams. It allows for receiving messages and 
    * sending messages.
    * </pre>
    */
    private final class ConnectionThread extends Thread
    {

        private ObjectInputStream input;
        private ObjectOutputStream output;
        private final Socket SOCK;
        private int stage;

        /**
         * Create a new connection thread
         *
         * @param socket The socket the user is connected on.
         * @param input The ObjectInputStream.
         * @param output The ObjectOutputStream
         */
        public ConnectionThread(Socket socket, ObjectInputStream input,
                ObjectOutputStream output)
        {
            SOCK = socket;
            this.input = input;
            this.output = output;
            this.stage = 0;
        }

        /**
         * Getter method for the socket
         *
         * @return The user's socket.
         */
        public Socket getSocket()
        {
            return SOCK;
        }

        /**
         * Getter method for the stage
         *
         * @return The current stage of the thread.
         */
        public int getStage()
        {
            return stage;
        }

        /**
         * Set method for the stage
         *
         * @param stage The stage to set.
         */
        public void setStage(int stage)
        {
            this.stage = stage;
        }

        @Override
        /**
         * This method runs an infinite loop that searches for a message from
         * the Client. It then processes it.
         */
        public void run()
        {
            while (true)
            {
                try
                {
                    Object readObj = input.readObject();
                    /* If the message received is a String, we are removing it
                    from the Thread Pools. */
                    if (readObj instanceof String)
                    {
                        if (((String) readObj).split(":")[0]
                                .equals("REMOVE_UUID"))
                        {
                            final int UUID = Integer.valueOf(((String) readObj)
                                    .split(":")[1]);
                            KEY_MAP.remove(UUID);
                            NEW_CONNECTION_POOL.remove(UUID);
                        }
                        return;
                    } else
                    {
                        try
                        {
                            SealedMessage recvMsg = (SealedMessage) readObj;
                            int msgUUID = recvMsg.getUUID();

                            if (recvMsg.getType() == 0)
                            {
                                /* Init the cipher with the correct key based on
                                the UUID. */
                                SealedMessage recvSealed
                                        = (SealedMessage) readObj;
                                aesCipher.init(Cipher.ENCRYPT_MODE, KEY_MAP
                                        .get(msgUUID),
                                        new GCMParameterSpec(TAG_LENGTH,
                                                recvSealed.getIV()));
                                ServerMessage recvServerMsg = (ServerMessage) 
                                        recvSealed.getObject(aesCipher);

                                try
                                {
                                    processMessage(recvServerMsg, KEY_MAP
                                            .get(msgUUID), output,
                                            msgUUID);
                                } catch (ExceptionFactory.VerificationException 
                                        ex)
                                {
                                    System.err.println("Unable to verify "
                                            + "ServerMessage. -> " + ex
                                                    .getMessage());
                                    ex.printStackTrace();
                                }
                            } else
                            {
                                postToAll((SealedMessage) readObj);

                            }
                        } catch (IOException | ClassNotFoundException
                                | IllegalBlockSizeException
                                | BadPaddingException | InvalidKeyException
                                | InvalidAlgorithmParameterException e)
                        {
                            System.err.println("Error decrypting message. -> "
                                    + e.getMessage());

                        }
                    }
                } catch (IOException | ClassNotFoundException ex)
                {
                    System.err.println("Error reading message from Client. -> "
                            + ex.getMessage());
                    ex.printStackTrace();
                }
            }
        }

        /**
         * This method will post a sealed message to the output stream
         *
         * @param msg The SealedMessage to send to the client.
         */
        public void post(SealedMessage msg)
        {
            try
            {
                output.writeObject(msg);
                output.flush();
            } catch (IOException ex)
            {
                System.err.println("Unable to post message to thread.");
            }
        }
    }
}
