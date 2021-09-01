package client;

import Sealed.ServerMessage;
import Sealed.SealedMessage;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.JFrame;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 * 
 * This class serves as the login frame for the GUI and handles most of the
 * communication with the server.
 * </pre>
 */
public class LoginFrame extends JFrame
{
    private final static GridBagConstraints GBC = new GridBagConstraints();
    private int offset;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private JButton connectButton, createAccountButton, forgotPasswordButton, 
            loginButton;
    private JLabel connectionStatusLabel, passwordLabel, ipAddressLabel, 
            headerLabel, emailUsernameLabel, portNumberLabel;
    private JTextField emailField, portNumberField, ipAddressField;
    private JPasswordField passwordField;
    
    private Socket socket;
    private final X509Certificate X509_CERTIFICATE;
    private final PrivateKey PRIV_KEY;
    private final PublicKey PUB_KEY;
    private SecretKey clientServerKey;
    private Cipher rsaCipher, aesCipher;
    private Signature signature;
    private static final String RSA_SIGN_ALGO = "SHA256withRSA",
            RSA_ALGO = "RSA/ECB/PKCS1Padding", AES_ALGO = "AES/GCM/NoPadding";
    private int UUID;
    private final static int TAG_LENGTH = 128;
    
    /**
     * Constructor which loads the appropriate keys, certificates, ciphers,  
     * and enable to correct Swing components.
     */
    public LoginFrame()
    {
        // Call the super class and initialize the swing components.
        super("Welcome to ChatterBox");
        
        // Load the certificate.
        X509_CERTIFICATE = loadCertificate();
        
        // Init the Cipher and Signature object.
        initCipher();
        
        // Load the Public/Private key pair.
        Key[] keyPair = loadKeys(); 
        PUB_KEY = (PublicKey) keyPair[0];
        PRIV_KEY = (PrivateKey) keyPair[1];
        
        // Add a listener to remove the user from the server when closing.
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (outputStream != null)
                    try
                    {
                        outputStream.writeObject("REMOVE_UUID:" + UUID);
                    } catch (IOException ex)
                    {
                        System.err.println("Error writing remove message to "
                                + "server.");
                    }
                System.exit(0);
            }
        });
        
        // Set the icon for the program.
        setIconImage(new ImageIcon("logo.png").getImage());
        
        // Initialize the components needed for the GUI.
        initComponents();
        
        // Disable the components that are not needed until the client connects.
        disableComponents();
        
        // Center the frame in the screen.
        setLocationRelativeTo(null);
        setVisible(true);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        validate();
    }

    /**
     * This method reads the certificate from the project directory
     * and returns a new X508EncodedKeySpec Object.
     */
    private X509Certificate loadCertificate()
    {
        // Set the cert to null.
        X509Certificate cert = null;
        
        try
        {
            // Set the cert to the clientsx509 cert.
            cert = (X509Certificate) CertificateFactory
                    .getInstance("X509").generateCertificate(
                            new FileInputStream("clientx509.cert"));
        } catch (CertificateException | FileNotFoundException ex)
        {
            System.err.println("Unable to read user's certificate. -> " + ex
                    .getMessage());
        }
        
        return cert;
    }
    
    /**
     * This method initializes a cipher for RSA encryption and a signature 
     * object for signing.
     */
    private void initCipher()
    {
        try
        {
            // Set the rsaCipher using the RSA_ALGO.
            rsaCipher = Cipher.getInstance(RSA_ALGO);
            // Set the signature using the RSA_SIGN_ALGO.
            signature = Signature.getInstance(RSA_SIGN_ALGO);
            // Set the aesCipher using the AES_ALGO.
            aesCipher = Cipher.getInstance(AES_ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex)
        {
            System.err.println("Unable to create cipher. -> " + ex
                    .getMessage());
        }
    }
    
    /**
     * This method builds the SSLSocket needed to communicate with the server.
     * 
     * @throws IOException If there is an Input/Output error while initializing. 
     */
    private void buildSocket() throws IOException
    {
        // Create the new socket using the ip and the port provided.
        socket = new Socket(ipAddressField.getText(), Integer
                .valueOf(portNumberField.getText()));

        // Set the inputStream.
        inputStream = new ObjectInputStream(socket.getInputStream());
        // Set the outputStream.
        outputStream = new ObjectOutputStream(socket.getOutputStream());
    }
    
    /**
     * This method disables the Swing components that are not needed until the 
     * user connects to the server.
     */
    private void disableComponents()
    {
        // Set the connection to not visible.
        connectionStatusLabel.setVisible(false);
        
        // Disable the loginButton.
        loginButton.setEnabled(false);
        // Disable the email and username field.
        emailField.setEnabled(false);
        // Disable the passsword field.
        passwordField.setEnabled(false);
        // Disable the create account button.
        createAccountButton.setEnabled(false);
        // Disable the forgot password button.
        forgotPasswordButton.setEnabled(false);
    }
    
    /**
     * This method disables the Swing components that are not needed until the 
     * user connects to the server.
     */
    private void enableComponents()
    {
        // Set the connection status to visible.
        connectionStatusLabel.setVisible(true);
        
        // Enable the login button.
        loginButton.setEnabled(true);
        // Enable the email and username field.
        emailField.setEnabled(true);
        // Enable the password field.
        passwordField.setEnabled(true);
        // Enable the create account button.
        createAccountButton.setEnabled(true);
        // Enable the forgot password button.
        forgotPasswordButton.setEnabled(true);
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
        final String CLIENT_PWD = "client123", ALIAS = "client", 
                TRUSTSTORE = "clienttruststore.jks", 
                KEYSTORE = "clientkeystore.jks";
        
        // Set the keystore to null.
        KeyStore keyStore = null;
        
        try
        {
            // Load the keystore, printing and loggin if an exception is thrown.
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream keyStoreData = new FileInputStream(KEYSTORE);
            keyStore.load(keyStoreData, CLIENT_PWD.toCharArray()); 
            
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | 
                CertificateException ex)
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
            System.setProperty("javax.net.ssl.trustStorePassword", CLIENT_PWD);
        } catch (Exception ex)
        {
            System.err.println("Unable to load truststore. -> " + ex
                    .getMessage());
        }
        
        // Set the pub and priv key to null.
        PublicKey pubKey = null;
        PrivateKey privKey = null;
        
        try
        {
            // Attempt to load the Public and Private keys from the keystore. 
            privKey = ((PrivateKeyEntry) keyStore.getEntry(ALIAS, 
                    new PasswordProtection(CLIENT_PWD.toCharArray())))
                    .getPrivateKey();
            pubKey = keyStore.getCertificate(ALIAS).getPublicKey();
        } catch (KeyStoreException | NoSuchAlgorithmException | 
                UnrecoverableEntryException ex)
        {
            System.err.println("Error loading Private/Public Key.");
        }
        
        // Build a new array to hold the keys and return it.
        return new Key[] {pubKey, privKey};
    }
    
    /**
     * This method initializes the Swing components needed and adds the 
     * appropriate action listeners.
     */
    @SuppressWarnings("unchecked")
    private void initComponents()
    {
        // Initalize the swing components.
        createAccountButton = new javax.swing.JButton();
        loginButton = new javax.swing.JButton();
        forgotPasswordButton = new javax.swing.JButton();
        passwordField = new javax.swing.JPasswordField();
        passwordLabel = new javax.swing.JLabel();
        emailField = new javax.swing.JTextField();
        emailUsernameLabel = new javax.swing.JLabel();
        portNumberLabel = new javax.swing.JLabel();
        portNumberField = new javax.swing.JTextField();
        ipAddressField = new javax.swing.JTextField();
        ipAddressLabel = new javax.swing.JLabel();
        headerLabel = new javax.swing.JLabel();
        connectButton = new javax.swing.JButton();
        connectionStatusLabel = new javax.swing.JLabel();

        // Set constraints of GUI.
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setPreferredSize(new java.awt.Dimension(450, 370));
        setResizable(false);
        setSize(new java.awt.Dimension(450, 400));
        getContentPane().setLayout(new org.netbeans.lib.awtextra
                .AbsoluteLayout());

        // Set the font of the createAccountButton.
        createAccountButton.setFont(new java.awt.Font("Tahoma", 0, 10)); 
        // Set the text of the createAccountButton.
        createAccountButton.setText("Don't have an account yet? Create one");
        // Set the opaque to false.
        createAccountButton.setOpaque(false);
        // Add and action listener that pulls ip create account window.
        createAccountButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createAccountButtonActionPerformed(evt);
            }
        });
        getContentPane().add(createAccountButton, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(110, 290, 211, -1));

        // Set loginButton text.
        loginButton.setText("Login");
        // Add an action listender that pulls up login panel.
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loginButtonActionPerformed(evt);
            }
        });
        getContentPane().add(loginButton, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(110, 250, 211, 37));

        // Set forgotPasswordButton font.
        forgotPasswordButton.setFont(new java.awt.Font("Tahoma", 0, 10)); 
        // Set forgotPasswordButton foreground.
        forgotPasswordButton.setForeground(new java.awt.Color(255, 51, 51));
        // Set forgotPasswordButton text.
        forgotPasswordButton.setText("Forgot your password?");
        // Set forgotPasswordButton opaque.
        forgotPasswordButton.setOpaque(false);
        // Add an action listender that adds the forgotPasswordButton.
        forgotPasswordButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                forgotPasswordButtonActionPerformed(evt);
            }
        });
        getContentPane().add(forgotPasswordButton, new org.netbeans.lib
                .awtextra.AbsoluteConstraints(270, 180, -1, -1));

        // Set passwordField font.
        passwordField.setFont(new Font("Tahoma", 0, 12));
        // Set passwordField text.
        passwordField.setText("defaultpassword");
        // Add a focus listener to the passwordField.
        passwordField.addFocusListener(new java.awt.event.FocusAdapter()
        {
            @Override
            public void focusGained(java.awt.event.FocusEvent evt)
            {
                passwordFieldFocusGained(evt);
            }
        });
        getContentPane().add(passwordField, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(200, 150, 209, -1));

        // Set passwordLabel font.
        passwordLabel.setFont(new java.awt.Font("Tahoma", 0, 12)); 
        // Set passwordLabel text.
        passwordLabel.setText("Password");
        // Set passwordLabel tool tip text to blank.
        passwordLabel.setToolTipText("");
        // Add constraints.
        getContentPane().add(passwordLabel, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(200, 130, -1, -1));

        // Set the emailUsernameField font.
        emailField.setFont(new java.awt.Font("Tahoma", 0, 12));
        // Set the emailUsernameField foreground.
        emailField.setForeground(new java.awt.Color(255, 255, 255));
        // Set the emailUsernameField tool tip text to blank.
        emailField.setToolTipText("");
        getContentPane().add(emailField, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(200, 90, 209, -1));

        // Set the emailUsernameLabel font.
        emailUsernameLabel.setFont(new java.awt.Font("Tahoma", 0, 12)); 
        // Set the emailUsernameLabel text. 
        emailUsernameLabel.setText("Email ");
        // Set the emailUsernameLabel tool tip text to blank.
        emailUsernameLabel.setToolTipText("");
        getContentPane().add(emailUsernameLabel, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(200, 70, -1, -1));
        
        // Set the portNumberLabel font.
        portNumberLabel.setFont(new java.awt.Font("Tahoma", 0, 12)); 
        // Set the portNumberLabel text.
        portNumberLabel.setText("Port Number");
        // Set the portNumberLabel tool tip text to blank.
        portNumberLabel.setToolTipText("");
        getContentPane().add(portNumberLabel, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(20, 128, -1, -1));

        // Set the portNumberField font.
        portNumberField.setFont(new java.awt.Font("Tahoma", 0, 12)); 
        // Set the portNumberField foreground.
        portNumberField.setForeground(new java.awt.Color(255, 255, 255));
        // Set the portNumberField tool tip text to blank.
        portNumberField.setToolTipText("");
        getContentPane().add(portNumberField, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(20, 150, 129, -1));

        // Set the ipAddressField font.
        ipAddressField.setFont(new java.awt.Font("Tahoma", 0, 12)); 
        // Set the ipAddressField foreground.
        ipAddressField.setForeground(new java.awt.Color(255, 255, 255));
        // Set the ipAddressField tool tip text to blank.
        ipAddressField.setToolTipText("");
        getContentPane().add(ipAddressField, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(20, 90, 129, -1));

        // Set the ipAddressLabel font.
        ipAddressLabel.setFont(new java.awt.Font("Tahoma", 0, 12));
        // Set the ipAddressLabel text.
        ipAddressLabel.setText("IP Address");
        // Set the ipAddressLabel tool tip text to blank.
        ipAddressLabel.setToolTipText("");
        getContentPane().add(ipAddressLabel, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(20, 70, -1, -1));
        
        // Set the headerLabel font.
        headerLabel.setFont(new java.awt.Font("Tahoma", 1, 18)); 
        // Set the headerLabel text.
        headerLabel.setText("Please enter the following:");
        // Set the headerLabel tool tip text to blank.
        headerLabel.setToolTipText("");
        getContentPane().add(headerLabel, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(80, 30, 259, -1));

        // Set the connect button text.
        connectButton.setText("Connect");
        connectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });
        getContentPane().add(connectButton, new org.netbeans.lib.awtextra
                .AbsoluteConstraints(45, 180, 80, -1));

        // Set the connectionStatusLabel foreground.
        connectionStatusLabel.setForeground(new java.awt.Color(51, 255, 0));
        // Set the connectionStatusLabel horizontal alignment.
        connectionStatusLabel.setHorizontalAlignment(javax.swing.SwingConstants
                .CENTER);
        // Set the connectionStatusLabel text.
        connectionStatusLabel.setText("Successfully connected to server.");
        // Set the connectionStatusLabel tool tip text to blank.
        connectionStatusLabel.setToolTipText("");
        getContentPane().add(connectionStatusLabel, new org.netbeans.lib
            .awtextra.AbsoluteConstraints(110, 230, 210, -1));

        // Pack the GUI.
        pack();
    }

    /**
     * This method prompts the user for the necessary data to reset their 
     * password.
     * 
     * @param evt The ActionEvent.
     */
    private void forgotPasswordButtonActionPerformed(ActionEvent evt)
    {
        // Set the offset.
        offset = -1;
        
        // Initialzie the resetPanel.
        final JPanel[] resetPanel = new JPanel[1];
        // Set the resetPanel to GBL.
        resetPanel[0] = new JPanel(new GridBagLayout());
        
        // IDX 0 stores password, IDX 2 stores OTP. 
        final JPasswordField[] passwordFields = new JPasswordField[2];
        
        // Set the resetPanel dimensions.
        resetPanel[0].setPreferredSize(new Dimension(200, 200));
        
        // Set the GBC settings of the email.
        GBC.gridx = 0;
        GBC.gridy  = ++offset;
        GBC.anchor = GridBagConstraints.LINE_START;
        GBC.insets = new Insets(2, 2, 2, 2);
        resetPanel[0].add(new JLabel("Enter your email"), GBC);
        
        // Set the emailField GBC settings.
        JTextField emailField = new JTextField(20);
        GBC.gridy = ++offset;
        GBC.anchor = GridBagConstraints.CENTER;
        resetPanel[0].add(emailField, GBC);
        
        // Initialize the otpButton.
        JButton otpButton = new JButton("Send OTP");
        otpButton.addActionListener(new ActionListener() {
            
            // Generate an OTP and email it to the user's email address.
            @Override
            public void actionPerformed(ActionEvent e)
            {
                // Check if the email field is blank.
                if (emailField.getText().equals(""))
                {
                    JOptionPane.showMessageDialog(null, "Please enter a valid "
                            + "email address.");
                    return;
                }
                
                // Get the OTP from the Server.
                final int[] OTP = {Integer.MIN_VALUE};
                
                try
                {
                    // Set OTP[0] to getOTP og the email field.
                    OTP[0] = getOTP(emailField.getText(), null, false);
                } catch (ExceptionFactory.LoginException ex)
                {
                    System.err.println("LoginException while getting OTP. -> " 
                            + ex.getMessage());
                }
                
                // Initialize sentLabel.
                var sentLabel = new JLabel("OTP Sent. Please check your "
                        + "email.");
                // Set the sentLabel foreground.
                sentLabel.setForeground(new Color(56, 184, 252));
                GBC.gridy = ++offset;
                // Add the sent label and the GBC.
                resetPanel[0].add(sentLabel, GBC);

                // Call validate.
                resetPanel[0].validate();
                
                /* Start a timer to start a slight delay between sending the 
                OTP and prompting for the user to enter it. */
                Timer timer = new Timer(1500, (ActionEvent ae) -> {
                    int enteredOTP = Integer.valueOf(JOptionPane
                            .showInputDialog("Enter OTP"));

                    /* If the OTP equals the one sent to the user's email, show 
                    fields for the password. */
                    if (OTP[0] == enteredOTP)
                    {   
                        // Diable the otpButton.
                        otpButton.setEnabled(false);
                        // Remove the sentLabel.
                        resetPanel[0].remove(sentLabel);
                        // Set the sentLabel foreground to green.
                        sentLabel.setForeground(Color.GREEN);
                        // Set the sentLabel text.
                        sentLabel.setText("OTP Successfully Verified.");
                        // Add the sentLabel.
                        resetPanel[0].add(sentLabel, GBC);
                                              
                        // Set the size of the resetPanel.
                        resetPanel[0].setSize(resetPanel[0].getWidth(), 
                                resetPanel[0].getHeight() + 10);
                        // Call validate on the resetPanel.
                        resetPanel[0].validate();
                        
                        // Initialize the spaceLabel.
                        JLabel spaceLabel = new JLabel("");
                        GBC.gridy = ++offset;
                        // Add spaceLabel to the resetPanel.
                        resetPanel[0].add(spaceLabel, GBC);

                        // Initialize the firstEntry.
                        JLabel firstEntry = new JLabel("Enter password");
                        GBC.anchor = GridBagConstraints.LINE_START;
                        GBC.gridy = ++offset;
                        // Add the firstEntry to the resetPanel.
                        resetPanel[0].add(firstEntry, GBC);
                        
                        // Initialize the first JPasswordField with 20 char max.
                        passwordFields[0] = new JPasswordField(20);
                        GBC.gridy = ++offset;
                        // Add the first JPasswordField to the resetPanel.
                        resetPanel[0].add(passwordFields[0], GBC);
                        
                        // Initialzie the secondentry JLabel.
                        JLabel secondEntry = new JLabel("Re-enter password");
                        GBC.anchor = GridBagConstraints.LINE_START;
                        GBC.gridy = ++offset;
                        // Add secondEntry to resetPanel.
                        resetPanel[0].add(secondEntry, GBC);

                        // Init the second JPasswordField with 20 char max.
                        passwordFields[1] = new JPasswordField(20);
                        GBC.gridy = ++offset;
                        // Add the second JPasswordField to the resetPanel.
                        resetPanel[0].add(passwordFields[1], GBC);
                        
                        // Validate the resetPanel.
                        resetPanel[0].validate();
                    }         
                });
                // Dont repeat the timer and start it.
                timer.setRepeats(false);
                timer.start();
            }
        });
        GBC.gridy = ++offset;
        // Add the otpButton to the resetPanel.
        resetPanel[0].add(otpButton, GBC);
        
        // Set the options.
        Object[] options = {"OK", "Cancel"};
        
        // Show the JDialog and get a response.
        int res = JOptionPane.showOptionDialog(null, resetPanel,
                    "Change your password", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE, null, options, null);
        
        /* If the user selected "OK" and the two passwordFields equal, attempt 
        to reset the password. If successful, get the session key and start a 
        new ClientGUI. */
        if (res == JOptionPane.OK_OPTION && Arrays.equals(passwordFields[0]
                .getPassword(), passwordFields[1].getPassword()))
        {
            // Placeholder variables.
            String email = emailField.getText();
            String password = new String(passwordFields[1].getPassword());
            String username = getUsername(email, password);
            
            // Tell to server to attempt a password reset.
            if (resetPassword(emailField.getText(), new String(passwordFields[0]
                    .getPassword())))
            {
                JOptionPane.showMessageDialog(null, "Password successfully "
                        + "changed!");  
            }
            else
            {
                JOptionPane.showMessageDialog(null, "An account doesn't exist "
                        + "with that information. Please create an account.");
            }
        }
        else if (res == -1 || res == 1)
            System.out.println("User exited JDialog."); 
        else
            JOptionPane.showMessageDialog(null, "Passwords didn't match, "
                    + "please try again.");            
    }
    
    /**
     * This method communicates with the server to allow for creating an 
     * account. It prompts the user for the necessary inputs in order to do so.
     * 
     * @param evt The ActionEvent. 
     */
    private void createAccountButtonActionPerformed(ActionEvent evt)
    {
        // Set offset.
        offset = -1;
        
        // Init the createPanel.
        final JPanel[] createPanel = new JPanel[1];
        // Set createPanel to a GBL.
        createPanel[0] = new JPanel(new GridBagLayout());
        
        // An array to hold the JPasswordFields. 
        final JPasswordField[] passwordFields = new JPasswordField[2];
        final JTextField[] usernameField = new JTextField[1];
        createPanel[0].setPreferredSize(new Dimension(200, 275));
        
        // Add a JLabel for the email address.
        GBC.gridx = 0;
        GBC.gridy  = ++offset;
        GBC.anchor = GridBagConstraints.LINE_START;
        GBC.insets = new Insets(2, 2, 2, 2);
        createPanel[0].add(new JLabel("Enter your email"), GBC);
        
        // Add a field for the email address.
        JTextField emailField = new JTextField(20);
        GBC.gridy = ++offset;
        GBC.anchor = GridBagConstraints.CENTER;
        createPanel[0].add(emailField, GBC);
        
        // Add a button for sending an OTP to the user's email address.
        JButton otpButton = new JButton("Send OTP");
        otpButton.addActionListener((ActionEvent e) -> {
            if (emailField.getText().equals(""))
            {
                JOptionPane.showMessageDialog(null, "Please enter a valid "
                        + "email address.");
                return;
            }
            
            // Get the OTP from the server.
            final int[] SEND_OTP = new int[1];
            SEND_OTP[0] = Integer.MIN_VALUE;
            
            try
            {
                // Get OTP.
                SEND_OTP[0] = getOTP(emailField.getText(), null, false);
            } catch (ExceptionFactory.LoginException ex)
            {
                System.err.println("Error getting OTP from server. -> " + ex
                        .getMessage());
            }
            
            // Notify the user that the OTP has been sent.
            var sentLabel = new JLabel("OTP Sent. Please check your "
                    + "email.");
            // Set the foreground of sentLabel.
            sentLabel.setForeground(new Color(56, 184, 252));
            GBC.gridy = ++offset;
            // Add sentLabel to the createPanel.
            createPanel[0].add(sentLabel, GBC);
            
            // Call validate on the createPanel.
            createPanel[0].validate();
            
            /* Start a timer to start a slight delay between sending the
            OTP and prompting for the user to enter it. */
            Timer timer = new Timer(2000, (ActionEvent ae) -> {
                String res = JOptionPane.showInputDialog("Enter OTP");
                int enteredOTP = 0;
                if (res != null && !res.equals(""))
                    enteredOTP = Integer.valueOf(res);
                else
                {
                    JOptionPane.showMessageDialog(null, "Please enter a valid "
                            + "OTP.");
                    return;
                }
                
                /* If the OTP equals the one sent to the user's email, show
                fields for the password. */
                if (SEND_OTP[0] == enteredOTP)
                {
                    // Create a JLabel notifying the OTP matched.
                    otpButton.setEnabled(false);
                    createPanel[0].remove(sentLabel);
                    sentLabel.setForeground(Color.GREEN);
                    sentLabel.setText("OTP Successfully Verified.");
                    createPanel[0].add(sentLabel, GBC);
                    
                    // Set the size of the JPanel.
                    createPanel[0].setSize(createPanel[0].getWidth(),
                            createPanel[0].getHeight() + 20);
                    createPanel[0].validate();
                    
                    // Create a space by using a blank JLabel.
                    JLabel spaceLabel = new JLabel("");
                    GBC.gridy = ++offset;
                    createPanel[0].add(spaceLabel, GBC);
                    
                    // Create a JLabel for the username.
                    JLabel usernameLabel = new JLabel("Username");
                    GBC.anchor = GridBagConstraints.LINE_START;
                    GBC.gridy = ++offset;
                    createPanel[0].add(usernameLabel, GBC);
                    
                    // Allocate the JTextField for the username.
                    usernameField[0] = new JTextField(20);
                    GBC.gridy = ++offset;
                    createPanel[0].add(usernameField[0], GBC);
                    
                    // Create a JLabel for the password.
                    JLabel firstEntry = new JLabel("Enter password");
                    GBC.gridy = ++offset;
                    createPanel[0].add(firstEntry, GBC);
                    
                    // Allocate a password field.
                    passwordFields[0] = new JPasswordField(20);
                    GBC.gridy = ++offset;
                    createPanel[0].add(passwordFields[0], GBC);
                    
                    // Add a JLabel for the second entry of the password.
                    JLabel secondEntry = new JLabel("Re-enter password");
                    GBC.anchor = GridBagConstraints.LINE_START;
                    GBC.gridy = ++offset;
                    createPanel[0].add(secondEntry, GBC);
                    
                    // Allocate a second password field.
                    passwordFields[1] = new JPasswordField(20);
                    GBC.gridy = ++offset;
                    createPanel[0].add(passwordFields[1], GBC);
                    
                    createPanel[0].validate();
                }
            });
            // Set the timer to the not repeat and start it.
            timer.setRepeats(false);
            timer.start();
        });
        GBC.gridy = ++offset;
        // Set the otpButton and add the createPanel to it.
        createPanel[0].add(otpButton, GBC);
        
        // Prompt the user by using a JDialog and save their choice.
        int res = JOptionPane.showOptionDialog(null, createPanel,
                    "Create Account", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE, null, new Object[] {"Confirm", 
                    "Cancel"}, null);
        System.out.println(res);
        /* If the user clicked "OK" and the passwords match, tell the server to
        create a new account. */
        if (res == JOptionPane.OK_OPTION && Arrays.equals(passwordFields[0]
                .getPassword(), passwordFields[1].getPassword()))
        {
            System.out.println("inside if");
            // Get the username and password from the fields.
            String username = usernameField[0].getText();
            String password = new String(passwordFields[0].getPassword());
            
            // Call sendCreateAccount() to tell the server to create an account.
            if (sendCreateAccount(emailField.getText(),username, password))
            {
                try
                {
                    // Set the sessionKey.
                    SecretKey sessionKey = getSessionKey(username, password);
                    
                    if (sessionKey != null)
                    {
                        /* If creating the account was successful, create a new 
                        ClientGUI with their information. */
                        new Thread(new ClientGUI(username, 
                                sessionKey, inputStream, outputStream, 
                                ipAddressField.getText(), Integer.valueOf(
                                portNumberField.getText()),
                                UUID)).start();
                        // Dispose of the thread.
                        this.dispose();
                    }
                    else
                    {
                        System.err.println("Error getting session key.");
                        JOptionPane.showMessageDialog(this, "Error getting "
                                + "encryption key. Please try again.");
                    }
                } catch (ExceptionFactory.LoginException | ExceptionFactory
                        .VerificationException ex)
                {
                    System.err.println("Error logging into server with new "
                            + "info." + ex.getMessage());
                }
            } 
            else
            {
                JOptionPane.showMessageDialog(null, "An account already exists "
                        + "with that information, please use another "
                        + "username/password.");
            }
        } 
        else if (res == -1 || res == 1)
            System.out.println("User exited JDialog."); 
        else
            JOptionPane.showMessageDialog(null, "Your passwords don't match, "
                    + "please try again.");
    }

    /**
     * This method resets the passwordField to an empty String when the user
     * clicks on it.
     * 
     * @param evt The FocusEvent. 
     */
    private void passwordFieldFocusGained(java.awt.event.FocusEvent evt)
    {
        passwordField.setText("");
    }

    /**
     * This method validates the input the user enters in order to log in to the
     * application. It contacts the server with the user's username/email and 
     * password.
     * 
     * @param evt The ActionEvent. 
     */
    private void loginButtonActionPerformed(ActionEvent evt)
    {
        // Check the user's input, prompting for an OTP if it is valid.
        if (!emailField.getText().equals("") || 
                !new String(passwordField.getPassword())
                        .equals("defaultpassword"))
        {
            if (!checkEmailField())
            {
                JOptionPane.showMessageDialog(null, "Please enter a valid "
                        + "email address.");
                return;
            }
            
            // Set and init otp.
            int otp = Integer.MIN_VALUE;
            
            try
            {
                // Get the OTP from the server.
                otp = getOTP(emailField.getText(),
                        new String(passwordField.getPassword()), true);
            } catch (ExceptionFactory.LoginException ex)
            {
                JOptionPane.showMessageDialog(null, "Unable to login to"
                        + " account. Please try resetting your password or "
                        + "creating a new account.");
                return;
            }
 
            // Create a new JPanel to prompt the user.
            JPanel otpPanel = new JPanel();
            // Add a JLabel to the otp.
            otpPanel.add(new JLabel("OTP: "));
            // Init the otpField with a char max of 6.
            JTextField otpField = new JTextField(6);
            // Add the otpField to the otpPanel.
            otpPanel.add(otpField);

            // Prompt the user using a JDialog.
            int res = JOptionPane.showOptionDialog(null, otpPanel,
                    "Enter OTP", JOptionPane.OK_CANCEL_OPTION, JOptionPane
                    .PLAIN_MESSAGE, null, new Object[] {"OK", "Cancel"}, 
                    null);

            /* If the user clicked "OK" and the OTP matches, send the
            login info to the server. */
            if (res == JOptionPane.OK_OPTION && otp == Integer
                    .valueOf(otpField.getText()))
            {
                String email = emailField.getText();
                String password = new String(passwordField.getPassword());
                
                // If the login info is valid, get the session key.
                if (sendLoginInfo(email, password))
                {
                    // Set the sessionKey to null.
                    SecretKey sessionKey = null;
                    
                    // Set the username.
                    String username = getUsername(email, password);
                
                    // Try and get the session key and catch the exception.
                    try
                    {
                        sessionKey = getSessionKey(email, password);
                    } catch (ExceptionFactory.LoginException | ExceptionFactory
                            .VerificationException ex)
                    {
                        System.err.println("Unable to get SessionKey from "
                                + "server.");
                    } 
                    
                    if (sessionKey != null)
                    {
                        /* If logging into the account was successful, create a 
                        new ClientGUI with their information. */
                        new Thread(new ClientGUI(username, sessionKey, inputStream, 
                                outputStream, ipAddressField.getText(), Integer
                                    .valueOf(portNumberField
                                    .getText()), UUID)).start(); 
                        this.dispose();
                    }
                    else
                    {
                        JOptionPane.showMessageDialog(this, "Unable to login "
                                + "to server. Please check your username and "
                                + "password.");
                    }
                }
                else
                {
                    JOptionPane.showMessageDialog(this, "Unable to login to "
                            + "server. Please check your username and "
                            + "password.");
                }
            }
            else if (res != -1)
                JOptionPane.showMessageDialog(this, "Invalid OTP, "
                        + "please try again.");
        }
        else
        {
            JOptionPane.showMessageDialog(this, "Please fill in all fields.");
        }
    }

    /**
     * This method connects the user to the server and enables the components 
     * in the GUI if the connect was successful.
     * 
     * @param evt The ActionEvent. 
     */
    private void connectButtonActionPerformed(ActionEvent evt)
    {        
        // Check the IP and port number fields to make sure they are valid.
        if (checkInputs())
        {
            try
            {
                // Build the socket.
                buildSocket();
            } catch (IOException ex)
            {
                JOptionPane.showMessageDialog(this, "Unable to connect to "
                        + "server. Please check the IP Address and Port "
                        + "number.\nReason: " + ex.getMessage());
                return;
            }
            
            /* Now that the socket is built, we can perform a Diffie-Hellman
            Key Exchange using BigIntegers. */
            clientServerKey = performDHKEX();
        }
        else
        {
            JOptionPane.showMessageDialog(this, "Please fill in all fields.");
            return;
        }
        
        // Enable to other components on the GUI.
        enableComponents();
        
        // Disable the connect button, IP, and port fields.
        connectButton.setEnabled(false);
        ipAddressField.setEnabled(false);
        portNumberField.setEnabled(false);
    }

    /**
     * This method performs a Diffie-Hellman Key Exchange with the server to 
     * establish a SecretKey to use for communications prior to receiving the 
     * Session Key.
     * 
     * @return The ephemeral key for the Client and Server to communicate with.
     */
    private SecretKey performDHKEX()
    {   
        SecretKey sharedKey = null;
        
        try
        {
            /* Send a message telling the server to get ready for a DH-KEX and 
            the Client's Certificate. */
            outputStream.writeObject("DO_DH_KEX");
            outputStream.writeObject(X509_CERTIFICATE);
            
            KeyAgreement ecdhKex = KeyAgreement.getInstance("ECDH");
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            KeyPair keyPair = gen.genKeyPair();
            
            // Get the Server's Certificate.
            X509Certificate serverCert = (X509Certificate) inputStream
                    .readObject();
            
            // Generate a nonce and get the key, the encrypt and sign.
            final int NONCE = genNonce();
            final String MESSAGE = Base64.getEncoder().encodeToString(keyPair
                    .getPublic().getEncoded()) + ":" + NONCE;   
            byte[] cText = encrypt(MESSAGE.getBytes(), serverCert
                    .getPublicKey());
            byte[] sign = sign(cText);
            outputStream.writeObject(new byte[][] {cText, sign});       
            
            // Start the exchange with Private Key.
            ecdhKex.init(keyPair.getPrivate());
            
            /* Wait for the response from the Server, then decrypt and load the
            public value the Server sent. */
            byte[][] recvCipherText = (byte[][]) inputStream.readObject();  
            String plainText = new String(decrypt(recvCipherText[0]));
            byte[] recvKey = Base64.getDecoder().decode(plainText
                    .split(":")[0]);
            int recvNonce = Integer.valueOf(plainText.split(":")[1]);
            
            // If the signature verifies, build a keyspec from the public value.
            if (verify(recvCipherText[1], recvCipherText[0], serverCert) && 
                    recvNonce == NONCE)
            {
                // Create a new PublicKey from the Server's Public Value.
                PublicKey pub = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(recvKey));
               
                // Perform the last step of the KEX and create a new SecretKey.
                ecdhKex.doPhase(pub, true);
                
                // Use the first 16 bytes of the generate secret for a key.
                sharedKey = new SecretKeySpec(Arrays.copyOfRange(ecdhKex
                        .generateSecret(), 0, 16), "AES");
            }
            else
                System.err.println("Error verifying signature.");
            
        } catch (IOException | ClassNotFoundException | IllegalStateException | 
                InvalidKeyException | NoSuchAlgorithmException | 
                InvalidKeySpecException ex)
        {
            System.err.println("Error during DH-KEX -> " + ex.getMessage());
        }
        
        try
        {
            // Read the UUID from the Server.
            final int uuid = (int) inputStream.readObject();
            UUID = uuid;
        } catch (IOException | ClassNotFoundException ex)
        {
            System.err.println("Error getting UUID from Server. -> " + ex
                    .getMessage());
        }
        
        return sharedKey;
    }
    
    /**
     * This method signs a message with the Client's Private Key.
     * 
     * @param message The message to sign as a byte array.
     * @return A byte array representing the signed message.
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
     * This method verifies a signature using the provided certificate's Public
     * Key.
     * 
     * @param message The signed message.
     * @param expectedMsg What the verified signature should equal.
     * @param cert The X509Certificate the sender sent.
     * @return A boolean representing if the message verified or not.
     */
    private boolean verify(byte[] message, byte[] expectedMsg, 
            X509Certificate cert)
    {
        // set signOK to false.
        boolean signOK = false;
        
        try
        {
            // Verify the certificate with it's own PublicKey.
            cert.verify(cert.getPublicKey());
            
            // Init the signature with the PublickKey and verify.
            signature.initVerify(cert.getPublicKey());
            signature.update(expectedMsg);
            signOK = signature.verify(message);
        } catch (CertificateException | NoSuchAlgorithmException | 
                InvalidKeyException | NoSuchProviderException | 
                SignatureException ex)
        {
            System.err.println("Error verifying message. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }
        
        return signOK;
    }
    
    /**
     * This method encrypts a message using RSA.
     * 
     * @param message The message to encrypt.
     * @param key The public key to use for encryption.
     * @return The encrypted message.
     */
    private byte[] encrypt(byte[] message, PublicKey key)
    {
        // Set cipherText to null.
        byte[] cipherText = null;
        
        try
        {
            // Init the Cipher and encrypt.
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = rsaCipher.doFinal(message);
        } catch (InvalidKeyException | BadPaddingException | 
                IllegalBlockSizeException ex)
        {
            System.err.println("Error encrypting message. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }
        
        return cipherText;
    }
    
    /**
     * This method decrypts a given message using RSA.
     * 
     * @param cipherText The message to decrypt (ciphertext).
     * @return A byte array representing the plaintext.
     */
    private byte[] decrypt(byte[] cipherText)
    {
        try
        {
            // Init the Cipher and return the result of decrypting.
            rsaCipher.init(Cipher.DECRYPT_MODE, PRIV_KEY);
            return rsaCipher.doFinal(cipherText);
        } catch (InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex)
        {
            System.err.println("Unable to decrypt ciphertext. -> " + ex
                    .getMessage());
            ex.printStackTrace();
        }
        
        return null;
    }
    
    /**
     * Getter for the OTP from the server.
     * 
     * @param email The email or username.
     * @param password The user's password.
     * @param doesAccountExist A boolean representing whether or not the user 
     * has an account.
     * 
     * @return An integer containing the OTP,
     */
    private int getOTP(String email, String password, 
            boolean doesAccountExist) throws ExceptionFactory.LoginException
    {
        String sendMessage;
        final int NONCE = genNonce();
        
        // If the user has an account, request an OTP with the user account.
        if (doesAccountExist)
            sendMessage = "EXISTING_SAMPLE_OTP:" + email + ":" + 
                    password;
        else
            sendMessage = "SAMPLE_OTP:" + email;
        
        // Set the OTP to the lowest possible integer value.
        int otp = Integer.MIN_VALUE;
        
        try
        {
            byte[] iv = genIV();
            
            // Encrypt and send a new SealedMessage with the OTP request.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            
            outputStream.writeObject(new SealedMessage(new ServerMessage(
                    sendMessage, NONCE), aesCipher, 
                    UUID, iv));

            // Decrypt the response from the server and cast to a ServerMessage.
            SealedMessage recvMessage = (SealedMessage) inputStream
                    .readObject();
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, recvMessage.getIV()));
            ServerMessage recMessage = (ServerMessage) recvMessage
                    .getObject(aesCipher);

            // Get the OTP depending on if the account exists or not.
            if (doesAccountExist)
                // If the account exists and the nonce verifies, get the OTP.
                if (recMessage.verifyNonce(NONCE))
                    // If the message is valid, get the OTP, otherwise throw.
                    if (recMessage.toArray()[0].equals("VALID"))
                        otp = Integer.valueOf(recMessage.toArray()[1]);
                    else
                        throw ExceptionFactory.getLoginException("Your account "
                                + "doesn't exist, please create a new "
                                + "account.");
                else
                {
                    System.err.println("Nonce does not match. ");
                }
            else
                // If the message's nonce verifies, get the OTP.
                if (recMessage.verifyNonce(NONCE))
                    otp = Integer.valueOf(recMessage.toArray()[0]);
            
        } catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Error sending OTP request to server. -> " 
                    + ex.getMessage());
            ex.printStackTrace();
        }
        
        return otp;
    }
    
    /**
     * This method generates a uniformly random IV by using SecureRandom.
     * 
     * @return A 12-byte IV. 
     */
    private byte[] genIV()
    {
        // Init a SecureRandom object rand.
        SecureRandom rand = new SecureRandom();
        // Set the IV to a new byte object.
        final byte[] IV = new byte[12];
        
        // Call nextBytes on rand and pass in the IV.
        rand.nextBytes(IV);
        
        return IV;
    }
    
    /**
     * This method checks the IP Address and Port number fields to verify that
     * the user has entered valid data.
     * 
     * @return A boolean representing whether or not the input was valid or not.
     */
    private boolean checkInputs()
    {
        // Set IP and Port ok to false.
        boolean ipOK = false, portOK = false;
        
        // If either field is empty, return false.
        if (ipAddressField.getText().equals("") || portNumberField.getText()
                .equals(""))
            return false;
        
        // Use regex to match the IP address field.
        Pattern pattern = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}"
                + "\\.[0-9]{1,3}\\.[0-9]{1,3}");
        Matcher matcher = pattern.matcher(ipAddressField.getText());
        ipOK = matcher.find() || ipAddressField.getText().equals("localhost"); 
        
        // Check the port number by checking a range.
        int port = Integer.valueOf(portNumberField.getText());
        portOK = (port > 1023) && (port < 65354);
        
        return (ipOK && portOK);
    }
    
    /**
     * This method gets the username from the server given an email and 
     * password.
     * 
     * @param email The email address.
     * @param password The password.
     * @return The username.
     */
    private String getUsername(String email, String password)
    {
        // Get a new random nonce.
        final int NONCE = genNonce();
        
        // The message to send.
        final String MESSAGE = "GET_USERNAME:" + email + ":" + password;
        
        try
        {
            byte[] iv = genIV();
            // Init the cipher, send a ServerMessage, and wait for a response.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            SealedMessage sendMessage = new SealedMessage(
                    new ServerMessage(MESSAGE, NONCE), aesCipher, UUID, iv);
            // Write sendMessage to the outputStream.
            outputStream.writeObject(sendMessage);

            SealedMessage recvMessage = (SealedMessage) 
                    inputStream.readObject();
            // Decrypt the response from the server and cast to a ServerMessage.
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey,
                    new GCMParameterSpec(TAG_LENGTH, recvMessage.getIV()));
            ServerMessage recMessage = (ServerMessage) (recvMessage)
                    .getObject(aesCipher);
            
            // Verify the message's certicate and none, and then get the uname.
            if (recMessage.verifyNonce(NONCE))
                return recMessage.toArray()[0];
            else
            {
                JOptionPane.showMessageDialog(this, "Unable to get username "
                        + "from Server.");
                return null;
            }
        } catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Unable to get username from server. -> " + ex
                    .getMessage());
            return null;
        }
    }
    
    /**
     * This method sends a message to the server to create a new account.
     * 
     * @param username The username.
     * @param password The password.
     * @return A boolean representing whether or not the creation of an account 
     * was successful.
     */
    private boolean sendCreateAccount(String email, String username, 
            String password)
    {
        assert (email != null) && (!email.equals("")) &&(username != null && 
                !username.equals("")) && (password != null && 
                !password.equals(""));
        
        // Generate a nonce and create the message.
        final int NONCE = genNonce();
        final String MESSAGE = "ENROLL:" + email + ":" + username + ":" + 
                password;
        
        // Set createSuccess to false.
        boolean createSuccess = false;
        
        try
        {
            byte[] iv = genIV();
            // Init the cipher with a new ServerMessage and send it.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            outputStream.writeObject(new SealedMessage(
                    new ServerMessage(MESSAGE, NONCE), aesCipher, UUID, iv));
            
            SealedMessage recvMsg = (SealedMessage) inputStream.readObject();
            // Get the response from the server and operate on it.
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey,
                    new GCMParameterSpec(TAG_LENGTH, recvMsg.getIV()));
            ServerMessage recMessage = (ServerMessage) recvMsg
                    .getObject(aesCipher);

            // Verify the message's certificate, signature, and nonce.
            if (recMessage.verifyNonce(NONCE))
            {
                /* If the first index of the message is "SUCCESS", the creation
                was successful. */
                createSuccess = (recMessage.toArray()[0].equals("SUCCESS"));
            } 
        }
        catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Error creating new account.");
            JOptionPane.showMessageDialog(null, "Unable to create new account. "
                    + "Please try again with a different username/password "
                    + "combination.");
            ex.printStackTrace();
            return false;
        }   
        
        return createSuccess;
    }
    
    /**
     * This method sends the login information to the server to verify that the 
     * user's information exists.
     * 
     * @param emailOrUsername The user's email address or username.
     * @param password The user's password.
     * @return A boolean representing whether or not the account exists. True 
     * if it does, false otherwise.
     */
    private boolean sendLoginInfo(String emailOrUsername, String password)
    {
        assert (emailOrUsername != null && !emailOrUsername.equals("")) && 
                (password != null && !password.equals(""));
        
        // Get a new random nonce and create the message as a String.
        final int NONCE = genNonce();
        final String MESSAGE = "VERIFY_ACCOUNT:" + emailOrUsername + ":" + 
                password;

        // Set loginSuccess to false.
        boolean loginSuccess = false;

        try
        {
            byte[] iv = genIV();
            
            // Init the cipher with a new ServerMessage and send it.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            outputStream.writeObject(new SealedMessage(
                    new ServerMessage(MESSAGE, NONCE), aesCipher, UUID, iv));

            SealedMessage recvMsg = (SealedMessage) inputStream.readObject();
            // Get the response from the server and operate on it.
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey,
                    new GCMParameterSpec(TAG_LENGTH, recvMsg.getIV()));
            ServerMessage recMessage = (ServerMessage) recvMsg
                    .getObject(aesCipher);

            // Verify the message's nonce.
            if (recMessage.verifyNonce(NONCE))
            {
                /* If the first index of the message is "SUCCESS", the login is
                successful. */
                loginSuccess = (recMessage.toArray()[0].equals("SUCCESS"));
            }

        } catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Unable to send reset password message.");
            JOptionPane.showMessageDialog(this, "Unable to reset password, "
                    + "please try again.");
            return false;
        }

        return loginSuccess;
    }
    
    /**
     * This method attempts to reset the user's password.
     * 
     * @param emailOrUsername The user's email or username.
     * @param newPassword The new password.
     * @return A boolean representing whether or not the operation was 
     * successful.
     */
    private boolean resetPassword(String emailOrUsername, String newPassword)
    {
        assert (emailOrUsername != null && !emailOrUsername.equals("")) && 
                (newPassword != null && !newPassword.equals(""));
        
        // Get a new random nonce and create the message as a String.
        final int NONCE = genNonce();
        final String MESSAGE = "RESET:" + emailOrUsername + ":" + newPassword;
        
        // Set sendMessage to null and resetSuccess to false.
        SealedMessage sendMessage = null;
        boolean resetSuccess = false;
        
        try
        {
            // Set iv by generating an IV.
            byte[] iv = genIV();
            
            // Init the cipher with a new ServerMessage and send it.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            // Set sendMessage to the new SealedMessage.
            sendMessage = new SealedMessage(new ServerMessage(MESSAGE, NONCE), 
                    aesCipher, UUID, iv);
            // Write sendMessage ot the output stream.
            outputStream.writeObject(sendMessage);
            
            SealedMessage recvMsg = (SealedMessage) inputStream.readObject();
            // Get the response from the server and operate on it.
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, recvMsg.getIV()));
            ServerMessage recMessage = (ServerMessage) recvMsg
                    .getObject(aesCipher);
            
            // Verify the message's certificate, signature, and nonce.
            if (recMessage.verifyNonce(NONCE))
            {
                /* If the first index of the message is "SUCCESS", successfully 
                changed the password. */
                resetSuccess = (recMessage.toArray()[0].equals("SUCCESS"));
            }
            
        } catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Unable to send reset password message.");
            JOptionPane.showMessageDialog(this, "Unable to reset password, "
                    + "please try again.");
            return false;
        }
        
        return resetSuccess;
    }
    
    /**
     * This method gets a session key from the server represented as a 
     * SecretKey.
     * 
     * <br>
     * CODE REFERENCED FROM: <a href = "https://stackoverflow.com/questions/
     * 5355466/converting-secret-key-into-a-string-and-vice-versa">URL</a>
     * </br>
     * 
     * @param usernameEmail The user's email or username.
     * @param password The user's password.
     * @return A SecretKey containing the session key.
     * @throws LoginException If the login information failed.
     * @throws VerificationException If the message failed to verify.
     */
    private SecretKey getSessionKey(String usernameEmail, String password) 
            throws ExceptionFactory.LoginException, ExceptionFactory
            .VerificationException
    {
        // No time battery LOW
        assert (usernameEmail != null && !usernameEmail.equals("")) && 
                (password != null && !password.equals(""));
        
        final int NONCE = genNonce();
        String message = "KEY_REQ:" + usernameEmail + ":" + password;
        
        try
        {
            byte[] iv = genIV();
            
            // Write the message to the stream.
            aesCipher.init(Cipher.ENCRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            outputStream.writeObject(new SealedMessage(
                    new ServerMessage(message, NONCE), aesCipher, UUID, iv));
            
            // Read the message off the stream with the wrapped key.
            SealedMessage recvMsg = (SealedMessage) inputStream.readObject();
            aesCipher.init(Cipher.DECRYPT_MODE, clientServerKey, 
                    new GCMParameterSpec(TAG_LENGTH, recvMsg.getIV()));
            ServerMessage wrappedKey = (ServerMessage) recvMsg
                    .getObject(aesCipher);
            
            /* If the nonce verifies and the message has the key, return a new 
            SecretKeySpec. */
            if (wrappedKey.verifyNonce(NONCE))
            {
                if (!wrappedKey.toArray()[0].equals("FAILED"))
                {
                    byte[] keyBytes = wrappedKey.toArray()[0].getBytes();
                    return new SecretKeySpec(keyBytes, 0, keyBytes.length, 
                            "AES");
                }
                else
                    throw ExceptionFactory.getLoginException("Unable to login "
                            + "to account. Please verify that the username and "
                            + "password are correct.");
            }
            else
            {
                throw ExceptionFactory.getVerificationException("Unable to "
                        + "verify message.");
            }

        } catch (IOException | ClassNotFoundException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex)
        {
            System.err.println("Error sending session key request to server. "
                    + "-> " + ex.getMessage());
            return null;
        }
    } 
        
    /**
     * This method generates a cryptographically random integer that serves as 
     * a nonce.
     * 
     * @return An integer representing a nonce. 
     */
    private int genNonce()
    {
        // Create a new SecureRandom object.
        final SecureRandom RAND = new SecureRandom();
        
        return RAND.nextInt();
    }
    
    /**
     * This method uses Regex to see if the user entered an email address
     * in the emailField.
     * 
     * @return True if the input was an email, false otherwise.
     */
    private boolean checkEmailField()
    {
        Pattern pattern = Pattern.compile(".*@");
        Matcher matcher = pattern.matcher(emailField.getText());

        // Return whether or not a match was found for the email.
        return matcher.find();
    }
}