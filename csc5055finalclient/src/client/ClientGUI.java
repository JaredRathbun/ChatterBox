package client;

import Sealed.ChatMessage;
import Sealed.SealedMessage;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.swing.GroupLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle;
import javax.swing.WindowConstants;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as an object to display the chat to the user and allows 
 * them to send messages. 
 * </pre>
 */
public class ClientGUI extends JFrame implements Runnable
{
    private final String USERNAME, IP;
    private final int PORT;
    private final ObjectInputStream INPUT_STREAM;
    private final ObjectOutputStream OUTPUT_STREAM;
    private final LinkedList<ChatMessage> MESSAGE_LIST;    
    private JPanel bottomPanel, infoPanel;
    private JButton disconnectButton, sendMessageButton;
    private JTextArea messagesBox, newMessageArea;
    private JScrollPane messagesPane, newMessagePane;
    private JLabel usernameLabel, ipAddressLabel, usernameHeaderLabel, 
            ipAddressHeader, portNumberLabel, portNumberHeader;
    
    private final SecretKey SESSION_KEY;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12, TAG_LENGTH = 128;
    private Cipher aesCipher;
    private final int UUID;
    
    /**
     * Constructor which creates and initializes the components needed to 
     * display the chat to the user.
     * 
     * @param username The user's username.
     * @param sessionKey The session key.
     * @param inputStream The ObjectInputStream to receive messages.
     * @param outputStream The ObjectOutputStream to send messages.
     * @param IP The IP address.
     * @param port The port number.
     * @param UUID The user's Unique ID number.
     */
    public ClientGUI(String username, SecretKey sessionKey, 
            ObjectInputStream inputStream, ObjectOutputStream outputStream, 
            String IP, int port, int UUID) 
    {
        // Make a call to the super class.
        super("ChatterBox - " + username);
        
        USERNAME = username;
        INPUT_STREAM = inputStream;
        OUTPUT_STREAM = outputStream;
        SESSION_KEY = sessionKey;
        PORT = port;
        this.IP = IP;
        this.UUID = UUID;
        MESSAGE_LIST = new LinkedList<>();
        
        // Add a listener to remove the user from the server when closing.
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                try
                {
                    OUTPUT_STREAM.writeObject("REMOVE_UUID:" + UUID);
                    OUTPUT_STREAM.flush();
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
        
        initCipher();
        initComponents();  
        setLocationRelativeTo(null);
        setVisible(true);
        validate();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    /**
     * This method reads a SealedMessage off the ObjectInputStream and 
     * processes it.
     */
    @Override
    public void run()
    {
        while (true)
        {
            try
            {
                // When a message is received, process it.
                processMessage((SealedMessage) INPUT_STREAM.readObject());

            } catch (IOException | ClassNotFoundException ex)
            {
                System.err.println("Error reading SealedMessage off I/O "
                        + "stream.");
            }
        }
    }
    
    /**
     * This method builds the cipher needed to encrypt/decrypt data.
     */
    private void initCipher()
    {
        try
        {
            aesCipher = Cipher.getInstance(AES_ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex)
        {
            System.err.println("Error creating Cipher object: " + ex
                    .getMessage());
        }
    }
    
    /**
     * This method initializes all of the components needed to display the chat
     * to the user.
     */
    private void initComponents()
    {
        bottomPanel = new JPanel();
        newMessagePane = new JScrollPane();
        newMessageArea = new JTextArea();
        sendMessageButton = new JButton();
        messagesPane = new JScrollPane();
        messagesBox = new JTextArea();
        infoPanel = new JPanel();
        usernameHeaderLabel = new JLabel();
        usernameLabel = new JLabel();
        ipAddressHeader = new JLabel();
        ipAddressLabel = new JLabel();
        portNumberHeader = new JLabel();
        portNumberLabel = new JLabel();
        disconnectButton = new JButton();

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setPreferredSize(new java.awt.Dimension(550, 620));
        setResizable(false);
        setSize(new java.awt.Dimension(550, 625));

        bottomPanel.setPreferredSize(new java.awt.Dimension(538, 550));

        newMessageArea.setColumns(20);
        newMessageArea.setRows(5);
        newMessageArea.setText("Enter your message here...");
        newMessageArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                newMessageArea.setText("");
            }
        });
        newMessagePane.setViewportView(newMessageArea);

        sendMessageButton.setText("Send Message");
        sendMessageButton.addActionListener((ActionEvent e) -> {
           sendMessage(newMessageArea.getText()); 
        });

        messagesBox.setEditable(false);
        messagesBox.setColumns(20);
        messagesBox.setLineWrap(true);
        messagesBox.setRows(5);
        messagesPane.setViewportView(messagesBox);

        infoPanel.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Session Information"));

        usernameHeaderLabel.setFont(new java.awt.Font("Tahoma", 1, 12)); 
        usernameHeaderLabel.setText("Username:");

        usernameLabel.setText(USERNAME);

        ipAddressHeader.setFont(new java.awt.Font("Tahoma", 1, 12)); 
        ipAddressHeader.setText("IP Address:");

        ipAddressLabel.setText(IP);

        portNumberHeader.setFont(new java.awt.Font("Tahoma", 1, 12)); 
        portNumberHeader.setText("Port Number:");

        portNumberLabel.setText(String.valueOf(PORT));

        disconnectButton.setText("Disconnect");
        disconnectButton.addActionListener((ActionEvent e) -> {
            try
            {
                OUTPUT_STREAM.writeObject("REMOVE_UUID:" + UUID);
                OUTPUT_STREAM.flush();
            } catch (IOException ex)
            {
                System.err.println("Error writing remove message to "
                        + "server.");
            }
            System.exit(0);
        });

        GroupLayout infoPanelLayout = new GroupLayout(infoPanel);
        infoPanel.setLayout(infoPanelLayout);
        infoPanelLayout.setHorizontalGroup(infoPanelLayout
            .createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(infoPanelLayout.createSequentialGroup().addContainerGap()
            .addGroup(infoPanelLayout.createParallelGroup(GroupLayout
            .Alignment.LEADING).addComponent(usernameHeaderLabel, GroupLayout
            .PREFERRED_SIZE, 64, GroupLayout.PREFERRED_SIZE)
            .addComponent(usernameLabel, GroupLayout
            .PREFERRED_SIZE, 111, GroupLayout.PREFERRED_SIZE))
            .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
            .addGroup(infoPanelLayout.createParallelGroup(GroupLayout.Alignment
            .LEADING).addComponent(ipAddressHeader)
            .addComponent(ipAddressLabel, GroupLayout
            .PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE)).addGap(25, 25, 25)
            .addGroup(infoPanelLayout.createParallelGroup(GroupLayout.Alignment
            .LEADING).addComponent(portNumberLabel, GroupLayout
            .PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE)
            .addComponent(portNumberHeader)).addGap(18, 18, 18)
            .addComponent(disconnectButton, GroupLayout
            .DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addContainerGap())
        );
        infoPanelLayout.setVerticalGroup(infoPanelLayout
            .createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(infoPanelLayout.createSequentialGroup()
            .addGap(5, 5, 5).addGroup(infoPanelLayout
            .createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(usernameHeaderLabel).addComponent(ipAddressHeader)
            .addComponent(portNumberHeader)).addPreferredGap(LayoutStyle
            .ComponentPlacement.RELATED).addGroup(infoPanelLayout
            .createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(usernameLabel).addComponent(ipAddressLabel)
            .addComponent(portNumberLabel))
            .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(infoPanelLayout.createSequentialGroup()
            .addComponent(disconnectButton, GroupLayout
            .DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addContainerGap()));

        GroupLayout bottomPanelLayout = new GroupLayout(bottomPanel);
        bottomPanel.setLayout(bottomPanelLayout);
        bottomPanelLayout.setHorizontalGroup(bottomPanelLayout
            .createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(bottomPanelLayout.createSequentialGroup()
            .addContainerGap().addGroup(bottomPanelLayout
            .createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(bottomPanelLayout.createSequentialGroup()
            .addComponent(newMessagePane, GroupLayout
            .PREFERRED_SIZE, 380, GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(sendMessageButton, GroupLayout
            .DEFAULT_SIZE, 132, Short.MAX_VALUE)).addComponent(messagesPane)
            .addComponent(infoPanel, GroupLayout.DEFAULT_SIZE, GroupLayout
            .DEFAULT_SIZE, Short.MAX_VALUE)).addContainerGap()));
        bottomPanelLayout.setVerticalGroup(bottomPanelLayout
            .createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(bottomPanelLayout.createSequentialGroup()
            .addContainerGap().addComponent(infoPanel, GroupLayout
            .PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout
            .PREFERRED_SIZE).addPreferredGap(LayoutStyle.ComponentPlacement
            .RELATED).addComponent(messagesPane, GroupLayout
            .PREFERRED_SIZE, 389, GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
            .addGroup(bottomPanelLayout.createParallelGroup(GroupLayout
            .Alignment.LEADING).addComponent(sendMessageButton, GroupLayout
            .PREFERRED_SIZE, 95, GroupLayout.PREFERRED_SIZE)
            .addComponent(newMessagePane, GroupLayout
            .PREFERRED_SIZE, 95, GroupLayout.PREFERRED_SIZE))
            .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout
            .Alignment.LEADING).addComponent(bottomPanel, GroupLayout
            .PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout
            .PREFERRED_SIZE));
        layout.setVerticalGroup(layout.createParallelGroup(GroupLayout
            .Alignment.LEADING).addComponent(bottomPanel, GroupLayout
            .PREFERRED_SIZE, 591, GroupLayout.PREFERRED_SIZE));

        pack();
    }
    
    /**
     * This method updates the messages box with the current messages in the 
     * message list.
     */
    private void updateMessagesBox()
    {
        messagesBox.setText("");
        
        for (ChatMessage msg : MESSAGE_LIST)
            messagesBox.append(msg.toString() + "\n");
        
        // Rebuild the GUI.
        messagesBox.validate();
        validate();
    }
    
    /**
     * This method sends a message across the stream.
     * 
     * @param message The message to send represented as a String. 
     */
    private void sendMessage(String message)
    {
        try
        {
            SealedMessage sendMessage = encrypt(message);
            OUTPUT_STREAM.writeObject(sendMessage);
            OUTPUT_STREAM.flush(); // Flush dat toilet
        } catch (IOException ex)
        {
            JOptionPane.showMessageDialog(null, "Unable to send message.");
            ex.printStackTrace();
        }
    }
    
    /**
     * This message processes a message received over the ObjectInputStream. 
     * 
     * @param message The SealedMessage to process. 
     */
    private void processMessage(SealedMessage message)
    {
        ChatMessage decryptedMessage = null;
        
        /* Decrypt the SealedMessage into a ChatMessage and add it to the 
        message list before updating the messages box so the user can see the 
        new message. */
        decryptedMessage = (ChatMessage) decrypt(message);
        MESSAGE_LIST.add(decryptedMessage);
        updateMessagesBox();      
    }
    
    /**
     * This message encrypts a message into a SealedMessage and returns it.
     * 
     * @param message The message to send represented as a String.
     * @return The message wrapped in a SealedMessage.
     */
    private SealedMessage encrypt(String message)
    {
        assert (message != null) && (!message.equals("")) 
                && (SESSION_KEY != null) && (aesCipher != null);
        
        // Create a new ChatMessage to hold the message.
        ChatMessage newMessage = new ChatMessage(message, USERNAME);
        
        // Define a new array for the IV and fill it with random bytes.
        byte[] iv = new byte[IV_SIZE];        
        RANDOM.nextBytes(iv);
        
        // A SealedObject to hold the encrypted ChatMessage.
        SealedMessage sealedMessage = null;
        
        try
        {
            // Init the cipher to encrypt and create a new SealedMessage.
            aesCipher.init(Cipher.ENCRYPT_MODE, SESSION_KEY, 
                    new GCMParameterSpec(TAG_LENGTH, iv));
            sealedMessage = new SealedMessage(newMessage, aesCipher, 0, iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex)
        {
            System.err.println("Error initializing cipher. -> " + ex
                    .getMessage());
        } catch (IOException | IllegalBlockSizeException ex)
        {
            System.err.println("Error created new SealedMessage. -> " + ex
                    .getMessage());
        }

        return sealedMessage;
    }
    
    /**
     * This method decrypts a SealedMessage into a ChatMessage which can then
     * be posted to the chat box.
     * 
     * @param message The SealedMessage to decrypt.
     * @return The SealedMessage decrypted into a ChatMessage.
     */
    private ChatMessage decrypt(SealedMessage message)
    {
        assert (message != null) && (SESSION_KEY != null) 
                && (aesCipher != null);
        
        ChatMessage decryptedMessage = null;
        
        byte[] iv = message.getIV();
        
        try
        {
            // Init the cipher to decrypt and decrypt the SealedMessage.
            aesCipher.init(Cipher.DECRYPT_MODE, SESSION_KEY,
                    new GCMParameterSpec(TAG_LENGTH, iv));
            decryptedMessage = (ChatMessage) message.getObject(aesCipher);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
                IOException | ClassNotFoundException | 
                IllegalBlockSizeException | BadPaddingException ex)
        {
            System.err.println("Error decrypting ChatMessage. -> " + ex
                    .getMessage());
        }
        
        return decryptedMessage;
    }   
}
