package Sealed;

import java.io.Serializable;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as a container for a message with the Server. It takes a 
 * message (String) and signs it using the appropriate cryptography objects.
 * </pre>
 */
public class ServerMessage implements Serializable
{
    private final Serializable MESSAGE;
    private final int NONCE;
    
    /**
     * Constructor which takes a message and nonce.
     * 
     * @param message The message to send to the server.
     * @param nonce The nonce to include in the message.
     */
    public ServerMessage(Serializable message, int nonce)
    {
        MESSAGE = message;
        NONCE = nonce;
    }
    
    /**
     * Getter for the message.
     * 
     * @return The array containing the elements in the message.
     */
    public Serializable getMessage()
    {
        return MESSAGE;
    }
    
    /**
     * Getter for the certificate.
     * 
     * @return The certificate. 
     */
    public int getNonce()
    {
        return NONCE;
    }
    
    /**
     * This method converts the message into an array of Strings.
     * 
     * @return The message converted to an array separated by the colons.
     */
    public String[] toArray() 
    {
        return ((String) MESSAGE).split(":");
    }
    
    public boolean verifyNonce(int nonce)
    {
        return (nonce == NONCE);
    }
}
