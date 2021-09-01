package Sealed;

import java.io.IOException;
import java.io.Serializable;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as a container to hold an encrypted object by utilizing 
 * Java's SealedObject class.
 * </pre>
 */
public class SealedMessage extends SealedObject implements Serializable
{ 
    private final int UUID;
    private final byte[] IV;
    private static final long serialVersionUID = -6743567631108323096L;
    private final int TYPE;
    
    /**
     * This constructor initializes a new instance of a SealedMessage. It uses 
     * a {@code Cipher} to encrypt the {@code Serializable} data. It also takes
     * a UUID to identify the sender of the message and the IV used in 
     * encryption.
     * 
     * @param data The data to encrypt.
     * @param cipher The Cipher to use.
     * @param UUID The Unique User ID number.
     * @param iv The IV used in encryption.
     * @throws IOException If there is an I/O error.
     * @throws IllegalBlockSizeException If the cipher encounters and illegal
     * block size.
     */
    public SealedMessage(Serializable data, Cipher cipher, final int UUID,
            byte[] iv) throws IOException, IllegalBlockSizeException
    {    
        // Call to SealedObject.
        super(data, cipher);
        
        if (data instanceof ServerMessage)
            TYPE = 0;
        else
            TYPE = 1;
        
        // Set the UUID and IV.
        this.UUID = UUID;
        IV = iv;
    }
    
    /**
     * Getter for the UUID.
     * 
     * @return The UUID. 
     */
    public int getUUID()
    {
        return UUID;
    }
    
    /**
     * Getter for the IV.
     * 
     * @return The IV. 
     */
    public byte[] getIV()
    {
        return IV;
    }
    
    /**
     * Getter for the type of message. 0 if the message is a ServerMessage, 1 
     * otherwise.
     * 
     * @return The type of message. 
     */
    public int getType()
    {
        return TYPE;
    }
}
