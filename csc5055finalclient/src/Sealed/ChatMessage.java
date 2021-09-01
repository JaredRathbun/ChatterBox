package Sealed;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as an object to hold a message which can be encrypted via
 * a SealedObject. It utilizes Java's Date class to create a timestamp and 
 * requires the sender's name, along with the message.
 * </pre>
 */
public class ChatMessage implements Serializable
{
    /**
     * A constant for the date the message originated.
     */
    private final Date DATE;
    
    /**
     * Constants for both the sender's name and message.
     */
    private final String SENDER; 
            
    /**
     * A String to hold the message the user is sending.
     */
    private final String MESSAGE;
    
    /**
     * Constructor which creates the message object. The message is concatenated
     * to follow the format: message + ":" + sender.
     * 
     * @param sender The sender's name represented as a String.
     * @param message The message to send.
     */
    public ChatMessage(String sender, String message)
    {
        DATE = new Date();
        SENDER = sender;
        this.MESSAGE = message;
    }
    
    /**
     * Getter for the message.
     * 
     * @return The message. 
     */
    public String getMessage()
    {
        return MESSAGE;
    }
    
    /**
     * Getter for the Sender.
     * 
     * @return The sender. 
     */
    public String getSender()
    {
        return SENDER;
    }
    
    /**
     * toString method which returns the object's data in the following format:
     * <br>
     * [Date] [Sender's Name]: (Message)
     * </br>
     * @return A String representation of the object.
     */
    @Override
    public String toString()
    {
        SimpleDateFormat dateFormat = 
                new SimpleDateFormat("MM-dd-yyyy @ HH:mm aa");
        
        return String.format("[%s] [%s]: %s", dateFormat.format(DATE), MESSAGE
                .toUpperCase(), SENDER);
    }
}
