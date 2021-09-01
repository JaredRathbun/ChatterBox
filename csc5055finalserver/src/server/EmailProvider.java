package server;

import java.util.Properties;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as utility to send an email to an email address. 
 * Specifically, it sends an email containing a One Time Password, which is 
 * generated from the server.
 * </pre>
 */
public class EmailProvider
{
    /**
     * A constant to represent the email address to send from.
     */
    private static final String FROM_ADDRESS = "EMAIL_ADDRESS_HERE";
    
    /**
     * A constant to represent the email's password.
     */
    private static final String FROM_PASSWORD = "EMAIL_PASSWORD_HERE";
    
    /**
     * A constant to represent the mail server to use.
     */
    private static final String SMTP = "mail.smtp.host";
    
    /**
     * Constructor which takes an address to send to, a message to send, and 
     * OTP. It automatically sends the email upon initialization.
     * 
     * @param to The email address to send to (the recipient).
     * @param message The message to send.
     * @param OTP The OTP to send.
     * 
     * @see sendEmail(String to, String message, int OTP)
     */
    public EmailProvider(String to, String message, final int OTP)
    {
        sendEmail(to, message, OTP);
    }
    
    /**
     * This method sends an email to user using the specified parameters as a 
     * recipient and content, respectively.
     * 
     * @param to The email address to send to (the recipient).
     * @param message The message to send.
     * @param OTP The OTP to send.
     */
    public static void sendEmail(String to, String message, final int OTP)
    {
        // Set the SMTP property for localhost.
        Properties properties = System.getProperties();
        properties.setProperty(SMTP, "localhost");
        
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", "smtp.gmail.com");
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.ssl.trust", "smtp.gmail.com");
        
        // Create a session and override it's password authentication method.
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(FROM_ADDRESS, FROM_PASSWORD);
            }
        });
        
        try
        {
            /* Create a new message, add the recepient and sender, add the 
            message, and then send. */
            MimeMessage msg = new MimeMessage(session);
            
            msg.setFrom(new InternetAddress(FROM_ADDRESS));
            msg.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
            msg.setSubject("ChatterBox OTP Code");
            msg.setText(message + OTP);
            
            // Send the msg object.
            Transport.send(msg);
            
        } catch (MessagingException ex)
        {
            ex.printStackTrace();
            
            /** DON'T REPORT THE EXCEPTION TO THE USER INSTEAD, MAKE THEM SEND 
            AN EMAIL AGAIN. */
        }
    }
}