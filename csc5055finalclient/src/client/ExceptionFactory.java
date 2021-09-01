package client;

/**
 * <pre>
 * Author: Jared Rathbun
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 * 
 * This class serves as a container to get a number of exceptions. It uses a 
 * Factory Design Pattern to do so.
 * </pre>
 */
public class ExceptionFactory
{    
    /**
     * Getter for an InvalidColorThemeException with no specific message.
     * 
     * @return A new InvalidColorThemeException with no specific message.
     */
    public static final InvalidColorThemeException 
            getInvalidColorThemeException()
    {
        return new InvalidColorThemeException();
    }
    
    /**
     * Getter for an InvalidColorThemeException with a specific message.
     * 
     * @param message The message to set on the exception.
     * @return A new InvalidColorThemeException with the specific message.
     */
    public static final InvalidColorThemeException 
            getInvalidColorThemeException(String message)
    {
        return new InvalidColorThemeException(message);
    }
    
    /**
     * Getter for a LoginException without a specific message.
     * 
     * @return A new LoginException with no specific message.
     */
    public static final LoginException getLoginException()
    {
        return new LoginException();
    }
    
    /**
     * Getter for a LoginException with a specific message.
     * 
     * @param message The message to set on the exception.
     * @return A new LoginException with a specific message.
     */
    public static final LoginException getLoginException(String message)
    {
        return new LoginException(message);
    }
    
    /**
     * Getter for a VerificationException with no specific message.
     * 
     * @return A new VerificationException with no specific message. 
     */
    public static final VerificationException getVerificationException()
    {
        return new VerificationException();
    }
    
    /**
     * Getter for a VerificationException with a specific message.
     * 
     * @param message The message to set on the exception.
     * @return A new VerificationException with a specific message. 
     */
    public static final VerificationException getVerificationException(
            String message)
    {
        return new VerificationException(message);
    }
    
    /**
     * <pre>
     * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis
     * Course: CSC5055 - Network Security 1
     * Due Date: May 11, 2021 @ 11:30am
     *
     * This class serves as an exception that is thrown when an invalid color
     * theme (look and feel) is selected.
     * </pre>
     */
    protected static final class InvalidColorThemeException extends 
            RuntimeException
    {
        /**
         * Default constructor which calls the super class with a default 
         * message.
         */
        public InvalidColorThemeException()
        {
            super("Invalid Color Theme.");
        }

        /**
         * Overloaded constructor which calls the super class with the 
         * specified message.
         *
         * @param message The message to include in the exception.
         */
        public InvalidColorThemeException(String message)
        {
            super(message);
        }
    }
    
    /**
    * <pre>
    * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis
    * Course: CSC5055 - Network Security 1
    * Due Date: May 11, 2021 @ 11:30am
    *
    * This class serves as an exception for when a login failed.
    * </pre>
    */
   protected static final class LoginException extends RuntimeException
   {
       /**
        * Creates a new instance of <code>LoginException</code> without detail
        * message.
        */
       public LoginException()
       {
           super("Unable to log into account.");
       }

       /**
        * Constructs an instance of <code>LoginException</code> with the 
        * specified detail message.
        *
        * @param msg the detail message.
        */
       public LoginException(String msg)
       {
           super(msg);
       }
   }
   
    /**
     * <pre>
     * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis
     * Course: CSC5055 - Network Security 1
     * Due Date: May 11, 2021 @ 11:30am
     *
     * This class serves as an exception for when a verification of a signature
     * fails.
     * </pre>
     */
    protected static final class VerificationException extends Exception
    {   
        /**
         * Creates a new instance of <code>VerificationException</code> without
         * detail message.
         */
        public VerificationException()
        {
            super("Unable to verify.");
        }

        /**
         * Constructs an instance of <code>VerificationException</code> with the
         * specified detail message.
         *
         * @param msg the detail message.
         */
        public VerificationException(String msg)
        {
            super(msg);
        }
    }
}
