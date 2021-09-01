package client;

import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as the Driver to the program. It checks the command line 
 * arguments and sets a Look and Feel depending on what they are, before 
 * starting a new GUI for the user to login.
 * </pre>
 */
public class Driver
{
    /**
     * Entry point to the program.
     * 
     * @param args The command line args. 
     */
    public static void main(String... args)
    {    
        int laf = 1;
        
        // If there were no command line arguments specified, print and return.
        if (args.length != 1)
        {
            System.out.println("Usage: java ChatterBox [-colortheme]");
            return;
        }
        else
        {
            // Depending on what the user entered, set the laf variable to it.
            if (args[0].equals("dark"))
                laf = 0;
            else if (args[0].equals("light"))
                laf = 1;
            else
                throw ExceptionFactory.getInvalidColorThemeException("Invalid "
                        + "Color Theme. Must be either \"light\" or \"dark\"");      
        } 
        
        try
        {
            // Depending on what the LAF was, set the correct LaF.
            if (laf == 0)
                UIManager.setLookAndFeel("com.formdev.flatlaf.FlatDarculaLaf");
            else
                UIManager.setLookAndFeel("com.formdev.flatlaf.FlatIntelliJLaf");
            
        } catch (ClassNotFoundException | InstantiationException | 
                IllegalAccessException | UnsupportedLookAndFeelException ex)
        {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
        }
        
        // Create and display the dialog 
        LoginFrame startGUI = new LoginFrame();
        startGUI.setVisible(true);
    }
}
