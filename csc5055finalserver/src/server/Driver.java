package server;

import java.util.Scanner;

/**
 * <pre>
 * Author(s): Jared Rathbun, Alexander Royer, and Camron Chrissis 
 * Course: CSC5055 - Network Security 1
 * Due Date: May 11, 2021 @ 11:30am
 *
 * This class serves as the Driver to the program. It prompts the user for a 
 * port number creates a new Server object with that port.
 * </pre>
 */
public class Driver
{
    /**
     * @param args The command line arguments.
     */
    public static void main(String[] args)
    {
        new Server(promptUser()).start();
        System.out.println("Server started.");
    }
    
    /**
     * This method prompts the user for a port number and returns it represented
     * as an integer.
     * 
     * @return The port number.
     */
    private static int promptUser()
    {
        System.out.println("Welcome to the ChatterBox Server interface!");
        
        Scanner input = new Scanner(System.in);
        
        System.out.print("Please enter the port number to listen on: ");
        
        return input.nextInt();
    }
}
