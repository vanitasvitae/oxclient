package de.vanitasvitae.oxclient;

import java.util.Scanner;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jivesoftware.smack.SmackConfiguration;

public class Main {

    public static void main(String[] args) throws Exception {

        SmackConfiguration.DEBUG = true;
        SmackConfiguration.setDefaultReplyTimeout(10 * 1000);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.FINER);
        Logger.getGlobal().addHandler(handler);

        String username, password;
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter your JID:");
        username = scanner.nextLine();
        System.out.println("Please enter your password:");
        password = scanner.nextLine();

        Client client = new Client(username, password);
        client.start();
    }
}
