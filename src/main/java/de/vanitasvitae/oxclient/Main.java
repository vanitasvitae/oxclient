/*
 * Copyright 2018 Paul Schaub
 *
 * This file is part of OXClient.
 *
 * OXClient is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */
package de.vanitasvitae.oxclient;

import java.util.Scanner;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jivesoftware.smack.SmackConfiguration;

public class Main {

    public static void main(String[] args) throws Exception {

        /*
        SmackConfiguration.DEBUG = true;
        /*/
        SmackConfiguration.DEBUG = false;
        //*

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
