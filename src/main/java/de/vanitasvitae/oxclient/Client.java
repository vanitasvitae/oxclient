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

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Scanner;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smackx.ox.OpenPgpContact;
import org.jivesoftware.smackx.ox.OpenPgpManager;
import org.jivesoftware.smackx.ox.OpenPgpSelf;
import org.jivesoftware.smackx.ox.crypto.OpenPgpProvider;
import org.jivesoftware.smackx.ox.crypto.PainlessOpenPgpProvider;
import org.jivesoftware.smackx.ox.element.SigncryptElement;
import org.jivesoftware.smackx.ox.exception.InvalidBackupCodeException;
import org.jivesoftware.smackx.ox.exception.MissingOpenPgpKeyException;
import org.jivesoftware.smackx.ox.exception.MissingUserIdOnKeyException;
import org.jivesoftware.smackx.ox.exception.NoBackupFoundException;
import org.jivesoftware.smackx.ox.store.definition.OpenPgpStore;
import org.jivesoftware.smackx.ox.store.definition.OpenPgpTrustStore;
import org.jivesoftware.smackx.ox.store.filebased.FileBasedOpenPgpStore;

import org.jivesoftware.smackx.ox.util.OpenPgpPubSubUtil;
import org.jivesoftware.smackx.ox_im.OXInstantMessagingManager;
import org.jivesoftware.smackx.ox_im.OxMessageListener;
import org.jivesoftware.smackx.pubsub.PubSubException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.Jid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class Client {

    private XMPPTCPConnection connection;
    private OpenPgpStore store;
    private OpenPgpProvider provider;
    private OpenPgpManager openPgpManager;
    private OXInstantMessagingManager oxManager;
    private OpenPgpSelf self;
    private Scanner scanner;

    static {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }

    public Client(String username, String password) throws XmppStringprepException {
        this.connection = new XMPPTCPConnection(username, password);
        this.store = new FileBasedOpenPgpStore(new File("store" + File.separator + username));
    }

    void start() throws InterruptedException, XMPPException, SmackException, IOException, PGPException {
        connection.connect().login();
        scanner = new Scanner(System.in);

        provider = new PainlessOpenPgpProvider(connection, store);
        openPgpManager = OpenPgpManager.getInstanceFor(connection);
        openPgpManager.setOpenPgpProvider(provider);

        oxManager = OXInstantMessagingManager.getInstanceFor(connection);
        oxManager.addOxMessageListener(new OxMessageListener() {
            @Override
            public void newIncomingOxMessage(OpenPgpContact openPgpContact, Message message, SigncryptElement signcryptElement, OpenPgpMetadata openPgpMetadata) {
                Message.Body body = signcryptElement.getExtension(Message.Body.ELEMENT, Message.Body.NAMESPACE);
                if (body != null) {
                    System.out.println(message.getFrom() + ": " + body.getMessage());
                }
            }
        });

        self = openPgpManager.getOpenPgpSelf();

        while (true) {
            try {
                loop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void loop() throws Exception {
        String line = scanner.nextLine();
        switch (line != null ? line.trim() : "") {
            case "/prepare":
                prepare();
                break;

            case "/encrypt":
                encrypt();
                break;

            case "/backup":
                backup();
                break;

            case "/fingerprint":
                fingerprint();
                break;

            case "/update":
                update();
                break;

            case "/trust":
                trust();
                break;

            case "/exit":
            case "/quit":
                exit();
                break;

            case "/deleteMetadata":
                deleteMetadata();
                break;
        }
        System.out.println("done.");
    }

    private void deleteMetadata() throws XMPPException.XMPPErrorException, SmackException.NotLoggedInException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, IOException {
        openPgpManager.deleteSecretKeyServerBackup();
        for (OpenPgpV4Fingerprint f : store.getAnnouncedFingerprintsOf(self.getJid()).keySet()) {
            try {
                OpenPgpPubSubUtil.deletePublicKeyNode(connection, f);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        OpenPgpPubSubUtil.deletePubkeysListNode(connection);
    }

    private void update() throws IOException, InterruptedException, SmackException.NoResponseException, PubSubException.NotAPubSubNodeException, SmackException.NotConnectedException, XMPPException.XMPPErrorException, PubSubException.NotALeafNodeException {
        System.out.println("Enter a Jid:");
        BareJid jid = JidCreate.bareFrom(scanner.nextLine());
        OpenPgpContact contact = openPgpManager.getOpenPgpContact(jid.asEntityBareJidIfPossible());
        contact.updateKeys(connection);
    }

    private void trust() throws IOException, PGPException {
        System.out.println("Enter a JID:");
        BareJid jid = JidCreate.bareFrom(scanner.nextLine());
        OpenPgpContact contact = openPgpManager.getOpenPgpContact(jid.asEntityBareJidIfPossible());
        for (PGPPublicKeyRing publicKey : contact.getAnyPublicKeys()) {
            OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(publicKey);
            System.out.println(fingerprint + " " + contact.getTrust(fingerprint));
            OpenPgpTrustStore.Trust trust = null;
            while (trust == null) {
                try {
                    trust = OpenPgpTrustStore.Trust.valueOf(scanner.nextLine());
                } catch (IllegalArgumentException | NullPointerException e) {
                    System.out.println("Try again.");
                }
            }
            store.setTrust(jid, fingerprint, trust);
            System.out.println("Key " + fingerprint + " is now " + trust);
        }
    }

    private void fingerprint() throws IOException, PGPException {
        System.out.println("Enter a jid or leave empty");
        String l = scanner.nextLine();
        if (l.isEmpty()) {
            OpenPgpV4Fingerprint fingerprint = self.getSigningKeyFingerprint();
            System.out.println(fingerprint != null ? fingerprint.toString() : "null");
        } else {
            Jid jid = JidCreate.bareFrom(l);
            OpenPgpContact contact = openPgpManager.getOpenPgpContact(jid.asEntityBareJidIfPossible());
            PGPPublicKeyRingCollection publicKeyRings = contact.getAnnouncedPublicKeys();
            for (PGPPublicKeyRing key : publicKeyRings) {
                System.out.println(new OpenPgpV4Fingerprint(key));
            }
        }
    }

    private void exit() throws SmackException.NotConnectedException {
        connection.disconnect(new Presence(Presence.Type.unavailable));
        System.exit(0);
    }

    private void prepare() throws IOException, PGPException, InterruptedException, PubSubException.NotALeafNodeException, SmackException.NoResponseException, SmackException.NotConnectedException, XMPPException.XMPPErrorException, SmackException.NotLoggedInException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        if (self.hasSecretKeyAvailable()) {
            System.out.println("You already have key " + new OpenPgpV4Fingerprint(self.getSigningKeyRing()).toString() + " available.");
            openPgpManager.announceSupportAndPublish();
            oxManager.announceSupportForOxInstantMessaging();
            return;
        }

        try {
            openPgpManager.restoreSecretKeyServerBackup(() -> scanner.nextLine());
            openPgpManager.announceSupportAndPublish();
            oxManager.announceSupportForOxInstantMessaging();
            return;
        } catch (MissingUserIdOnKeyException e) {
            System.out.println("Invalid key.");
            e.printStackTrace();
        } catch (InvalidBackupCodeException e) {
            System.out.println("Wrong backup password.");
            e.printStackTrace();
            return;
        } catch (NoBackupFoundException e) {
            System.out.println("No Backup found.");
        }

        System.out.println("Generate new key? (y/n)");
        String answer = scanner.nextLine().trim().toLowerCase();
        if (answer.equals("y")) {
            openPgpManager.generateAndImportKeyPair(self.getJid());
            openPgpManager.announceSupportAndPublish();
            oxManager.announceSupportForOxInstantMessaging();
        }
    }

    private void encrypt() throws IOException, InterruptedException, PGPException, SmackException.NotConnectedException, SmackException.NotLoggedInException {
        System.out.println("Enter the recipients jid:");
        BareJid jid = JidCreate.bareFrom(scanner.nextLine());
        System.out.println("Enter a message:");
        String message = scanner.nextLine();
        oxManager.sendOxMessage(openPgpManager.getOpenPgpContact(jid.asEntityBareJidIfPossible()),
                message);
    }


    private void backup() throws IOException, MissingOpenPgpKeyException, SmackException.FeatureNotSupportedException, SmackException.NotLoggedInException, InterruptedException, XMPPException.XMPPErrorException, PGPException, PubSubException.NotALeafNodeException, SmackException.NotConnectedException, SmackException.NoResponseException {
        openPgpManager.backupSecretKeyToServer(System.out::println, set -> set);
    }
}
