package de.vanitasvitae.oxclient;

import java.io.File;
import java.util.Scanner;
import java.util.Set;

import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.roster.RosterEntry;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smackx.ox.OXInstantMessagingManager;
import org.jivesoftware.smackx.ox.OpenPgpManager;
import org.jivesoftware.smackx.ox.OpenPgpV4Fingerprint;
import org.jivesoftware.smackx.ox.PubSubDelegate;
import org.jivesoftware.smackx.ox.bouncycastle.BCOpenPgpProvider;
import org.jivesoftware.smackx.ox.bouncycastle.FileBasedBcOpenPgpStore;
import org.jivesoftware.smackx.ox.callback.SecretKeyBackupSelectionCallback;
import org.jivesoftware.smackx.ox.callback.SecretKeyRestoreSelectionCallback;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import org.jxmpp.jid.BareJid;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

public class Client {

    private final XMPPTCPConnection connection;

    public Client(String username, String password) throws XmppStringprepException {
        this.connection = new XMPPTCPConnection(username, password);
    }

    public void start() throws Exception {
        BouncyGPG.registerProvider();
        connection.connect().login();
        Scanner scanner = new Scanner(System.in);

        BareJid user = connection.getUser().asBareJid();
        OpenPgpManager manager = OpenPgpManager.getInstanceFor(connection);
        BCOpenPgpProvider provider = new BCOpenPgpProvider(user);
        FileBasedBcOpenPgpStore store = new FileBasedBcOpenPgpStore(new File("oxstore"), user,
                KeyringConfigCallbacks.withUnprotectedKeys());
        provider.setStore(store);
        manager.setOpenPgpProvider(provider);

        OXInstantMessagingManager instantManager = OXInstantMessagingManager.getInstanceFor(connection);
        instantManager.addOpenPgpEncryptedMessageListener((from, originalMessage, decryptedPayload, chat) -> System.out.println("Received OX chat message from " + from + ":\n" +
                decryptedPayload.<Message.Body>getExtension(
                        Message.Body.ELEMENT, Message.Body.NAMESPACE)
                        .getMessage()));
        instantManager.announceSupportForOxInstantMessaging();

        Roster.getInstanceFor(connection).setSubscriptionMode(Roster.SubscriptionMode.accept_all);

        System.out.println("Client logged in successfully. To get a list of available commands, enter \"help\".");

        BareJid jid;
        outerloop: while (true) {
            String cmd = scanner.nextLine();
            switch (cmd) {
                case "publishKeys":
                    if (provider.primaryOpenPgpKeyPairFingerprint() == null) {
                        System.out.println("No private key available. Try to generate one using \"generateKey\"");
                        break;
                    }
                    manager.announceSupportAndPublish();
                    System.out.println("Keys published successfully.");
                    break;

                case "listContacts":
                    for (RosterEntry e : Roster.getInstanceFor(connection).getEntries()) {
                        System.out.println(e.getJid() +
                                " canSeeMe: " + e.canSeeMyPresence() +
                                " canSeeThem: " + e.canSeeHisPresence() +
                                " OX-support: " + instantManager.contactSupportsOxInstantMessaging(e.getJid()));
                    }
                    break;

                case "addContact":
                    System.out.println("Enter a JID:");
                    jid = JidCreate.bareFrom(scanner.nextLine());
                    System.out.println("Enter a Nickname:");
                    String nick = scanner.nextLine();

                    Roster.getInstanceFor(connection).createEntry(jid, nick, null);
                    break;

                case "exit":
                case "quit":
                    connection.disconnect(new Presence(Presence.Type.unavailable));
                    System.out.println("Bye Bye!");
                    break outerloop;

                case "generateKey":
                    provider.createOpenPgpKeyPair();
                    System.out.println("Key generated.");
                    System.out.println(manager.getOurFingerprint());
                    break;

                case "deleteMetadata":
                    PubSubDelegate.deletePubkeysListNode(connection);
                    System.out.println("Metadata deleted.");
                    break;

                case "fingerprint":
                    System.out.println("Enter a JID (leave empty to display our fingerprint):");
                    String l = scanner.nextLine();

                    if (l.isEmpty()) {
                        System.out.println(provider.primaryOpenPgpKeyPairFingerprint());
                    } else {
                        jid = JidCreate.bareFrom(l);
                        for (OpenPgpV4Fingerprint f : provider.availableOpenPgpPublicKeysFingerprints(jid)) {
                            System.out.println(f);
                        }
                    }
                    break;

                case "encrypt":
                    if (provider.primaryOpenPgpKeyPairFingerprint() == null) {
                        System.out.println("No private key available. Try to generate one using \"generateKey\"");
                        break;
                    }
                    System.out.println("Enter a JID:");
                    jid = JidCreate.entityBareFrom(scanner.nextLine());
                    System.out.println("Enter a message:");
                    String message = scanner.nextLine();

                    instantManager.chatWith(((EntityBareJid) jid).asEntityBareJid())
                            .send(new Message(jid), message);
                    System.out.println("Message sent.");
                    break;

                case "backup":
                    if (provider.primaryOpenPgpKeyPairFingerprint() == null) {
                        System.out.println("No private key available. Try to generate one using \"generateKey\"");
                        break;
                    }
                    manager.backupSecretKeyToServer(
                            System.out::println,
                            availableSecretKeys -> availableSecretKeys);
                    break;

                case "restore":
                    manager.restoreSecretKeyServerBackup(
                            () -> {
                                System.out.println("Enter Backup Code:");
                                return scanner.nextLine();
                            },
                            availableSecretKeys -> {
                                if (availableSecretKeys.size() > 1) {
                                    System.out.println("Select key to restore:");
                                    int i = 1;
                                    for (OpenPgpV4Fingerprint f : availableSecretKeys) {
                                        System.out.println(i++ + f.toString());
                                    }
                                    int s = scanner.nextInt();
                                    i = 1;
                                    for (OpenPgpV4Fingerprint f : availableSecretKeys) {
                                        if (i++ == s) {
                                            return f;
                                        }
                                    }
                                    System.out.println("Invalid selection.");
                                    return null;
                                }
                                if (availableSecretKeys.size() == 1) {
                                    return availableSecretKeys.iterator().next();
                                }
                                System.out.println("Backup does not contain a key.");
                                return null;
                            });
                    System.out.println(manager.getOurFingerprint());
                    break;

                case "help":
                    System.out.println("Available commands:");
                    System.out.println("\tfingerprint - Display OpenPGP fingerprints of users.");
                    System.out.println("\tlistContacts - List the roster of contacts.");
                    System.out.println("\taddContact - Add a user to the roster.");
                    System.out.println("\tencrypt - Send an encrypted message to a recipient.");
                    System.out.println("\tgenerateKey - Generate and use a fresh OpenPGP key.");
                    System.out.println("\tpublishKeys - Publish public keys.");
                    System.out.println("\tbackup - Put a backup of our secret keys into a private pubsub node.");
                    System.out.println("\trestore - Restore a secret key backup.");
                    System.out.println("\texit/quit - Exit the client.");
                    break;
            }
        }
    }
}
