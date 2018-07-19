# OpenPGP for XMPP Instant Messaging Demo Client

This command line XMPP client is part of my [Summer of Code 2018 project](https://vanitasvitae.github.io/GSOC2018/).
It demonstrates the capabilities of the OX-IM-API I wrote.

### OpenPGP for XMPP: Instant Messaging

The client implements [XEP-0373](https://xmpp.org/extensions/xep-0373.html) and [XEP-0374](https://xmpp.org/extensions/xep-0374.html) in order to encrypt messages using [OpenPGP](https://tools.ietf.org/html/rfc4880).

### Installation

In order to install the client, you have to follow these steps:
```
# create a working directory
mkdir ox
cd ox

# Prepare Smack
git clone https://github.com/vanitasvitae/Smack.git
cd Smack
git checkout 12c7b3aebf446c20e4f35f2ca354f7b637486b06
gradle install

# prepare the client
cd ..
git clone https://github.com/vanitasvitae/oxclient.git
cd oxclient
gradle build
```

### Running the client

The last command above generates the executable `build/libs/oxclient-1.0-SNAPSHOT.jar`.
That can be executed using

```
java -jar build/libs/oxclient-1.0-SNAPSHOT.jar
```
