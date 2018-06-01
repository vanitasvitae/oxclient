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
git checkout c9c22068a3e07d44c88225f04bbf47189caae3f9
gradle install

# Prepare pgpainless
cd ..
git clone https://github.com/vanitasvitae/pgpainless.git
cd pgpainless
git checkout 9af42c7231a6837694461e087ef5b3c51e451ef5
gradle install

# prepare the client
cd ..
git clone https://github.com/vanitasvitae/oxclient.git
cd oxclient
gradle build
```

### Running the client

The last command above generates the executable `build/libs/cmd-1.0-SNAPSHOT.jar`.
That can be executed using

```
java -jar build/libs/cmd-1.0-SNAPSHOT.jar
```