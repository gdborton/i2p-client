# Same Usage

Creating a destination:

```typescript
const samHost = "127.0.0.1";
const samTcpPort = 7656;
const samUdpPort = 7655;

const destination = await SAM.generateDestination({
  host: samHost,
  port: samTcpPort,
});

const primarySession = new PrimarySession({
  host: samHost,
  tcpPort: samTcpPort,
  udpPort: samUdpPort,
  publicKey: destination.public,
  privateKey: destination.private,
});

// Datagram Sessions

const listenPort = 14;
const datagramSession = await primarySession.getOrCreateSubsession(
  "my-application-name",
  "DATAGRAM",
  samUdpPort,
  listenPort, // <-- optional: the i2p port to listen on for incoming DATAGRAM requests
);

// incoming message
datagramSession.on(
  "repliableDatagram",
  (obj: {
    destination: string;
    fromPort: number;
    toPort: number;
    payload: Buffer;
  }) => {},
);

// outgoing data
datagramSession.sendRepliableDatagram(
  destination.public, // base64 or base32 destination, router support varies base64 is safer
  13, // the i2p port to send FROM
  14, // the i2p port to send TO
  payload, // the payload to send
);

// Raw Datagram Sessions
const rawDatagramSession = await primarySession.getOrCreateSubsession(
  "raw1",
  "RAW",
  13, // optional: the i2p port to list on for incoming RAW requests
);

rawDatagramSession.on("rawDatagram", (payload: Buffer) => {});

const payload = Buffer.from("Hello World!");

rawDatagramSession.sendRawDatagram(
  destination.public, // base64 or base32 destination, router support varies base64 is safer
  13, // the i2p port to send FROM
  14, // the i2p port to send TO
  payload, // the payload to send
);

// streaming

const streamSession = await primarySession.getOrCreateSubsession(
  "my-streaming-app",
  "STREAM", // the type of session you're creating
  0, // optional: the port that you want to listen on for incoming streams
);

// outgoing connections
const stream = await streamSession.createStream({
  destination: dest2.public,
  fromPort: 0,
  toPort: 0,
});
// ^ stream is a socket that you can use to send data to the remote destination

streamSession.on("stream", (stream: Socket) => {
  stream.write("HI");
});
```
