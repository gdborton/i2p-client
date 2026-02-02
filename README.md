# Sam

```typescript
const samHost = "127.0.0.1";
const samTcpPort = 7656;
const samUdpPort = 7655;

// create a new destination
const destination = await generateDestination({
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

// creating a `fetch` function that works with i2p without a proxy
import { createFetch } from "i2p-client/utils/fetch";

const fetch = createFetch({ session: primarySession });

fetch("someAddress.i2p");
```

# I2CP

> [!WARNING]  
> It's not recommended to use I2CP. SAM should cover all your needs.

```typescript
const session1 = new I2CPSession({
  i2cpHost: "localhost",
  i2cpPort,
  // you can optionally pass a LocalDestination instance
});
const session2 = new I2CPSession({
  i2cpHost: "localhost",
  i2cpPort,
});

const session1Ready = new Promise((resolve) => {
  session1.on("session_created", () => {
    resolve(true);
  });
});

const session2Ready = new Promise((resolve) => {
  session2.on("session_created", () => {
    resolve(true);
  });
});
await session1Ready;
await session2Ready;

// Repliable Datagrams
const session1PortNumber = 13;
const session2PortNumber = 14;
const session1Port = session1.connect(session1PortNumber);
const session2Port = session1.connect(session2PortNumber);

session1Port.sendRepliableDatagram(
  session1.getDestinationBuffer(),
  session1PortNumber, // from port
  session2PortNumber, // to port
);

session2Port.on("repliableMessage", (from, fromPort, payload) => {
  console.log("got a message!");
});

// Streaming

const stream = session1.createStream(session2.getDestinationBuffer());
stream.write("Hello World!");

session2.on("stream", (stream) => {
  stream.on("data", (data) => {
    console.log(String(data)); // Hello World!
  });
});
```
