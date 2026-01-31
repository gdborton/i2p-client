import { describe, it, beforeAll, expect } from "vitest";
import {
  SAM,
  StreamAcceptSocket,
  type RepliableDatagramEvent,
} from "../../src/sam";
import { isTcpPortOpen, isUdpPortOpen } from "./test-utils";

const WAIT_FOR_DATAGRAM_TIMEOUT = 5_000;

describe(
  "SAM",
  {
    timeout: 40_000,
    retry: 3, // ideally we don't need this, I don't seem to need it on local, but GH is sporadically failing
  },
  () => {
    const samHost = "127.0.0.1";
    const samTcpPort = 7656;
    const samUdpPort = 7655;

    beforeAll(async () => {
      // Check required ports
      const tcpOpen = await isTcpPortOpen(samTcpPort, samHost);
      const udpOpen = await isUdpPortOpen(samUdpPort, samHost);
      if (!tcpOpen)
        throw new Error(`SAM TCP port ${samTcpPort} not open on ${samHost}`);
      if (!udpOpen)
        throw new Error(`SAM UDP port ${samUdpPort} not open on ${samHost}`);
    });

    describe("SAM integration: repliable datagrams", () => {
      it("should establish two destinations and exchange repliable datagrams", async () => {
        // Generate destinations
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        // Start primary sessions for each destination
        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort, // use standard default UDP port
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort, // use standard default UDP port
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create repliable datagram sessions from primary sessions
        const dgram1 = await primary1.getOrCreateSubsession(
          "dgram1",
          "DATAGRAM",
          samUdpPort,
        );
        const dgram2 = await primary2.getOrCreateSubsession(
          "dgram2",
          "DATAGRAM",
          samUdpPort,
        );

        // Listen for messages on dgram2
        const waitForMessage = () =>
          new Promise<RepliableDatagramEvent>((resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for datagram")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            dgram2.once("repliableDatagram", (obj) => {
              clearTimeout(timeout);
              resolve(obj);
            });
          });

        // Send a datagram from dgram1 to dgram2
        const testPayload = Buffer.from("hello from dgram1");
        // Use the actual UDP port assigned to dgram2 for destination
        await dgram1.sendRepliableDatagram(
          dest2.public,
          samUdpPort,
          samUdpPort,
          testPayload,
        );

        // Wait for datagram on dgram2
        const obj = await waitForMessage();
        expect(obj.payload.toString()).toBe("hello from dgram1");
        // Optionally check sender address if available

        // Send a reply from dgram2 to dgram1
        const replyPayload = Buffer.from("hello from dgram2");
        // Use the actual UDP port assigned to dgram1 for destination
        await dgram2.sendRepliableDatagram(
          dest1.public,
          samUdpPort,
          samUdpPort,
          replyPayload,
        );

        // Wait for reply on dgram1
        const reply = await new Promise<RepliableDatagramEvent>(
          (resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for reply")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            dgram1.once("repliableDatagram", (obj) => {
              clearTimeout(timeout);
              resolve(obj);
            });
          },
        );
        expect(reply.payload.toString()).toBe("hello from dgram2");

        // Cleanup (add close methods if available)
        // dgram1.close?.();
        // dgram2.close?.();
        // If SAM has a close method, call it here
      });
    });

    describe("SAM integration: raw datagrams", () => {
      it("should establish two destinations and exchange raw datagrams", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create raw datagram sessions from primary sessions
        const raw1 = await primary1.getOrCreateSubsession("raw1", "RAW");
        const raw2 = await primary2.getOrCreateSubsession("raw2", "RAW");

        // Listen for raw datagrams on raw2
        const waitForRawDatagram = () =>
          new Promise<Buffer>((resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for datagram")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            raw2.once("rawDatagram", (msg: Buffer) => {
              clearTimeout(timeout);
              resolve(msg);
            });
          });

        // Send a datagram from raw1 to raw2
        const testPayload = Buffer.from("hello from raw1");
        await raw1.sendRawDatagram(
          dest2.public,
          samUdpPort,
          samUdpPort,
          testPayload,
        );

        // Wait for datagram on raw2
        const msg = await waitForRawDatagram();
        expect(msg.toString()).toBe("hello from raw1");

        // Send a reply from raw2 to raw1
        const replyPayload = Buffer.from("hello from raw2");
        await raw2.sendRawDatagram(
          dest1.public,
          samUdpPort,
          samUdpPort,
          replyPayload,
        );

        // Wait for reply on raw1
        const reply = await new Promise<Buffer>((resolve, reject) => {
          const timeout = setTimeout(
            () => reject(new Error("Timeout waiting for reply")),
            WAIT_FOR_DATAGRAM_TIMEOUT,
          );
          raw1.once("rawDatagram", (msg: Buffer) => {
            clearTimeout(timeout);
            resolve(msg);
          });
        });
        expect(reply.toString()).toBe("hello from raw2");
      });
    });

    describe("SAM integration: streaming data between destinations", () => {
      it("should create two destinations and stream data to each other", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0, // not used for STREAM, but required by constructor
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0, // not used for STREAM, but required by constructor
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create STREAM sessions from primary sessions
        const stream1 = await primary1.getOrCreateSubsession(
          "stream1",
          "STREAM",
        );
        const stream2 = await primary2.getOrCreateSubsession(
          "stream2",
          "STREAM",
        );

        // Listen for incoming connections on stream2
        const incomingConnection: Promise<StreamAcceptSocket> = new Promise(
          (resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for stream connection")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            stream2.once("stream", (socket: StreamAcceptSocket) => {
              clearTimeout(timeout);
              resolve(socket);
            });
          },
        );

        // stream1 creates a stream to stream2's destination
        const clientSocket = await stream1.createStream({
          destination: dest2.public,
          fromPort: 0,
          toPort: 0,
        });
        const serverSocket = await incomingConnection;

        // Send data from client to server
        const testPayload = Buffer.from("hello from stream1");
        clientSocket.write(testPayload);

        // Receive data on server
        const received: Buffer = await new Promise((resolve, reject) => {
          let data = Buffer.alloc(0);
          const timeout = setTimeout(
            () => reject(new Error("Timeout waiting for stream data")),
            WAIT_FOR_DATAGRAM_TIMEOUT,
          );
          serverSocket.on("data", (chunk: Buffer) => {
            data = Buffer.concat([data, chunk]);
            if (data.length >= testPayload.length) {
              clearTimeout(timeout);
              resolve(data);
            }
          });
        });
        expect(received.toString()).toBe("hello from stream1");

        // Send reply from server to client
        const replyPayload = Buffer.from("hello from stream2");
        serverSocket.write(replyPayload);

        // Receive reply on client
        const reply: Buffer = await new Promise((resolve, reject) => {
          let data = Buffer.alloc(0);
          const timeout = setTimeout(
            () => reject(new Error("Timeout waiting for stream reply")),
            WAIT_FOR_DATAGRAM_TIMEOUT,
          );
          clientSocket.on("data", (chunk: Buffer) => {
            data = Buffer.concat([data, chunk]);
            if (data.length >= replyPayload.length) {
              clearTimeout(timeout);
              resolve(data);
            }
          });
        });
        expect(reply.toString()).toBe("hello from stream2");

        // Cleanup
        clientSocket.destroy();
        serverSocket.destroy();
        // Optionally close sessions if supported
      });

      it("should establish multiple streams to the same destination and send unique data", async () => {
        const destA = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const destB = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primaryA = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: destA.public,
          privateKey: destA.private,
        });
        const primaryB = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: destB.public,
          privateKey: destB.private,
        });

        // Create STREAM sessions
        const streamA = await primaryA.getOrCreateSubsession(
          "streamA",
          "STREAM",
        );
        const streamB = await primaryB.getOrCreateSubsession(
          "streamB",
          "STREAM",
        );

        const clientSockets: any[] = [];
        const serverSockets: StreamAcceptSocket[] = [];
        const receivedData: string[] = [];

        // Listen for incoming connections on streamB
        streamB.on("stream", (socket: StreamAcceptSocket) => {
          serverSockets.push(socket);
          let data = Buffer.alloc(0);
          socket.on("data", (chunk: Buffer) => {
            data = Buffer.concat([data, chunk]);
            if (data.length >= 5) {
              // "dataX" is 5 chars
              receivedData.push(data.toString());
            }
          });
        });

        // Create three streams from A to B and send unique data
        for (let i = 1; i <= 3; i++) {
          const clientSocket = await streamA.createStream({
            destination: destB.public,
            fromPort: 0,
            toPort: 0,
          });
          clientSockets.push(clientSocket);
          clientSocket.write(Buffer.from(`data${i}`));
        }

        // Wait for all data to be received
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(
            () => reject(new Error("Timeout waiting for all stream data")),
            WAIT_FOR_DATAGRAM_TIMEOUT * 3,
          );
          const check = () => {
            if (receivedData.length === 3) {
              clearTimeout(timeout);
              resolve();
            } else {
              setTimeout(check, 100);
            }
          };
          check();
        });

        expect(serverSockets.length).toBe(3);

        // Check that all unique data was received
        expect(receivedData.sort()).toEqual(["data1", "data2", "data3"]);

        // Cleanup
        clientSockets.forEach((socket) => socket.destroy());
        serverSockets.forEach((socket) => socket.destroy());
      });
    });

    describe("SAM integration: repliable datagrams port filtering", () => {
      it("should listen on port 13 and NOT get messages sent to port 14", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create repliable datagram sessions with specific ports
        const dgram1 = await primary1.getOrCreateSubsession(
          "dgram1",
          "DATAGRAM",
          13,
        );
        const dgram2 = await primary2.getOrCreateSubsession(
          "dgram2",
          "DATAGRAM",
          13,
        );

        // Send a datagram to port 14
        const testPayload = Buffer.from("hello to port 14");
        await dgram1.sendRepliableDatagram(
          dest2.public,
          13,
          14, // wrong port
          testPayload,
        );

        // Wait a bit and check no message received
        let received = false;
        dgram2.once("repliableDatagram", () => {
          received = true;
        });
        await new Promise((resolve) => setTimeout(resolve, 5000));
        expect(received).toBe(false);
      });

      it("should listen on port 13 and SHOULD get messages sent to port 13", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create repliable datagram sessions with specific ports
        const dgram1 = await primary1.getOrCreateSubsession(
          "dgram1",
          "DATAGRAM",
          13,
        );
        const dgram2 = await primary2.getOrCreateSubsession(
          "dgram2",
          "DATAGRAM",
          13,
        );

        // Listen for messages on dgram2
        const waitForMessage = () =>
          new Promise<RepliableDatagramEvent>((resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for datagram")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            dgram2.once("repliableDatagram", (obj) => {
              clearTimeout(timeout);
              resolve(obj);
            });
          });

        // Send a datagram to port 13
        const testPayload = Buffer.from("hello to port 13");
        await dgram1.sendRepliableDatagram(
          dest2.public,
          13,
          13, // correct port
          testPayload,
        );

        // Wait for datagram on dgram2
        const obj = await waitForMessage();
        expect(obj.payload.toString()).toBe("hello to port 13");
      });
    });

    describe("SAM integration: raw datagrams port filtering", () => {
      it("should listen on port 13 and NOT get messages sent to port 14", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create raw datagram sessions with specific ports
        const raw1 = await primary1.getOrCreateSubsession("raw1", "RAW", 13);
        const raw2 = await primary2.getOrCreateSubsession("raw2", "RAW", 13);

        // Send a datagram to port 14
        const testPayload = Buffer.from("hello to port 14");
        await raw1.sendRawDatagram(
          dest2.public,
          13,
          14, // wrong port
          testPayload,
        );

        // For raw datagrams, since no port filtering, it will receive
        const waitForRawDatagram = () =>
          new Promise<Buffer>((resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for datagram")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            raw2.once("rawDatagram", (msg: Buffer) => {
              clearTimeout(timeout);
              resolve(msg);
            });
          });

        // Wait for datagram on raw2
        await expect(waitForRawDatagram()).rejects.toThrow(
          "Timeout waiting for datagram",
        );
      });

      it("should listen on port 13 and SHOULD get messages sent to port 13", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: samUdpPort,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create raw datagram sessions with specific ports
        const raw1 = await primary1.getOrCreateSubsession("raw1", "RAW", 13);
        const raw2 = await primary2.getOrCreateSubsession("raw2", "RAW", 13);

        // Listen for raw datagrams on raw2
        const waitForRawDatagram = () =>
          new Promise<Buffer>((resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for datagram")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            raw2.once("rawDatagram", (msg: Buffer) => {
              clearTimeout(timeout);
              resolve(msg);
            });
          });

        // Send a datagram to port 13
        const testPayload = Buffer.from("hello to port 13");
        await raw1.sendRawDatagram(
          dest2.public,
          13,
          13, // correct port
          testPayload,
        );

        // Wait for datagram on raw2
        const msg = await waitForRawDatagram();
        expect(msg.toString()).toBe("hello to port 13");
      });
    });

    describe("SAM integration: streaming data port filtering", () => {
      it("should listen on port 13 and NOT get connections sent to port 14", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create STREAM sessions with specific ports
        const stream1 = await primary1.getOrCreateSubsession(
          "stream1",
          "STREAM",
          13,
        );
        const stream2 = await primary2.getOrCreateSubsession(
          "stream2",
          "STREAM",
          13,
        );
        // Try to create a stream to port 14
        const clientSocket = await stream1.createStream({
          destination: dest2.public,
          fromPort: 13,
          toPort: 14, // wrong port
        });

        // Wait a bit and check no connection received
        let connected = false;
        stream2.once("stream", () => {
          connected = true;
        });
        await new Promise((resolve) => setTimeout(resolve, 5000));
        expect(connected).toBe(false);

        clientSocket.destroy();
      });

      it("should listen on port 13 and SHOULD get connections sent to port 13", async () => {
        const dest1 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });
        const dest2 = await SAM.generateDestination({
          host: samHost,
          port: samTcpPort,
        });

        const { PrimarySession } = await import("../../src/sam");
        const primary1 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: dest1.public,
          privateKey: dest1.private,
        });
        const primary2 = new PrimarySession({
          host: samHost,
          tcpPort: samTcpPort,
          udpPort: 0,
          publicKey: dest2.public,
          privateKey: dest2.private,
        });

        // Create STREAM sessions with specific ports
        const stream1 = await primary1.getOrCreateSubsession(
          "stream1",
          "STREAM",
          13,
        );
        const stream2 = await primary2.getOrCreateSubsession(
          "stream2",
          "STREAM",
          13,
        );

        // Listen for incoming connections on stream2
        const incomingConnection: Promise<StreamAcceptSocket> = new Promise(
          (resolve, reject) => {
            const timeout = setTimeout(
              () => reject(new Error("Timeout waiting for stream connection")),
              WAIT_FOR_DATAGRAM_TIMEOUT,
            );
            stream2.once("stream", (socket: StreamAcceptSocket) => {
              clearTimeout(timeout);
              resolve(socket);
            });
          },
        );

        // stream1 creates a stream to stream2's destination on port 13
        const clientSocket = await stream1.createStream({
          destination: dest2.public,
          fromPort: 13,
          toPort: 13, // correct port
        });
        const serverSocket = await incomingConnection;

        // Send data from client to server
        const testPayload = Buffer.from("hello to port 13");
        clientSocket.write(testPayload);

        // Receive data on server
        const received: Buffer = await new Promise((resolve, reject) => {
          let data = Buffer.alloc(0);
          const timeout = setTimeout(
            () => reject(new Error("Timeout waiting for stream data")),
            WAIT_FOR_DATAGRAM_TIMEOUT,
          );
          serverSocket.on("data", (chunk: Buffer) => {
            data = Buffer.concat([data, chunk]);
            if (data.length >= testPayload.length) {
              clearTimeout(timeout);
              resolve(data);
            }
          });
        });
        expect(received.toString()).toBe("hello to port 13");

        // Cleanup
        clientSocket.destroy();
        serverSocket.destroy();
      });
    });
  },
);
