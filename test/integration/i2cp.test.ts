import { describe, it, beforeAll, expect } from "vitest";
import { isTcpPortOpen } from "./test-utils";
import { I2CPSession } from "../../src/clients/i2cp/i2cp";

describe(
  "I2CP",
  {
    timeout: 20_000,
    retry: 3,
  },
  () => {
    const i2cpPort = 7654;
    let session1: I2CPSession;
    let session2: I2CPSession;
    let port1: ReturnType<typeof session1.connect>;
    let port2: ReturnType<typeof session2.connect>;

    beforeAll(async () => {
      // ensure that i2cp is listening
      const i2cpListening = await isTcpPortOpen(i2cpPort);
      if (!i2cpListening) {
        throw new Error(`I2CP is not listening on port ${i2cpPort}`);
      }
      session1 = new I2CPSession({
        i2cpHost: "localhost",
        i2cpPort,
      });
      const session1Ready = new Promise((resolve) => {
        session1.once("session_created", () => {
          resolve(true);
        });
      });
      session2 = new I2CPSession({
        i2cpHost: "localhost",
        i2cpPort,
      });
      const session2Ready = new Promise((resolve) => {
        session2.once("session_created", () => {
          resolve(true);
        });
      });
      await session1Ready;
      await session2Ready;
      port1 = session1.connect(13);
      port2 = session2.connect(14);
    });

    describe("Streaming", () => {
      it("allows you to stream data over I2CP", async () => {
        const stream = session1.createStream(session2.getDestinationBuffer());
        const originalMessage = Buffer.from("Hello over I2CP!");
        const reply = Buffer.from("Reply!");
        stream.write(originalMessage);
        const dataReplied = new Promise<Buffer>((resolve) => {
          stream.on("data", (data) => {
            resolve(data);
          });
        });
        const dataReceived = new Promise<Buffer>((resolve) => {
          session2.on("stream", (incomingStream) => {
            incomingStream.on("data", (data) => {
              resolve(data);
              incomingStream.write(reply);
            });
          });
        });
        const sleep = (ms: number) =>
          new Promise((resolve) => setTimeout(resolve, ms));
        await sleep(2000);
        expect(await dataReceived).toEqual(originalMessage);
        expect(await dataReplied).toEqual(reply);
      });
    });
    describe("RepliableDatagram", () => {
      it("allows you to send and receive repliable datagrams over I2CP", async () => {
        const message = Buffer.from("Hello over RepliableDatagram!");
        const reply = Buffer.from("Reply!");

        let replyRecieved = new Promise<Buffer>((resolve) => {
          port1.on(
            "repliableMessage",
            (fromDestination, sourcePort, payload) => {
              resolve(payload);
            },
          );
        });
        let messageReceived = new Promise<Buffer>((resolve) => {
          port2.on("repliableMessage", (from, sourcePort, payload) => {
            resolve(payload);
            port2.sendRepliableDatagram(
              session1.getDestinationBuffer(),
              sourcePort,
              reply,
            );
          });
        });

        port1.sendRepliableDatagram(
          session2.getDestinationBuffer(),
          14,
          message,
        );
        expect(await messageReceived).toEqual(message);
        expect(await replyRecieved).toEqual(reply);
      });
    });
  },
);
