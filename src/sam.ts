import EventEmitter from "node:events";
import { Socket } from "node:net";
import dgram from "node:dgram";

// @ts-expect-error
import split2 from "split2";
import {
  b64stringToB32String,
  stringDestinationToBuffer,
} from "./utils/utils.js";
// import { createDatagram1 } from "./Datagram1.js";
// import { LocalDestination, SIGNING_PUBLIC_KEY_TYPE } from "./Destination.js";
// import dgram from "node:dgram";
import { Destination } from "./Destination.js";
// import { Stream } from "node:stream";
// import { P } from "vitest/dist/chunks/environment.d.C8UItCbf.js";

/**
 * Add base64 padding if missing.
 * I2P destinations are often stored without padding, but emissary's SAM requires it.
 */
function addBase64Padding(str: string): string {
  const remainder = str.length % 4;
  if (remainder === 0) return str;
  return str + "=".repeat(4 - remainder);
}

export type DestinationConfig = {
  address: string;
  public: string;
  private: string;
  /** 32-byte signing private key for Ed25519 (SIGNATURE_TYPE=7) */
  signingPrivateKey: Buffer;
};

/**
 * Extract the signing private key from the SAM private key blob.
 *
 * The private key format is:
 * - Destination (variable length, 387+ bytes)
 * - Private Key (256 bytes, unused/zeros)
 * - Signing Private Key (32 bytes for Ed25519)
 */
export function extractSigningPrivateKey(
  publicKey: string,
  privateKey: string,
): Buffer {
  const publicBuffer = stringDestinationToBuffer(publicKey);
  const privateBuffer = stringDestinationToBuffer(privateKey);

  // Parse the destination to get its byte length
  const destination = new Destination(publicBuffer);
  const destinationLength = destination.byteLength;

  // The private key structure is:
  // [Destination][256-byte unused private key][Signing Private Key]
  const unusedPrivateKeyLength = 256;
  const signingKeyStart = destinationLength + unusedPrivateKeyLength;

  // For Ed25519 (SIGNATURE_TYPE=7), the signing private key is 32 bytes
  const signingPrivateKey = privateBuffer.subarray(
    signingKeyStart,
    signingKeyStart + 32,
  );

  return signingPrivateKey;
}

// type ConstructorArgs = {
//   publicKey: string;
//   privateKey: string;
//   sessionId?: number | string;
//   tcpPort: number;
//   udpPort: number;
//   host: string;
//   clientId: string;
// };

// class IncomingSocket extends Socket {
//   public remoteAddress?: string;
//   public remotePort?: number;
//   constructor() {
//     super();
//   }
// }

type SessionType = "STREAM" | "DATAGRAM" | "RAW";
const socketsToCleanUp: Set<Socket> = new Set();
const cleanup = () => {
  console.log(`cleaning up ${socketsToCleanUp.size} sockets`);
  for (const socket of socketsToCleanUp) {
    try {
      socket.write("QUIT\n");
    } catch {} // ignore errors, we're exiting anyway
  }
  setTimeout(() => {
    process.exit();
  });
};
process.on("SIGQUIT", cleanup); // Keyboard quit
process.on("SIGTERM", cleanup); // `kill` command
process.on("exit", cleanup);

const cachedLookups = new Map<string, string>();

abstract class BaseSamSocket extends EventEmitter {
  protected hasStream = false;
  protected internalEmitter: EventEmitter;
  public socket: Socket;
  protected helloCompleted: Promise<void>;
  protected isHelloCompleted: boolean = false;
  protected host: string;
  protected port: number;
  static type: string;

  constructor(
    { host, port }: { host: string; port: number } = {
      host: "localhost",
      port: 7654,
    },
  ) {
    super();
    this.host = host;
    this.port = port;
    this.internalEmitter = new EventEmitter();
    this.hasStream = false;
    this.socket = new Socket();
    socketsToCleanUp.add(this.socket);
    this.socket.on("data", (data) => {
      if (this.hasStream) {
        this.emit("data", data);
        return;
      }
      return this.parseReply(data);
    });
    this.socket.on("error", (err) => {
      console.log("socket error");
      console.log(
        `socket error on ${(<typeof BaseSamSocket>this.constructor).type} socket`,
        err,
      );
      this.emit("error", err);
    });
    // this.socket.on("close", () => {
    //   console.log("socket closed");
    // });
    // this.socket.on("end", () => {
    //   console.log("socket endded");
    // });
    this.socket.connect({
      port,
      host,
    });
    this.helloCompleted = new Promise((resolve, reject) => {
      this.isHelloCompleted = true;
      this.internalEmitter.once("hello", () => {
        resolve();
      });
      this.socket.once("connect", () => {
        this.sendHello();
      });
    });
  }

  private sendHello() {
    this.socket.write(Buffer.from("HELLO VERSION MIN=3.0 MAX=3.3\n"));
  }

  public async performNameLookup(name: string): Promise<string> {
    return new Promise(async (resolve, reject) => {
      console.log(`looking up "${name}"`);
      if (name.length > 387) {
        return resolve(name);
      }
      await this.helloCompleted;
      if (cachedLookups.has(name)) {
        return resolve(cachedLookups.get(name)!);
      }
      this.once("nameLookupResult", (result: string) => {
        if (result.length % 4 !== 0) {
          result = addBase64Padding(result);
        }
        cachedLookups.set(name, result);
        resolve(result);
      });
      this.once("error", (err) => {
        console.log("failed to lookup name:", name);
        reject(err);
      });
      this.socket.write(`NAMING LOOKUP NAME=${name}\n`);
    });
  }

  protected parseReply(data: Buffer) {
    const message = data.toString().trim();
    const msg = parseMessage(message);
    if (msg.type === SamReplies.REPLY_HELLO) {
      if (msg.args.RESULT === "OK") {
        this.internalEmitter.emit("hello");
      } else {
        this.emit("error", new Error(msg.args.MESSAGE));
      }
    } else if (msg.type === SamReplies.REPLY_STREAM) {
      if (msg.args.RESULT === "OK") {
        this.hasStream = true;
        this.emit("stream");
      } else {
        // console.error(
        //   "STREAM ERROR:",
        //   msg.args.RESULT,
        //   "msg:",
        //   msg.args.MESSAGE,
        // );
        this.emit(
          "error",
          new Error(`${SamReplies.REPLY_STREAM}: ${msg.args.RESULT}`),
        );
        // this.destroy();
      }
    } else if (msg.type === SamReplies.REPLY_SESSION) {
      // console.log("got a session", msg);
      if (msg.args.RESULT === "OK") {
        this.emit("session", msg.args.ID);
      } else {
        console.error("SESSION ERROR:", msg);
      }
    } else if (msg.type === SamReplies.REPLY_NAMING) {
      if (msg.args.RESULT === "OK") {
        this.emit("nameLookupResult", msg.args.VALUE);
      } else {
        console.log("failed lookup:", msg.args.RESULT, msg.args.MESSAGE);
        this.emit("error", new Error(msg.args.MESSAGE));
      }
    } else {
      console.error("UNHANDLED SAM MESSAGE:", msg);
    }
  }

  // I dunno if we actually want to do this...
  destroy() {
    this.socket.write("QUIT\n");
    socketsToCleanUp.delete(this.socket);
    return this.socket.destroy();
  }
}

class ControlSocket extends BaseSamSocket {
  private primarySessionCreatedProm: Promise<void> | undefined;
  private privateKey: string;
  private sessionId: number;
  private primarySession: PrimarySession;
  static type = "CONTROL";
  constructor({
    host,
    port,
    sessionId,
    privateKey,
    primarySession,
  }: {
    host: string;
    port: number;
    sessionId: number;
    privateKey: string;
    primarySession: PrimarySession;
  }) {
    super({ host, port });
    this.sessionId = sessionId;
    this.privateKey = privateKey;
    this.primarySession = primarySession;
  }

  private async primarySessionCreated() {
    await this.helloCompleted;
    if (this.primarySessionCreatedProm) return this.primarySessionCreatedProm;
    this.primarySessionCreatedProm = new Promise((resolve, reject) => {
      this.once("session", () => {
        resolve();
      });
      this.once("error", (err) => {
        reject(err);
      });
      this.socket.write(
        `SESSION CREATE STYLE=PRIMARY ID=${this.sessionId} DESTINATION=${this.privateKey} i2cp.leaseSetEncType=4,0\n`,
      );
    });
    return this.primarySessionCreatedProm;
  }

  public async addSession(opts: {
    style: SessionType;
    /**
     * The ID of the session.
     */
    id: string;
    fromPort?: number;
    toPort?: number;
  }): Promise<Subsession> {
    const { style, id, fromPort, toPort } = opts;
    // I haven't been able to get any responses on port14, so let's listen for everything on 13
    // const fromPort = fPort === 13 ? 0 : fPort;
    await this.primarySessionCreated();
    return new Promise((resolve, reject) => {
      const listenUdpPort = Math.floor(Math.random() * 10000 + 40000);
      this.once("session", (_sessionId) => {
        const opts = {
          host: this.host,
          port: style === "STREAM" ? this.port : this.primarySession.udpPort,
          id,
        };
        switch (style) {
          case "DATAGRAM":
            resolve(
              new RepliableDatagramSession({
                ...opts,
                listenUdpPort,
                fromPort,
              }),
            );
            break;
          case "RAW":
            resolve(
              new RawDatagramSession({
                ...opts,
                listenUdpPort,
                fromPort,
              }),
            );
            break;
          case "STREAM":
            resolve(new StreamSession({ ...opts, fromPort }));
            break;
        }
      });
      this.once("error", () => {
        reject(new Error("Error creating session"));
      });
      const sessionMessage = `SESSION ADD STYLE=${style} ID=${id} ${fromPort ? `FROM_PORT=${fromPort}` : ""}${toPort ? ` TO_PORT=${toPort}` : ""}${fromPort ? ` LISTEN_PORT=${fromPort}` : ""}${style !== "STREAM" ? ` PORT=${listenUdpPort}` : ""}\n`;
      // console.log("starting session...", sessionMessage);
      this.socket.write(sessionMessage);
    });
  }
}

export class StreamAcceptSocket extends BaseSamSocket {
  static type = "STREAM_ACCEPT";
  private destination: string = "";
  private isAccepting = true;
  private expectingDestination = false;
  private fromPort: number;
  constructor({
    host,
    port,
    sessionId,
    fromPort,
  }: {
    host: string;
    port: number;
    sessionId: string;
    fromPort?: number;
  }) {
    super({ host, port });
    this.fromPort = fromPort || 0;
    this.helloCompleted.then(() => {
      this.socket.write(`STREAM ACCEPT ID=${sessionId}\n`);
    });
  }

  protected parseReply(data: Buffer) {
    if (this.expectingDestination) {
      const message = data.toString().trim();
      // The destination line is like "base64dest FROM_PORT=0 TO_PORT=0"
      const parts = message.split(" ");
      const args: Record<string, string> = {};
      for (let i = 1; i < parts.length; i++) {
        const [key, value] = parts[i].split("=");
        args[key] = value;
      }
      const toPort = parseInt(args.TO_PORT, 10);
      if (this.fromPort === 0 || toPort === this.fromPort) {
        this.destination = parts[0];
        this.expectingDestination = false;
        this.hasStream = true;
        this.emit("data", data);
      } else {
        // Not for this port, reset for next accept
        this.expectingDestination = false;
        // Perhaps emit error or just ignore
      }
      return;
    }
    const message = data.toString().trim();
    const msg = parseMessage(message);
    if (msg.type === SamReplies.REPLY_HELLO) {
      if (msg.args.RESULT === "OK") {
        this.internalEmitter.emit("hello");
      } else {
        this.emit("error", new Error(msg.args.MESSAGE));
      }
    } else if (msg.type === SamReplies.REPLY_STREAM) {
      if (msg.args.RESULT === "OK") {
        if (this.isAccepting) {
          this.emit("stream");
          this.expectingDestination = true;
          // Don't set hasStream yet, wait for destination
        } else {
          this.hasStream = true;
          this.emit("stream");
        }
      } else {
        this.emit(
          "error",
          new Error(`${SamReplies.REPLY_STREAM}: ${msg.args.RESULT}`),
        );
      }
    } else if (msg.type === SamReplies.REPLY_SESSION) {
      // console.log("got a session", msg);
      if (msg.args.RESULT === "OK") {
        console.log("successfully created session id=", msg);
        this.emit("session", msg.args.ID);
      } else {
        console.error("SESSION ERROR:", msg.args.RESULT);
      }
    } else if (msg.type === SamReplies.REPLY_NAMING) {
      if (msg.args.RESULT === "OK") {
        this.emit("nameLookupResult", msg.args.VALUE);
      } else {
        console.log("failed lookup:", msg.args.RESULT, msg.args.MESSAGE);
        this.emit("error", new Error(msg.args.MESSAGE));
      }
    } else {
      console.error("UNHANDLED SAM MESSAGE:", msg);
    }
  }

  getDestination(): string {
    return this.destination;
  }

  async write(...args: Parameters<Socket["write"]>) {
    await this.helloCompleted;
    this.socket.write.apply(this.socket, args);
  }
}

export class StreamSocket extends BaseSamSocket {
  static type = "STREAM";
  constructor({
    host,
    port,
    fromPort,
    toPort,
    destination,
    sessionId,
  }: {
    host: string;
    port: number;
    fromPort: number;
    toPort: number;
    destination: string;
    sessionId: string;
  }) {
    super({ host, port });
    this.helloCompleted.then(() => {
      this.socket.write(
        `STREAM CONNECT ID=${sessionId} DESTINATION=${destination} FROM_PORT=${fromPort} TO_PORT=${toPort}\n`,
      );
    });
  }
  async write(...args: Parameters<Socket["write"]>) {
    await this.helloCompleted;
    this.socket.write.apply(this.socket, args);
  }
}

export class StreamSession extends EventEmitter {
  private host: string;
  private port: number;
  public id: string;
  private accepting: boolean = false;
  private fromPort: number;

  constructor({
    host,
    port,
    id,
    fromPort,
  }: {
    host: string;
    port: number;
    id: string;
    fromPort?: number;
  }) {
    super();
    this.host = host;
    this.port = port;
    this.id = id;
    this.fromPort = fromPort || 0;
    this.startAccepting();
  }

  /**
   * Continuously send STREAM ACCEPT to the SAM bridge and emit 'connection' when a new stream is accepted.
   */
  private startAccepting() {
    if (this.accepting) return;
    this.accepting = true;
    const acceptNext = () => {
      // Only one pending accept at a time
      const acceptSocket = new StreamAcceptSocket({
        host: this.host,
        port: this.port,
        sessionId: this.id,
        fromPort: this.fromPort,
      });
      // STREAM ACCEPT is sent in the constructor after hello
      let accepted = false;
      acceptSocket.once("stream", () => {
        // STREAM STATUS OK received, now wait for destination line
        acceptSocket.once("data", (data: Buffer) => {
          if (!accepted) {
            const dest = data.toString().trim();
            accepted = true;
            // Patch the StreamAcceptSocket with the correct destination
            // @ts-ignore
            acceptSocket.destination = dest;
            // Now set hasStream to start forwarding data
            // @ts-ignore
            acceptSocket.hasStream = true;
            this.emit("connection", acceptSocket);
            // Accept the next connection
            setImmediate(acceptNext);
          }
        });
      });
      acceptSocket.socket.on("error", () => {
        // Try again after a short delay
        setTimeout(acceptNext, 1000);
      });
    };
    acceptNext();
  }

  public async createStream({
    destination,
    fromPort,
    toPort,
  }: {
    destination: string;
    fromPort: number;
    toPort: number;
  }): Promise<any> {
    return new Promise((resolve, reject) => {
      const socket = new (StreamSocket as any)({
        host: this.host,
        port: this.port,
        fromPort,
        toPort,
        destination,
        sessionId: this.id,
      });
      socket.once("error", (err: any) => {
        reject(err);
      });
      socket.once("stream", () => {
        resolve(socket);
      });
    });
  }
}

class DatagramServer {
  constructor(port: number, subsession: Subsession, expectedToPort?: number) {
    const server = dgram.createSocket("udp4");
    server.on("error", (err) => {
      console.error(`Server error:\n${err.stack}`);
      server.close();
    });

    server.on("message", (msg, rinfo) => {
      // console.log("message!", port, subsession.id, msg);
      if (msg.includes("FROM_PORT=")) {
        const firstLineBreak = msg.indexOf("\n");
        const header = msg.subarray(0, firstLineBreak).toString();
        const [destination, ...rest] = header.split(" ");
        const args: Record<string, string> = {};
        for (let i = 0; i < rest.length; i++) {
          const [key, value] = rest[i].split("=");
          args[key] = value;
        }
        const payload = msg.subarray(firstLineBreak + 1);
        const toPort = parseInt(args.TO_PORT, 10);
        if (expectedToPort === undefined || toPort === expectedToPort) {
          // Emit both for backward compatibility
          subsession.emit("repliableDatagram", {
            destination: destination,
            fromPort: parseInt(args.FROM_PORT, 10),
            toPort,
            payload,
          });
          // Also emit 'message' for test compatibility
          subsession.emit("message", payload, destination);
        }
      } else {
        console.log("emitting a raw datagram");
        subsession.emit("rawDatagram", msg);
      }
    });

    server.on("listening", () => {
      const address = server.address();
      console.log(`UDP server listening on ${address.address}:${address.port}`);
    });

    server.bind(port); // The port number to listen on
  }
}
export class RawDatagramSession extends EventEmitter {
  public id: string;
  private socket: dgram.Socket;
  private host: string;
  private port: number;
  constructor({
    host,
    port,
    id,
    listenUdpPort,
    fromPort,
  }: {
    host: string;
    port: number;
    id: string;
    listenUdpPort: number;
    fromPort?: number;
  }) {
    super();
    this.id = id;
    this.socket = dgram.createSocket("udp4");
    this.port = port;
    this.host = host;
    // console.log("raw session connecting to ", host, port);
    this.socket.on("message", (msg, rinfo) => {
      console.log("raw datagram message", msg, rinfo);
    });
    this.socket.on("error", () => {
      console.log("udp socket error");
    });
    // this.socket.on("close", () => {
    //   // console.log("udp socket closed");
    // });
    console.log("raw session listening udp port", listenUdpPort);
    new DatagramServer(listenUdpPort, this, undefined);
  }
  sendRawDatagram(
    destination: string,
    fromPort: number,
    destinationPort: number,
    payload: Buffer,
  ) {
    // Add base64 padding if missing (emissary requires it)
    const paddedDestination = addBase64Padding(destination);

    // Validate destination has no whitespace
    if (paddedDestination.includes(" ") || paddedDestination.includes("\n")) {
      console.error("ERROR: Destination contains whitespace!");
    }

    // Build header as plain string first
    const headerStr = `3.0 ${this.id} ${paddedDestination} FROM_PORT=${fromPort} TO_PORT=${destinationPort}\n`;
    // console.log("raw payload", payload);

    // console.log("Raw datagram debug:", {
    //   sessionId: this.id,
    //   sessionIdHasSpaces: this.id.includes(" "),
    //   originalDestLength: destination.length,
    //   paddedDestLength: paddedDestination.length,
    //   destinationEnd: paddedDestination.substring(
    //     paddedDestination.length - 20,
    //   ),
    //   fromPort,
    //   destinationPort,
    //   payloadLength: payload.length,
    //   headerLength: headerStr.length,
    // });

    const header = Buffer.from(headerStr);
    const message = Buffer.concat([header, payload]);

    // Show first 100 bytes as hex for debugging
    // console.log(
    //   "Message first 100 bytes (hex):",
    //   message.subarray(0, 100).toString("hex"),
    // );
    // console.log("Message total length:", message.length);
    // console.log("sending raw datagram");
    this.socket.send(message, this.port, this.host, (err) => {
      console.log("raw datagram send complete", err);
      console.log(message.toString());
      console.log(this.port, this.host);
    });
  }
}

process.on("uncaughtException", (err) => {
  console.error("🔥 Uncaught exception:", err);
  console.error(err.stack);
});

export class RepliableDatagramSession extends EventEmitter {
  public id: string;
  private socket: dgram.Socket;
  private host: string;
  private port: number;
  private fromPort: number;
  constructor({
    host,
    port,
    id,
    listenUdpPort,
    fromPort,
  }: {
    host: string;
    port: number;
    id: string;
    listenUdpPort: number;
    fromPort?: number;
  }) {
    super();
    this.id = id;
    this.fromPort = fromPort || 0;
    this.socket = dgram.createSocket("udp4");
    this.port = port;
    this.host = host;
    this.socket.on("message", (msg, rinfo) => {
      // This event is not used for incoming SAM datagrams; handled by DatagramServer
      // But emit for local UDP messages if needed
      this.emit("message", msg, rinfo.address);
    });
    this.socket.on("error", () => {
      console.log("repliable socket error");
    });
    console.log("repliable session listening udp port", listenUdpPort);
    new DatagramServer(listenUdpPort, this, this.fromPort);
  }

  public async sendRepliableDatagram(
    destination: string,
    sourcePort: number,
    destinationPort: number,
    payload: Buffer,
  ) {
    // Add base64 padding if missing (emissary requires it)
    const paddedDestination = addBase64Padding(destination);

    // Validate destination has no whitespace
    if (paddedDestination.includes(" ") || paddedDestination.includes("\n")) {
      console.error("ERROR: Destination contains whitespace!");
    }

    // Try to parse the destination to verify it's valid
    try {
      const destBuffer = stringDestinationToBuffer(destination);
      const parsed = new Destination(destBuffer);
      console.log("Destination parsed OK:", {
        byteLength: parsed.byteLength,
        signingKeyType: parsed.signingPublicKeyType,
      });
    } catch (e) {
      console.error("ERROR: Failed to parse destination:", e);
      console.error("Full destination string:", destination);
    }

    // Build header as plain string first
    const headerStr = `3.0 ${this.id} ${paddedDestination} FROM_PORT=${sourcePort} TO_PORT=${destinationPort}\n`;

    // console.log("Repliable datagram debug:", {
    //   sessionId: this.id,
    //   sessionIdHasSpaces: this.id.includes(" "),
    //   originalDestLength: destination.length,
    //   paddedDestLength: paddedDestination.length,
    //   destinationEnd: paddedDestination.substring(
    //     paddedDestination.length - 20,
    //   ),
    //   sourcePort,
    //   destinationPort,
    //   payloadLength: payload.length,
    //   headerLength: headerStr.length,
    // });
    // console.log("raw payload", payload);

    const header = Buffer.from(headerStr);
    const message = Buffer.concat([header, payload]);

    // console.log(
    //   "Repliable datagram hex (first 100):",
    //   message.subarray(0, 100).toString("hex"),
    // );
    // console.log("Repliable datagram total length:", message.length);
    console.log("Sending repliable datagram to:", this.host, this.port);

    this.socket.send(message, this.port, this.host, (err) => {
      console.log("repliable datagram sent", err);
      console.log(message.toString());
      console.log(this.port, this.host);
    });
  }
}

const SessionMap = {
  STREAM: StreamSession,
  DATAGRAM: RepliableDatagramSession,
  RAW: RawDatagramSession,
};
type Subsession = StreamSession | RepliableDatagramSession | RawDatagramSession;

export class PrimarySession {
  private subsessionMap = new Map<string, Subsession>();
  private controlSocket: ControlSocket;
  private sessionId: number;
  public udpPort: number;

  constructor({
    host,
    tcpPort,
    udpPort,
    publicKey,
    privateKey,
  }: {
    host: string;
    tcpPort: number;
    udpPort: number;
    publicKey: string;
    privateKey: string;
  }) {
    this.sessionId = Math.floor(Math.random() * 1000000);
    this.udpPort = udpPort;
    this.controlSocket = new ControlSocket({
      host,
      port: tcpPort,
      sessionId: this.sessionId,
      privateKey,
      primarySession: this,
    });
  }

  public async getOrCreateSubsession<T extends SessionType>(
    applicationName: string,
    type: T,
    fromPort?: number,
  ): Promise<InstanceType<(typeof SessionMap)[T]>> {
    const key = `${applicationName}-${type}-${this.sessionId}`;
    let subsession = this.subsessionMap.get(key);
    if (!subsession) {
      subsession = await this.controlSocket.addSession({
        style: type as SessionType,
        id: `${applicationName}-${type}-${this.sessionId}`,
        fromPort,
      });
      this.subsessionMap.set(key, subsession);
    }
    return subsession as InstanceType<(typeof SessionMap)[T]>;
  }

  public async nameLookup(name: string): Promise<string> {
    if (name.length > 387) {
      return name;
    }
    return this.controlSocket.performNameLookup(name);
  }
}

// export const createNamelookup = (tcpPort: number, host: string) => {
//   return async (name: string): Promise<string> => {
//     return new Promise((resolve, reject) => {
//       const socket = new BaseSamSocket({ host, port: tcpPort });
//       return socket.performNameLookup(name);
//     });
//   };
// };

// export class SubStream extends EventEmitter {
//   private socket: Socket;
//   private hasStream = false;
//   private internalEmitter = new EventEmitter();
//   private sessionId: string;
//   private destination: string;
//   private remoteAddress: string;
//   private remotePort: number = 6881;
//   constructor(socket: Socket, sessionId: string, destination: string) {
//     super();
//     this.socket = socket;
//     this.sessionId = sessionId;
//     this.destination = destination;
//     this.socket.on("data", (data) => {
//       if (this.hasStream) {
//         this.emit("data", data);
//       } else {
//         this.parseReply(data);
//       }
//     });
//     this.remoteAddress = `${b64stringToB32String(destination)}.b32.i2p`;
//     this.socket.on("error", this.emit.bind(this, "error"));
//     this.socket.on("close", this.emit.bind(this, "close"));
//   }

//   connect(port: number, host: string) {
//     console.log("connecting to a subsession stream", this.sessionId);
//     this.socket.connect(port, host, () => {
//       this.internalEmitter.once("hello", () => {
//         console.log("got subsession hello", this.sessionId);
//         this.internalEmitter.once("session", () => {
//           console.log("Got a subsession!");
//         });
//         this.socket.write(
//           `SESSION ADD STYLE=STREAM ID=${this.sessionId} DESTINATION=${this.destination}\n`,
//         );
//         console.log("stream connecting... hello done", this.sessionId);
//         this.socket.write(
//           `STREAM CONNECT ID=${this.sessionId} DESTINATION=${this.destination}\n`,
//         );
//         this.emit("connect");
//       });
//       this.socket.write(`HELLO VERSION MIN=3.0 MAX=3.1\n`);
//     });
//   }

//   destroy() {
//     return this.socket.destroy();
//   }

//   parseReply(data: Buffer) {
//     const message = data.toString().trim();
//     const msg = parseMessage(message);
//     if (msg.type === SamReplies.REPLY_HELLO) {
//       if (msg.args.RESULT === "OK") {
//         this.internalEmitter.emit("hello");
//       } else {
//         this.emit("error", new Error(msg.args.MESSAGE));
//       }
//     }
//     if (msg.type === "STREAM STATUS") {
//       if (msg.args.RESULT === "OK") {
//         this.hasStream = true;
//         this.emit("stream");
//       } else {
//         this.destroy();
//         // this.emit("error", new Error(msg.args.MESSAGE));
//       }
//     }
//     if (msg.type === SamReplies.REPLY_SESSION) {
//       console.log("got a session", msg);
//       this.emit("session");
//     }
//   }

//   write(...args: Parameters<Socket["write"]>) {
//     this.socket.write.apply(this.socket, args);
//   }
// }

export class SAM extends EventEmitter {
  //   /**
  //    * Generate a new I2P destination via SAM bridge.
  //    * Creates a temporary connection to generate keys and immediately closes it.
  //    */
  static generateDestination(
    options: {
      host?: string;
      port?: number;
    } = {},
  ): Promise<DestinationConfig> {
    const { host = "127.0.0.1", port = 7656 } = options;

    return new Promise((resolve, reject) => {
      const socket = new Socket();
      let helloDone = false;

      const cleanup = () => {
        socket.removeAllListeners();
        socket.destroy();
      };

      socket.on("error", (err) => {
        console.log('error in generateDestination"', err);
        cleanup();
        reject(err);
      });

      socket.on("close", () => {
        if (!helloDone) {
          reject(
            new Error("Connection closed before destination was generated"),
          );
        }
      });

      socket.pipe(split2()).on("data", (data: Buffer) => {
        const message = data.toString().trim();
        const firstSpaceIndex = message.indexOf(" ");
        const secondSpaceIndex = message.indexOf(" ", firstSpaceIndex + 1);
        const type = message.substring(0, secondSpaceIndex);

        if (type === "HELLO REPLY") {
          // Parse RESULT
          if (message.includes("RESULT=OK")) {
            helloDone = true;
            socket.write("DEST GENERATE SIGNATURE_TYPE=7\n");
          } else {
            cleanup();
            reject(new Error(`SAM handshake failed: ${message}`));
          }
        } else if (type === "DEST REPLY") {
          // Parse PUB and PRIV from the message
          const pubMatch = message.match(/PUB=([^\s]+)/);
          const privMatch = message.match(/PRIV=([^\s]+)/);

          if (pubMatch && privMatch) {
            const publicKey = pubMatch[1];
            const privateKey = privMatch[1];
            const address = `${b64stringToB32String(publicKey)}.b32.i2p`;
            const signingPrivateKey = extractSigningPrivateKey(
              publicKey,
              privateKey,
            );

            cleanup();
            resolve({
              address,
              public: publicKey,
              private: privateKey,
              signingPrivateKey,
            });
          } else {
            cleanup();
            reject(new Error(`Failed to parse destination reply: ${message}`));
          }
        }
      });

      socket.connect(port, host, () => {
        socket.write("HELLO VERSION MIN=3.0 MAX=3.3\n");
      });
    });
  }

  //   private controlSocket: Socket;
  //   private subSessions = new Map<number, SubStream>();
  //   private sessionId: number | string;
  //   private internalEmitter = new EventEmitter();
  //   private subsessionId = 0;
  //   private clientId: string;

  //   private publicKey: string;
  //   private privateKey: string;

  //   private controlReady = false;

  //   private host: string;
  //   private tcpPort: number;
  //   private udpPort: number;

  //   private pendingStreams = new Set<Socket>();

  //   /**
  //    * Map of repliable datagram sockets that we're listening on/sending from.
  //    */
  //   private repliableDatagramSockets = new Map<number, Socket>();
  //   /**
  //    * Map of raw datagram sockets that we're listening on/sending from.
  //    */
  //   private rawDatagramSockets = new Map<number, Socket>();
  //   private datagramSocket: dgram.Socket;

  //   constructor({
  //     sessionId,
  //     publicKey,
  //     privateKey,
  //     host,
  //     tcpPort,
  //     udpPort,
  //     clientId,
  //   }: ConstructorArgs) {
  //     super();
  //     this.publicKey = publicKey;
  //     this.privateKey = privateKey;
  //     this.clientId = clientId;
  //     this.sessionId = sessionId || Math.floor(Math.random() * 1000000);
  //     this.controlSocket = new Socket();
  //     this.controlSocket.pipe(split2()).on("data", this.parseReply.bind(this));
  //     this.controlSocket.on("error", (err) => {
  //       console.error("Error in SAM:", err);
  //     });
  //     this.controlSocket.on("close", () => {
  //       console.log("sam socket closed :/");
  //     });

  //     this.datagramSocket = dgram.createSocket("udp4");
  //     this.host = host;
  //     this.tcpPort = tcpPort;
  //     this.udpPort = udpPort;
  //     this.controlSocket.connect(tcpPort, host);
  //     console.log("erm?");
  //     if (
  //       (this.publicKey || this.privateKey) &&
  //       !(this.publicKey && this.privateKey)
  //     ) {
  //       throw new Error("Both public and private keys must be provided");
  //     }
  //     this.internalEmitter.on("error", (err) => {
  //       console.error("Error in SAM:", err);
  //     });
  //     this.internalEmitter.once("destination", () => {
  //       const style = "MASTER"; // This _should_ be PRIMARY, but i2pd doesn't support it yet
  //       this.write(
  //         `SESSION CREATE STYLE=${style} ID=${this.clientId} DESTINATION=${this.privateKey}\n`,
  //       );
  //     });
  //     this.internalEmitter.once("session", () => {
  //       this.controlReady = true;
  //       this.createIncomingStreams();
  //       this.createDatagramStreams();
  //     });
  //     this.controlSocket.on("connect", () => {
  //       this.internalEmitter.once("hello", () => {
  //         if (!this.publicKey || !this.privateKey) {
  //           this.write("DEST GENERATE SIGNATURE_TYPE=7\n");
  //         } else {
  //           this.internalEmitter.emit("destination");
  //         }
  //       });
  //       this.write(`HELLO VERSION MIN=3.0 MAX=3.1\n`);
  //     });
  //   }

  //   /**
  //    * @param destination - Base64 or Base32 encoded destination.
  //    */
  //   createStream(destination: string) {
  //     const subSessionId = this.subsessionId++;
  //     const sessionId = `${this.clientId}-${subSessionId}`;
  //     console.log(
  //       "connecting to subsession",
  //       subSessionId,
  //       "sessionId",
  //       sessionId,
  //     );
  //     const stream = new SubStream(new Socket(), sessionId, destination);
  //     this.subSessions.set(subSessionId, stream);
  //     stream.once("close", () => {
  //       this.subSessions.delete(subSessionId);
  //     });
  //     const work = () => {
  //       this.internalEmitter.once("session", () => {
  //         stream.connect(this.tcpPort, this.host);
  //       });
  //       const t = () => {
  //         this.write(
  //           `SESSION ADD STYLE=STREAM ID=${sessionId} DESTINATION=${destination} FROM_PORT=${
  //             subSessionId + 55
  //           }\n`,
  //         );
  //       };
  //       try {
  //         t();
  //       } catch (e) {
  //         t();
  //       }
  //     };
  //     if (this.controlReady) {
  //       work();
  //     } else {
  //       this.internalEmitter.once("session", work);
  //     }
  //     return stream;
  //   }

  //   private createIncomingStreams() {
  //     while (this.pendingStreams.size < 5) {
  //       this.pendingStreams.add(this.createIncomingStream());
  //     }
  //   }

  //   private createIncomingStream() {
  //     console.log("creating incoming stream");
  //     const socket = new IncomingSocket();
  //     socket.connect(this.tcpPort, this.host, () => {
  //       socket.write("HELLO VERSION MIN=3.0 MAX=3.1\n");
  //       socket.once("data", (data) => {
  //         const parsed = parseMessage(data.toString().trim());
  //         console.log("got incoming stream reply", parsed);
  //         if (parsed.type !== SamReplies.REPLY_HELLO) {
  //           console.error("expected hello reply for incoming stream");
  //           process.exit(1);
  //         }
  //         socket.once("data", (data) => {
  //           const message = data.toString();
  //           if (!message.endsWith("\n")) {
  //             console.error("first message did not contain a line break!!!!");
  //             process.exit(1);
  //           }
  //           const destination = message.split(" ")[0];
  //           console.log("got incoming stream", destination);
  //           socket.remoteAddress = `${b64stringToB32String(destination)}.b32.i2p`;
  //           socket.remotePort = 6881; // fake port
  //           console.log("accepting incoming stream");
  //           this.emit("stream", socket);
  //           this.pendingStreams.delete(socket);
  //           // reset the callstack
  //           process.nextTick(() => {
  //             console.log("next tick?");
  //             this.pendingStreams.add(this.createIncomingStream());
  //           });
  //         });
  //         socket.write(`STREAM ACCEPT ID=${this.sessionId}\n`);
  //       });
  //     });
  //     return socket;
  //   }

  //   private async ready() {
  //     if (this.controlReady) {
  //       return Promise.resolve();
  //     }
  //     return new Promise((resolve) => {
  //       this.internalEmitter.once("session", () => {
  //         resolve(true);
  //       });
  //     });
  //   }

  //   private createDatagramStreams() {}

  //   // public listenForDatagrams = async (port: number) => {
  //   //   await this.ready();
  //   //   if (this.repliableDatagramSockets.has(port)) {
  //   //     return;
  //   //   }
  //   // };

  //   public sendDatagram(
  //     destination: string | Buffer,
  //     fromPort: number,
  //     toPort: number,
  //     data: Buffer,
  //   ) {
  //     console.log("sending raw datagram");
  //   }

  //   public sendRepliableDatagram = async (
  //     destination: string | Buffer,
  //     sourcePort: number,
  //     destinationPort: number,
  //     payload: Buffer,
  //   ) => {
  //     console.log("sending repliable to ", destination);
  //     await this.ready();
  //     const destinationBuffer = stringDestinationToBuffer(this.publicKey);
  //     const privateKeyBuffer = new Uint8Array(
  //       Buffer.from(this.privateKey, "base64"),
  //     );

  //     const datagram = createDatagram1(
  //       new LocalDestination(destinationBuffer, privateKeyBuffer),
  //       payload,
  //     );
  //     const subsessionId = this.subsessionId++;
  //     const nickname = `${this.clientId}-datagram-${subsessionId}`;

  //     const datagramSocket = new Socket();
  //     // this.repliableDatagramSockets.set(port, datagramSocket);
  //     this.once("session", () => {
  //       datagramSocket.write(
  //         Buffer.concat([
  //           Buffer.from(
  //             `3.0 ${nickname} ${destination} FROM_PORT=${sourcePort} TO_PORT=${destinationPort}\n`,
  //           ),
  //           datagram,
  //         ]),
  //       );
  //     });
  //     this.write(
  //       `SESSION ADD STYLE=DATAGRAM ID=${nickname} PORT=${subsessionId} FROM_PORT=${sourcePort} TO_PORT=${destinationPort}\n`,
  //     );
  //   };

  //   private parseReply(data: Buffer) {
  //     const message = data.toString().trim();
  //     const msg = parseMessage(message);
  //     // console.log("got message", msg.type);
  //     switch (msg.type) {
  //       case SamReplies.REPLY_HELLO:
  //         return msg.args.RESULT === "I2P_ERROR"
  //           ? this.internalEmitter.emit("error", new Error(msg.args.MESSAGE))
  //           : this.internalEmitter.emit("hello");
  //       case SamReplies.REPLY_DESTINATION:
  //         this.privateKey = msg.args.PRIV;
  //         this.publicKey = msg.args.PUB;
  //         return this.internalEmitter.emit("destination");
  //       case SamReplies.REPLY_SESSION:
  //         return msg.args.RESULT === "OK"
  //           ? this.internalEmitter.emit("session")
  //           : this.internalEmitter.emit(
  //               "error",
  //               new Error(
  //                 `Session error: ${msg.args.RESULT}${
  //                   "MESSAGE" in msg.args ? ` - ${msg.args.MESSAGE}` : ""
  //                 }`,
  //               ),
  //             );
  //       case SamReplies.REPLY_STREAM:
  //         return msg.args.RESULT === "OK"
  //           ? this.internalEmitter.emit("stream")
  //           : this.internalEmitter.emit("error", new Error(msg.args.MESSAGE));
  //       default:
  //         const t: never = msg; // catch unhandled message types at compile time
  //         console.trace(`Unhandled message type: "${message}"`);
  //     }
  //   }

  //   private write(msg: string) {
  //     this.controlSocket.write(msg);
  //   }
}

enum SamReplies {
  REPLY_HELLO = "HELLO REPLY",
  REPLY_STREAM = "STREAM STATUS",
  REPLY_DESTINATION = "DEST REPLY",
  REPLY_SESSION = "SESSION STATUS",
  REPLY_NAMING = "NAMING REPLY",
}

interface Args {
  [SamReplies.REPLY_HELLO]: {
    type: SamReplies.REPLY_HELLO;
    args:
      | {
          RESULT: "OK";
        }
      | {
          RESULT: "I2P_ERROR" | "NOVERSION";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_STREAM]: {
    type: SamReplies.REPLY_STREAM;
    args:
      | {
          RESULT: "OK";
        }
      | {
          RESULT:
            | "CANT_REACH_PEER"
            | "I2P_ERROR"
            | "INVALID_KEY"
            | "INVALID_ID"
            | "TIMEOUT";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_DESTINATION]: {
    type: SamReplies.REPLY_DESTINATION;
    args: {
      PUB: string;
      PRIV: string;
    };
  };
  [SamReplies.REPLY_SESSION]: {
    type: SamReplies.REPLY_SESSION;
    args:
      | {
          RESULT: "OK";
          ID: string;
          MESSAGE: string;
        }
      | {
          RESULT: "DUPLICATED_ID" | "INVALID_KEY" | "DUPLICATED_DEST";
        }
      | {
          RESULT: "I2P_ERROR";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_NAMING]: {
    type: SamReplies.REPLY_NAMING;
    args:
      | {
          RESULT: "OK";
          NAME: string;
          VALUE: string;
        }
      | {
          RESULT: "INVALID_KEY" | "KEY_NOT_FOUND";
          NAME: string;
          MESSAGE: string;
        };
  };
}

const parseMessage = <T extends SamReplies>(msg: string): Args[T] => {
  // Split on the second space character
  const firstSpaceIndex = msg.indexOf(" ");
  const secondSpaceIndex = msg.indexOf(" ", firstSpaceIndex + 1);
  const type = msg.substring(0, secondSpaceIndex);

  // Keep the original format of arguments as an array of key=value strings
  const remainingStr = msg.substring(secondSpaceIndex + 1);
  const pargs = parseArgString(remainingStr);

  const argsObj: Record<string, string> = {};
  for (const arg of pargs) {
    const [key, value] = arg.split("=");
    if (key && value) {
      try {
        argsObj[key] = value.startsWith('"') ? JSON.parse(value) : value;
      } catch (e) {
        console.error(`Error parsing value '${value}'`, e);
        throw new Error("Error parsing value");
      }
    }
  }
  return {
    type: type,
    args: argsObj,
  } as Args[T] satisfies {
    type: SamReplies;
    args: Record<string, string>;
  };
};

const parseArgString = (argString: string): string[] => {
  // This function parses the argument string into an array of key=value strings
  // handling quoted values properly (e.g., MESSAGE="Unknown STYLE")
  const args: string[] = [];
  let currentArg = "";
  let inQuotes = false;

  for (let i = 0; i < argString.length; i++) {
    const char = argString[i];

    if (char === '"') {
      inQuotes = !inQuotes; // Toggle the inQuotes flag
      currentArg += char;
    } else if (char === " " && !inQuotes) {
      // Only treat space as a separator when not inside quotes
      if (currentArg) {
        args.push(currentArg);
        currentArg = "";
      }
    } else {
      currentArg += char;
    }
  }

  // Push the last argument if there's any
  if (currentArg) {
    args.push(currentArg);
  }

  return args;
};
