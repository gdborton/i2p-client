import EventEmitter from "node:events";
import { Socket } from "node:net";
import dgram from "node:dgram";

// @ts-expect-error
import split2 from "split2";
import TypedEmitter from "typed-emitter";
import {
  b64stringToB32String,
  stringDestinationToBuffer,
} from "./utils/utils.js";
import { Destination } from "./Destination.js";
import { parseMessage, SamReplies } from "./utils/sam-utils.js";
import { R } from "vitest/dist/chunks/environment.d.cL3nLXbE.js";

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

type SessionType = "STREAM" | "DATAGRAM" | "RAW";
const socketsToCleanUp: Set<Socket> = new Set();
const cleanup = () => {
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
      this.emit("error", err);
    });
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
        this.emit(
          "error",
          new Error(`${SamReplies.REPLY_STREAM}: ${msg.args.RESULT}`),
        );
        // this.destroy();
      }
    } else if (msg.type === SamReplies.REPLY_SESSION) {
      if (msg.args.RESULT === "OK") {
        this.emit("session", msg.args.ID);
      } else {
        console.error("SESSION ERROR:", msg);
      }
    } else if (msg.type === SamReplies.REPLY_NAMING) {
      if (msg.args.RESULT === "OK") {
        this.emit("nameLookupResult", msg.args.VALUE);
      } else {
        this.emit("error", new Error(msg.args.MESSAGE));
      }
    } else if (msg.type === SamReplies.REPLY_QUIT) {
      if (msg.args.RESULT === "OK") {
        this.socket.destroy();
      }
    } else if (msg.type === SamReplies.PING) {
      // Handle PING messages if needed
      this.socket.write(
        `PONG${msg.args.REMAINDER ? ` ${msg.args.REMAINDER}` : ""}\n`,
      );
    } else {
      console.log("raw message", message);
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
      if (msg.args.RESULT === "OK") {
        this.emit("session", msg.args.ID);
      } else {
        console.error("SESSION ERROR:", msg.args.RESULT);
      }
    } else if (msg.type === SamReplies.REPLY_NAMING) {
      if (msg.args.RESULT === "OK") {
        this.emit("nameLookupResult", msg.args.VALUE);
      } else {
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

export type StreamEvent = StreamAcceptSocket;
type StreamSessionEvents = {
  stream: (stream: StreamEvent) => void;
};
export class StreamSession extends (EventEmitter as new () => TypedEmitter<StreamSessionEvents>) {
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
            this.emit("stream", acceptSocket);
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
          (subsession as RepliableDatagramSession).emit("repliableDatagram", {
            destination: destination,
            fromPort: parseInt(args.FROM_PORT, 10),
            toPort,
            payload,
          });
        }
      } else {
        (subsession as RawDatagramSession).emit("rawDatagram", msg);
      }
    });

    server.bind(port); // The port number to listen on
  }
}
export type RawDatagramEvent = Buffer;
type RawDGEvents = {
  rawDatagram: (payload: RawDatagramEvent) => void;
};
export class RawDatagramSession extends (EventEmitter as new () => TypedEmitter<RawDGEvents>) {
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
    const header = Buffer.from(headerStr);
    const message = Buffer.concat([header, payload]);
    this.socket.send(message, this.port, this.host);
  }
}

process.on("uncaughtException", (err) => {
  console.error("🔥 Uncaught exception:", err);
  console.error(err.stack);
});

export type RepliableDatagramEvent = {
  destination: string;
  fromPort: number;
  toPort: number;
  payload: Buffer;
};
type RepliableDBEvents = {
  repliableDatagram: (obj: RepliableDatagramEvent) => void;
};
export class RepliableDatagramSession extends (EventEmitter as new () => TypedEmitter<RepliableDBEvents>) {
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

    // Build header as plain string first
    const headerStr = `3.0 ${this.id} ${paddedDestination} FROM_PORT=${sourcePort} TO_PORT=${destinationPort}\n`;

    const header = Buffer.from(headerStr);
    const message = Buffer.concat([header, payload]);

    this.socket.send(message, this.port, this.host);
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

export class SAM extends EventEmitter {
  /**
   * Generate a new I2P destination via SAM bridge.
   * Creates a temporary connection to generate keys and immediately closes it.
   */
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
}
