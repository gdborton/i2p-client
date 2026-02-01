import { Socket } from "net";
import { promisify } from "node:util";
import { EventEmitter } from "events";
import { gzip as gzipCallback } from "node:zlib";

import LRU from "lru";
import TypedEmitter from "typed-emitter";
import { generateKeyPair as generateX25519KeyPair } from "ecies-25519";

import { generatePrivateKeyPair as genEgamlKeyPair } from "../../crypto/elgamal.js";
import { stringDestinationToBuffer } from "../../utils/utils.js";
import {
  Destination,
  generateLocalDestination,
  LocalDestination,
  SIGNING_PUBLIC_KEY_TYPE,
} from "../../protocol/Destination.js";
import { I2CPSocket, Packet } from "./I2CPSocket.js";
import { oneByteInteger, twoByteInteger } from "../../utils/byte-utils.js";
import { createDatagram1 } from "../../protocol/Datagram1.js";
import {
  I2P_PROTOCOL,
  MESSAGE_ID_BYTE_LENGTH,
  MESSAGE_SIZE_BYTE_LENGTH,
  MESSAGE_STATUS_BYTE_LENGTH,
  NONCE_BYTE_LENGTH,
  SESSION_ID_BYTE_LENGTH,
  unpackMessagePayloadMessage,
} from "./i2cp-utils.js";

export { bufferDestinationToString } from "../../utils/utils.js";

const gzip = promisify(gzipCallback);

const I2CP_PROTOCOL_VERSION_BYTE = Buffer.from([0x2a]);
const I2CP_VERSION = "0.9.65";

// https://geti2p.net/spec/i2cp#getdatemessage
const messageTypes = {
  // BandwidthLimitsMessage	R -> C	23	0.7.2
  BandwidthLimitsMessage: 23,
  // BlindingInfoMessage	C -> R	42	0.9.43
  BlindingInfoMessage: 42,
  // CreateLeaseSetMessage	C -> R	4	deprecated
  CreateLeaseSetMessage: 4,
  // CreateLeaseSet2Message	C -> R	41	0.9.39
  CreateLeaseSet2Message: 41,
  // CreateSessionMessage	C -> R	1
  CreateSessionMessage: 1,
  // DestLookupMessage	C -> R	34	0.7
  DestLookupMessage: 34,
  // DestReplyMessage	R -> C	35	0.7
  DestReplyMessage: 35,
  // DestroySessionMessage	C -> R	3
  DestroySessionMessage: 3,
  // DisconnectMessage	bidir.	30
  DisconnectMessage: 30,
  // GetBandwidthLimitsMessage	C -> R	8	0.7.2
  GetBandwidthLimitsMessage: 8,
  // GetDateMessage	C -> R	32
  GetDateMessage: 32,
  // HostLookupMessage	C -> R	38	0.9.11
  HostLookupMessage: 38,
  // HostReplyMessage	R -> C	39	0.9.11
  HostReplyMessage: 39,
  // MessagePayloadMessage	R -> C	31
  MessagePayloadMessage: 31,
  // MessageStatusMessage	R -> C	22
  MessageStatusMessage: 22,
  // ReceiveMessageBeginMessage	C -> R	6	deprecated
  ReceiveMessageBeginMessage: 6,
  // ReceiveMessageEndMessage	C -> R	7	deprecated
  ReceiveMessageEndMessage: 7,
  // ReconfigureSessionMessage	C -> R	2	0.7.1
  ReconfigureSessionMessage: 2,
  // ReportAbuseMessage	bidir.	29	deprecated
  ReportAbuseMessage: 29,
  // RequestLeaseSetMessage	R -> C	21	deprecated
  RequestLeaseSetMessage: 21,
  // RequestVariableLeaseSetMessage	R -> C	37	0.9.7
  RequestVariableLeaseSetMessage: 37,
  // SendMessageMessage	C -> R	5
  SendMessageMessage: 5,
  // SendMessageExpiresMessage	C -> R	36	0.7.1
  SendMessageExpiresMessage: 36,
  // SessionStatusMessage	R -> C	20
  SessionStatusMessage: 20,
  // SetDateMessage	R -> C	33
  SetDateMessage: 33,
};

const messageTypesReverse = Object.fromEntries(
  Object.entries(messageTypes).map(([key, value]) => [value, key]),
);

enum SESSION_STATUS {
  DESTROYED = 0,
  CREATED = 1,
  UPDATED = 2,
  INVALID = 3,
  REFUSED = 4,
}

const I2CPBufferToString = (buffer: Buffer) => {
  const length = buffer.readUInt8(0);
  if (length === 0) {
    return null; // Return null for zero-length strings
  }
  return buffer.subarray(1, length + 1).toString("utf-8");
};

const stringToI2CPBuffer = (string: string | null) => {
  if (string === null) {
    return Buffer.from([0]); // Write 0 length for null strings
  } else {
    const len = string.length;
    if (len > 255) {
      throw new Error(
        `The I2P data spec limits strings to 255 bytes or less, but this is ${len} [${string}]`,
      );
    }

    // Write the length as a single byte
    const lengthBuffer = Buffer.alloc(1);
    lengthBuffer.writeUInt8(len, 0); // 4 bytes for length
    // convert lengthBuffer to a number
    // const lengthBuffer = Buffer.from([len]);

    // Write each character as a byte
    const bytes = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = string.charCodeAt(i) & 0xff;
    }

    return Buffer.from([...lengthBuffer, ...bytes]);
  }
};

const createMessageBuffer = (
  type: keyof typeof messageTypes,
  message: Buffer,
) => {
  // Create a buffer for the message header (4 bytes for length + 1 byte for type)
  const header = Buffer.alloc(5);
  // Write the message length to the header
  header.writeUInt32BE(message.byteLength, 0); // Total message length
  // Write the message type to the header
  header.writeUInt8(messageTypes[type], 4); // Message type
  // Combine the header and message buffer
  return Buffer.concat([header, message]);
};

const createDateGetMessage = (version: string): Buffer => {
  const versionBuffer = stringToI2CPBuffer(version);
  // Emissary requires the options Mapping even though the spec says it's optional
  // An empty mapping is 2 bytes (0x00 0x00 for length)
  const emptyOptionsMapping = Buffer.alloc(2);
  return createMessageBuffer(
    "GetDateMessage",
    Buffer.concat([versionBuffer, emptyOptionsMapping]),
  );
};

const createHostLookupMessage = (payload: Buffer) => {
  return createMessageBuffer("HostLookupMessage", payload);
};

const decodeMessage = (data: Buffer) => {
  // Get the message length from the first 4 bytes
  const messageLength = data.readUInt32BE(0);
  // Get the message type from the next byte
  const messageType = data.readUInt8(4);
  // Get the message data from the rest of the buffer
  const messageData = data.subarray(5);
  // Return the message type and data
  return {
    messageType,
    messageLength,
    messageData,
  };
};

type Events = {
  session_created: () => void;
  leaseset_created: () => void;
  stream: (socket: I2CPSocket) => void;
};

type PortEvents = {
  repliableMessage: (
    fromDestination: Destination,
    sourcePort: number,
    payload: Buffer,
  ) => void;
  nonRepliableMessage: (sourcePort: number, payload: Buffer) => void;
};

const lookupCache: LRU<Buffer> = new LRU({
  max: 1000,
});

export class I2CPPort extends (EventEmitter as new () => TypedEmitter<PortEvents>) {
  public portNumber: number;
  private i2cp: I2CPSession;
  constructor(i2cp: I2CPSession, port: number) {
    super();
    this.portNumber = port;
    this.i2cp = i2cp;
  }

  public sendRepliableDatagram = (
    destination: Buffer | string,
    toPort: number,
    payload: Buffer,
  ) => {
    return this.i2cp.sendRepliableDatagram(
      destination,
      this.portNumber,
      toPort,
      payload,
    );
  };

  public sendDatagram = (
    destination: Buffer | string,
    toPort: number,
    payload: Buffer,
  ) => {
    return this.i2cp.sendDatagram(
      destination,
      this.portNumber,
      toPort,
      payload,
    );
  };
}

/**
 *
 * Flag bits:
 * order:
 * 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
 * Bit 0 - 0 = no offline keys, 1 = offline keys
 * Bit 1 - 0 = standard leaseset, 1 = unpublished leaseset
 * Bit 2 - 0 = standard leaseset, 1 = encrypt when published
 */
const createLeaseSet2Header = (
  destination: LocalDestination,
  options: {
    offlineSignature?: Buffer;
    unpublishedLeaseSet?: boolean;
    blindAndEncryptWhenPublished?: boolean;
  } = {
    offlineSignature: undefined, // bit 0
    unpublishedLeaseSet: false, // bit 1
    blindAndEncryptWhenPublished: false, // bit 2
  },
): Buffer => {
  const published = Math.floor(Date.now() / 1000);
  const publishedBuffer = Buffer.alloc(4);
  publishedBuffer.writeUInt32BE(published, 0);
  const expires = 10 * 60; // 10 minutes // 18 * 60 * 60; // 18 hours
  const expiresBuffer = Buffer.alloc(2);
  expiresBuffer.writeUInt16BE(expires, 0);
  const offlineSignature = options.offlineSignature || Buffer.alloc(0);
  const bit0 = offlineSignature.byteLength ? 1 : 0;
  const bit1 =
    options.unpublishedLeaseSet || options.blindAndEncryptWhenPublished ? 1 : 0;
  const bit2 = options.blindAndEncryptWhenPublished ? 1 : 0;
  const flagsBuffer = Buffer.alloc(2);
  flagsBuffer.writeUInt8((bit0 << 0) | (bit1 << 1) | (bit2 << 2), 1);
  const result = Buffer.concat([
    destination.buffer,
    publishedBuffer,
    expiresBuffer,
    flagsBuffer,
    offlineSignature,
  ]);
  return result;
};

const createOptionsBuffer = (options: Record<string, string>): Buffer => {
  // https://geti2p.net/spec/common-structures#type-mapping
  const optionsLengthBuffer = Buffer.alloc(2); // 2 bytes for options, this is a mapping, but we're not going to pass any options yet
  let optionsMapBuffer = Buffer.alloc(0);
  Object.keys(options)
    .sort() // ensure we're consistently sorting
    .forEach((key) => {
      const value = options[key];
      const keyBuffer = stringToI2CPBuffer(key);
      const valueBuffer = stringToI2CPBuffer(value);
      optionsMapBuffer = Buffer.concat([
        optionsMapBuffer,
        keyBuffer,
        Buffer.from("="),
        valueBuffer,
        Buffer.from(";"),
      ]);
    });
  optionsLengthBuffer.writeUInt16BE(optionsMapBuffer.byteLength, 0); // 2 bytes for options length
  return Buffer.concat([optionsLengthBuffer, optionsMapBuffer]);
};

// https://geti2p.net/en/docs/protocol/i2cp#options
type SessionOptions = {
  "i2cp.fastReceive"?: "true" | "false";
  "i2cp.leaseSetEncType"?: "4,0" | "4" | "0";
};
const createSessionOptionsBuffer = (options: SessionOptions): Buffer => {
  return createOptionsBuffer(options);
};

// https://github.com/i2p/i2p.i2p/blob/master/core/java/src/net/i2p/crypto/EncType.java#L21
enum enctryptionKeyTypeMap {
  ELGAMAL_2048 = 0,
  EC_P256 = 1,
  EC_P384 = 2,
  EC_P521 = 3,
  ECIES_X25519 = 4,
}

const CreateLeaseSet2Message = (
  dest: LocalDestination,
  sessionId: number,
  leasesBuffer: Buffer,
) => {
  const { publicKey: elgamalPublic, privateKey: elgamalPrivate } =
    genEgamlKeyPair();
  const { publicKey: x25519Public, privateKey: x25519Private } =
    generateX25519KeyPair();
  const keys: {
    public: Uint8Array;
    private: Uint8Array;
    type: enctryptionKeyTypeMap;
  }[] = [
    {
      type: enctryptionKeyTypeMap.ELGAMAL_2048,
      public: Buffer.from(elgamalPublic.toString(16), "hex"),
      private: Buffer.from(elgamalPrivate.toString(16), "hex"),
    },
    {
      type: enctryptionKeyTypeMap.ECIES_X25519,
      public: x25519Public,
      private: x25519Private,
    },
  ];

  // https://geti2p.net/spec/common-structures#struct-leaseset2
  if (leasesBuffer.byteLength % 40 !== 0) {
    throw new Error(
      `Leases buffer is not a multiple of 40 bytes, but ${leasesBuffer.byteLength} bytes`,
    );
  }
  const leaseSet2Buffer = Buffer.concat([
    createLeaseSet2Header(dest),
    createOptionsBuffer({}),
    oneByteInteger(keys.length),
    ...keys.map((keyData) => {
      return Buffer.concat([
        twoByteInteger(keyData.type),
        twoByteInteger(keyData.public.byteLength),
        keyData.public,
      ]);
    }),
    Buffer.from([leasesBuffer.byteLength / 40]), // number of leases
    leasesBuffer,
  ]);
  // signiture is prepended w/ datastore type
  const signatureBuffer = dest.sign(
    Buffer.concat([Buffer.from([3]), leaseSet2Buffer]),
  );
  const signedLeaseSet2Buffer = Buffer.concat([
    leaseSet2Buffer,
    signatureBuffer,
  ]);
  return createMessageBuffer(
    "CreateLeaseSet2Message",
    Buffer.concat([
      twoByteInteger(sessionId),
      oneByteInteger(3), // 3 === leaseset2
      signedLeaseSet2Buffer,
      oneByteInteger(keys.length),
      ...keys.map((keyData) => {
        return Buffer.concat([
          twoByteInteger(keyData.type),
          twoByteInteger(keyData.private.byteLength),
          keyData.private,
        ]);
      }),
    ]),
  );
};

const LEASE_1_BYTE_LENGTH = 44;
const LEASE_2_BYTE_LENGTH = 40;
const convertLease1sToLease2s = (count: number, leases: Buffer): Buffer => {
  // if we're already in the right format, just return the leases
  if (leases.byteLength / count === LEASE_2_BYTE_LENGTH) {
    return leases;
  }
  let newBuff = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    const lease = leases.subarray(
      i * LEASE_1_BYTE_LENGTH,
      (i + 1) * LEASE_1_BYTE_LENGTH,
    );
    const tunnelHashAndId = lease.subarray(0, 32 + 4);
    const oldEndDateBuffer = lease.subarray(32 + 4);
    if (oldEndDateBuffer.byteLength !== 8) {
      throw new Error("unexpected end date length");
    }
    const newEndDateBuffer = Buffer.alloc(4);
    const endDate = Number(oldEndDateBuffer.readBigUint64BE(0));
    newEndDateBuffer.writeUInt32BE(Math.floor(endDate / 1000), 0);
    const newLease = Buffer.concat([tunnelHashAndId, newEndDateBuffer]);
    if (newLease.byteLength !== LEASE_2_BYTE_LENGTH) {
      throw new Error(
        `Lease2 is not the right length, but ${newLease.byteLength} bytes`,
      );
    }
    newBuff = Buffer.concat([newBuff, newLease]);
  }
  return newBuff;
};

/**
 * Returns a usable payload for the SendMessageMessage.
 * Final Buffer looks like this:
 * 4 byte length + gzipped payload
 */
const createPayload = async (
  payload: Buffer,
  sourcePort: number,
  destinationPort: number,
  protocol: I2P_PROTOCOL,
): Promise<Buffer> => {
  const workedPayloadBuffer = await gzip(payload);
  workedPayloadBuffer.writeUint16BE(sourcePort, 4);
  workedPayloadBuffer.writeUint16BE(destinationPort, 6);
  workedPayloadBuffer.writeUInt8(protocol, 9);
  const payloadLengthBuffer = Buffer.alloc(4);
  payloadLengthBuffer.writeUInt32BE(workedPayloadBuffer.byteLength, 0);
  const packedPayload = Buffer.concat([
    payloadLengthBuffer,
    workedPayloadBuffer,
  ]);
  return packedPayload;
};

enum MESSAGE_STATUS {
  AVAILABLE = 0,
  ACCEPTED = 1,
  BEST_EFFORT_SUCCESS = 2,
  BEST_EFFORT_FAILURE = 3,
  GUARANTEED_SUCCESS = 4,
  GUARANTEED_FAILURE = 5,
  LOCAL_SUCESS = 6,
  LOCAL_FAILURE = 7,
  ROUTER_FAILURE = 8,
  NETWORK_FAILURE = 9,
  BAD_SESSION = 10,
  BAD_MESSAGE = 11,
  BAD_OPTIONS = 12,
  OVERFLOW_FAILURE = 13,
  MESSAGE_EXPIRED = 14,
  BAD_LOCAL_LEASESET = 15,
  NO_LOCAL_TUNNELS = 16,
  UNSUPPORTED_ENCRYPTION = 17,
  BAD_DESTINATION = 18,
  BAD_LEASESET = 19,
  EXPIRED_LEASESET = 20,
  NO_LEASESET = 21,
  META_LEASESET = 22,
  LOOPBACK_DENIED = 23,
}

enum HOST_REPLY_STATUS {
  SUCCESS = 0,
  FAILURE = 1,
  PASSWORD_REQUIRED = 2,
  PRIVATE_KEY_REQUIRED = 3,
  PASSWORD_AND_PRIVATE_KEY_REQUIRED = 4,
  LEASESET_DECRYPTION_FAILURE = 5,
  LEASESET_LOOKUP_FAILURE = 6,
  LOOKUP_TYPE_UNSUPPORTED = 7,
}

// just here for debugging help
let messagesSent = 0;
let messagesAccepted = 0;
let messagesFailed = 0;
let messageLikelySucceeded = 0;

export class I2CPSession extends (EventEmitter as new () => TypedEmitter<Events>) {
  private destination: LocalDestination;
  private socket: Socket;
  private sessionId: Buffer | null = null;

  private portConnections = new Map<number, I2CPPort>();

  /**
   * Map of lookup request ids to their resolve and reject functions.
   */
  private lookupHandlers = new Map<
    number,
    [string, (destination: Buffer) => void, (reason: Error) => void]
  >();

  /**
   * Keep tracks of open streams by their streamID.
   */
  private streams: Record<number, I2CPSocket> = {};

  private socketConnected = false;

  constructor(
    {
      i2cpPort,
      i2cpHost,
      destination,
    }: {
      i2cpPort: number;
      i2cpHost: string;
      destination?: LocalDestination;
    } = {
      i2cpPort: 7654,
      i2cpHost: "localhost",
    },
  ) {
    super();
    this.destination = destination
      ? destination
      : generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1).destination;
    const socketConfig = {
      host: i2cpHost,
      port: i2cpPort,
    };
    this.socket = new Socket().connect(socketConfig);
    let reconnectTimer: NodeJS.Timeout | null = null;
    this.socket.on("connect", () => {
      clearInterval(reconnectTimer!);
      this.socketConnected = true;
    });
    const attemptReconnect = () => {
      reconnectTimer = setInterval(() => {
        clearInterval(reconnectTimer!);
        if (this.socketConnected) return;
        reconnectTimer = null;
        this.socket.connect(socketConfig);
      }, 5000);
    };
    this.socket.on("close", () => {
      this.socketConnected = false;
      // reconnect logic can be added here
      attemptReconnect();
    });
    this.socket.on("error", (error) => {
      attemptReconnect();
    });
    this.socket.on("data", this.routeMessage);
    this.write(I2CP_PROTOCOL_VERSION_BYTE);
    this.write(createDateGetMessage(I2CP_VERSION));
  }

  getDestinationString() {
    return this.destination.string;
  }

  getDestinationBuffer() {
    return this.destination.buffer;
  }

  public connect = (port: number) => {
    if (this.portConnections.has(port)) {
      throw new Error(`Port ${port} is already in use.`);
    }
    const portConnection = new I2CPPort(this, port);
    this.portConnections.set(port, portConnection);
    return portConnection;
  };

  sendDatagram = async (
    destination: string | Buffer,
    sourcePort: number,
    destinationPort: number,
    payload: Buffer,
  ) => {
    if (!this.sessionId) {
      throw new Error("Session ID is not set");
    }
    messagesSent++;
    const destinationBuffer =
      typeof destination === "string"
        ? stringDestinationToBuffer(destination)
        : destination;
    const sendMessage = await this.createSendMessageMessage(
      destinationBuffer,
      sourcePort,
      destinationPort,
      I2P_PROTOCOL.RAW_DATAGRAM,
      payload,
    );
    this.write(sendMessage);
  };

  sendRepliableDatagram = async (
    destination: string | Buffer,
    sourcePort: number,
    destinationPort: number,
    payload: Buffer,
  ) => {
    if (!this.sessionId) {
      throw new Error("Session ID is not set");
    }
    messagesSent++;
    const destinationBuffer =
      typeof destination === "string"
        ? stringDestinationToBuffer(destination)
        : destination;
    const sendMessage = await this.createSendMessageMessage(
      destinationBuffer,
      sourcePort,
      destinationPort,
      I2P_PROTOCOL.REPLIABLE_DATAGRAM,
      payload,
    );

    this.write(sendMessage);
  };

  /**
   * I don't know yet if this will stick around.
   */
  sendStreamDatagram = async (
    destination: Buffer,
    sourcePort: number,
    destinationPort: number,
    payload: Buffer,
  ) => {
    const sendMessage = await this.createSendMessageMessage(
      destination,
      sourcePort,
      destinationPort,
      I2P_PROTOCOL.STREAMING,
      payload,
    );
    this.write(sendMessage);
  };

  public lookup = async (destString: string): Promise<Buffer> => {
    if (typeof destString !== "string")
      throw new Error("Invalid destination string");
    if (!destString.includes(".i2p"))
      throw new Error("Invalid destination host string");
    const cached = lookupCache.get(destString);
    if (cached) return Promise.resolve(cached);
    return new Promise(async (resolve, reject) => {
      if (!this.sessionId) throw new Error("Session not started yet");
      const lookupId = this.generateLookupId();
      const timeout = setTimeout(() => {
        reject(new Error("timeout"));
      }, 10_000);
      let resolved = false;
      let rejected = false;
      const cleanup = () => {
        clearTimeout(timeout);
        this.lookupHandlers.delete(lookupId);
        if (resolved || rejected) throw new Error("Promise already settled.");
      };
      const resolveFn = (destination: Buffer) => {
        cleanup();
        resolved = true;
        resolve(destination);
      };
      const rejectFn = (reason: Error) => {
        cleanup();
        rejected = true;
        reject(reason);
      };
      this.lookupHandlers.set(lookupId, [destString, resolveFn, rejectFn]);
      const requestIdBuffer = Buffer.alloc(4);
      requestIdBuffer.writeUInt32BE(lookupId, 0);
      const timeoutBuffer = Buffer.alloc(4);
      timeoutBuffer.writeUInt32BE(10_000, 0); // ms
      const requestTypeBuffer = Buffer.from([0x01]); // host name string
      const lookupPayload = Buffer.concat([
        this.sessionId,
        requestIdBuffer,
        timeoutBuffer,
        requestTypeBuffer,
        stringToI2CPBuffer(destString),
      ]);
      this.write(createHostLookupMessage(lookupPayload));
    });
  };

  private lookupId = 0;
  private generateLookupId = () => {
    if (this.lookupId > 65535) {
      this.lookupId = 0;
    }
    this.lookupId++;
    return this.lookupId;
  };

  public createStream(destination: Buffer) {
    const stream = new I2CPSocket(
      this,
      new Destination(destination),
      this.destination,
      true,
    );
    this.streams[stream.streamId] = stream;
    stream.on("close", (error: unknown) => {
      delete this.streams[stream.streamId];
    });
    stream.on("finish", () => {
      delete this.streams[stream.streamId];
    });
    stream.on("end", () => {
      delete this.streams[stream.streamId];
    });
    return stream;
  }

  stream = async (
    destination: string | Buffer,
    sourcePort: number,
    destinationPort: number,
    payload: Buffer,
  ) => {
    if (!this.sessionId) {
      throw new Error("Session ID is not set");
    }
    const destinationBuffer =
      typeof destination === "string"
        ? stringDestinationToBuffer(destination)
        : destination;
    const sendMessage = await this.createSendMessageMessage(
      destinationBuffer,
      sourcePort,
      destinationPort,
      I2P_PROTOCOL.STREAMING,
      payload,
    );
    this.write(sendMessage);
  };

  private routeMessage = (data: Buffer) => {
    const decoded = decodeMessage(data);
    const messageType = decoded.messageType;
    switch (messageType) {
      case messageTypes.SetDateMessage:
        this.handleSetDateMessage(decoded.messageData);
        break;
      case messageTypes.SessionStatusMessage:
        this.handleSessionStatusMessage(decoded.messageData);
        break;
      case messageTypes.RequestVariableLeaseSetMessage:
        this.handleRequestVariableLeaseSetMessage(decoded.messageData);
        break;
      case messageTypes.MessageStatusMessage:
        this.handleMessageStatusMessage(decoded.messageData);
        break;
      case messageTypes.MessagePayloadMessage:
        this.handleMessagePayloadMessage(decoded.messageData);
        break;
      case messageTypes.HostReplyMessage:
        this.handleHostReplyMessage(decoded.messageData);
        break;
      default:
        const messageData = decoded.messageData.toString("utf-8");
        console.log("--- got unhandled message type --");
        console.log(
          "message type:",
          messageType,
          messageTypesReverse[messageType],
        );
        console.log("Decoded message data:", messageData);
        console.log("---");
        break;
    }
  };

  private write(message: Buffer) {
    this.socket.write(message, (err) => {
      if (err) console.error("Error writing message:", err);
    });
  }

  // #region Message Handlers
  private handleSetDateMessage = (data: Buffer) => {
    const timestamp = data.readBigUInt64BE(0);
    // const date = new Date(Number(timestamp));
    if (this.sessionId) return;

    const sessionConfigBuffer = generateSessionConfigBuffer(this.destination);
    const createMessage = createMessageBuffer(
      "CreateSessionMessage",
      sessionConfigBuffer,
    );
    this.write(createMessage);
  };

  private handleSessionStatusMessage = async (data: Buffer) => {
    const sessionId = data.subarray(0, 2);
    const status = data.readUint8(2);
    if (status === SESSION_STATUS.CREATED) {
      this.emit("session_created");
    }
    this.sessionId = sessionId;
  };

  private handleRequestVariableLeaseSetMessage = (data: Buffer) => {
    const sessionId = data.readUint16BE(0);
    const numberOfTunnels = data.readUintBE(2, 1);
    // lease1s are 44 bytes each
    // they consist of the following:
    // 32 bytes for the hash of the tunnel gateway
    // 4 bytes for the tunnel id
    // 8 bytes for the expiration date, ms from epoch

    // lease2s are 40 bytes each
    // they're the same as lease1s, but the expiration date is 4 bytes and seconds
    const leases = data.subarray(3);
    const createLease2Message = CreateLeaseSet2Message(
      this.destination,
      sessionId,
      convertLease1sToLease2s(numberOfTunnels, leases),
    );
    this.write(createLease2Message);

    this.emit("leaseset_created");
  };

  private handleMessageStatusMessage = (data: Buffer) => {
    const sessionId = data.readUint16BE(0);
    const messageID = data.readInt32BE(SESSION_ID_BYTE_LENGTH);
    const messageStatus = data.readUInt8(
      SESSION_ID_BYTE_LENGTH + MESSAGE_ID_BYTE_LENGTH,
    ) as MESSAGE_STATUS;
    const messageSize = data.readUInt32BE(
      SESSION_ID_BYTE_LENGTH +
        MESSAGE_ID_BYTE_LENGTH +
        MESSAGE_STATUS_BYTE_LENGTH,
    );
    const nonce = data.readUInt32BE(
      SESSION_ID_BYTE_LENGTH +
        MESSAGE_ID_BYTE_LENGTH +
        MESSAGE_STATUS_BYTE_LENGTH +
        MESSAGE_SIZE_BYTE_LENGTH,
    );

    if (messageStatus !== MESSAGE_STATUS.ACCEPTED) {
      // console.log("got a message status -", messageStatus);
    }
    switch (messageStatus) {
      case MESSAGE_STATUS.ACCEPTED:
        messagesAccepted++;
        break;
      case MESSAGE_STATUS.GUARANTEED_SUCCESS:
      case MESSAGE_STATUS.BEST_EFFORT_SUCCESS:
      case MESSAGE_STATUS.LOCAL_SUCESS:
        messageLikelySucceeded++;
        break;
      case MESSAGE_STATUS.GUARANTEED_FAILURE:
      case MESSAGE_STATUS.LOCAL_FAILURE:
      case MESSAGE_STATUS.BEST_EFFORT_FAILURE:
      case MESSAGE_STATUS.BAD_DESTINATION:
      case MESSAGE_STATUS.BAD_LEASESET:
      case MESSAGE_STATUS.EXPIRED_LEASESET:
      case MESSAGE_STATUS.LOOPBACK_DENIED:
      case MESSAGE_STATUS.NETWORK_FAILURE:
      case MESSAGE_STATUS.UNSUPPORTED_ENCRYPTION:
      case MESSAGE_STATUS.NO_LEASESET:
      case MESSAGE_STATUS.ROUTER_FAILURE:
      case MESSAGE_STATUS.OVERFLOW_FAILURE:
        messagesFailed++;
        console.log(`message: ${messageID}, failed w/ ${messageStatus}`);
        break;
      default:
        console.log("unhandled message status", messageStatus);
    }
  };

  private handleMessagePayloadMessage = async (data: Buffer) => {
    const { payload, sourcePort, destinationPort, protocol, from } =
      await unpackMessagePayloadMessage(data);
    if (protocol === I2P_PROTOCOL.STREAMING) {
      const packet = new Packet(payload);
      const stream =
        this.streams[packet.receiveStreamId] ||
        this.streams[packet.sendStreamId];
      if (stream) {
        stream.handlePacket(packet);
      } else {
        // this is a remote attempting to start a stream with us
        if (packet.sync && packet.sendStreamId === 0) {
          if (!packet.from) {
            console.log("no from destination in sync packet, dropping");
            return;
          }
          const socket = new I2CPSocket(
            this,
            new Destination(packet.from.buffer),
            this.destination,
            false,
          );
          socket.on("close", () => {
            delete this.streams[socket.streamId];
          });
          this.streams[socket.streamId] = socket;
          this.emit("stream", socket);
          socket.handlePacket(packet);
        } else if (!packet.close && packet.sequenceNum !== 0) {
          // TODO- they're sending us data, but the stream is already closed :/
          return;
        }
        return;
      }
    } else {
      const listener = this.portConnections.get(destinationPort);
      if (listener) {
        if (from) {
          listener.emit(
            "repliableMessage",
            new Destination(from.buffer),
            sourcePort,
            payload,
          );
        } else {
          listener.emit("nonRepliableMessage", sourcePort, payload);
        }
      } else {
        console.log(
          `No listener for port ${destinationPort} proto:${protocol}, unable to deliver message`,
        );
      }
    }
  };

  private handleHostReplyMessage = async (data: Buffer) => {
    const sessionId = data.readUint16BE(0); // 2 bytes
    const requestId = data.readInt32BE(SESSION_ID_BYTE_LENGTH); // 4 bytes
    const resultCode = data.readUInt8(
      SESSION_ID_BYTE_LENGTH + MESSAGE_ID_BYTE_LENGTH,
    ) as HOST_REPLY_STATUS; // 1 byte
    const handlers = this.lookupHandlers.get(requestId);
    if (!handlers) {
      console.log("no handlers for requestId", requestId, "bailing");
      return;
    }
    const [queryString, resolve, reject] = handlers;
    if (resultCode === HOST_REPLY_STATUS.SUCCESS) {
      const buff = new Destination(data.subarray(7)).buffer;
      lookupCache.set(queryString, buff);
      return resolve(buff);
    } else {
      switch (resultCode) {
        default:
          return reject(
            new Error(
              `Unexpected lookup status code: ${resultCode} (${requestId})`,
            ),
          );
      }
    }
  };
  // #endregion

  // #region Message Creators
  private createSendMessageMessage = async (
    destinationBuffer: Buffer,
    sourcePort: number,
    destinationPort: number,
    protocol: I2P_PROTOCOL,
    payload: Buffer,
  ) => {
    if (!this.sessionId) throw new Error("Session ID is not set");
    const nonceBuffer = Buffer.alloc(NONCE_BYTE_LENGTH); // 4 byte nonce
    nonceBuffer.writeUInt32BE(Math.floor(Math.random() * 1000000), 0);
    const repliables = new Set([I2P_PROTOCOL.REPLIABLE_DATAGRAM]);
    const sizeAndPayloadBuffer = repliables.has(protocol)
      ? await this.createRepliablePayload(
          payload,
          sourcePort,
          destinationPort,
          protocol,
        )
      : await createPayload(payload, sourcePort, destinationPort, protocol);

    return createMessageBuffer(
      "SendMessageMessage",
      Buffer.concat([
        this.sessionId,
        destinationBuffer,
        sizeAndPayloadBuffer,
        nonceBuffer,
      ]),
    );
  };
  // #endregion

  private createRepliablePayload = async (
    payload: Buffer,
    sourcePort: number,
    destinationPort: number,
    protocol: I2P_PROTOCOL,
  ): Promise<Buffer> => {
    const datagram = createDatagram1(this.destination, payload);
    return createPayload(datagram, sourcePort, destinationPort, protocol);
  };
}

const generateSessionConfigBuffer = (destination: LocalDestination) => {
  const optionsBuffer = createSessionOptionsBuffer({
    "i2cp.fastReceive": "true",
    "i2cp.leaseSetEncType": "4,0",
  });
  const now = Date.now();
  const dateBuffer = Buffer.alloc(8);
  dateBuffer.writeBigUInt64BE(BigInt(now), 0); // 8 bytes for date
  const contentBuff = Buffer.concat([
    destination.buffer,
    optionsBuffer,
    dateBuffer,
  ]);
  return Buffer.concat([contentBuff, destination.sign(contentBuff)]);
};
