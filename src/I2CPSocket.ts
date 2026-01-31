import { Duplex } from "stream";
import { I2CPSession } from "./i2cp.js";
import { Destination, LocalDestination } from "./Destination.js";
import {
  setBit,
  twoByteInteger,
  fourByteInteger,
  oneByteInteger,
  getBit,
} from "./utils/byte-utils.js";

const RESEND_DELAY_SECONDS = 3; // 3 seconds
enum PacketType {
  /**
   * Used to tell the remote peer that we want to establish a connection.
   * They should respond with a SYN packet.
   */
  SYNC = 0,
  /**
   * Used to tell the remote peer that we want to close the connection.
   * They should respond with a CLOSE packet.
   */
  CLOSE = 1,
  /**
   * An abnormal close. Something went wrong, tells the remote to reset the connection.
   */
  RESET = 2,
  ECHO = 3,
  ESTABLISHED = 4,
  /**
   * Just a plain old ack, should use sequence number 0, and contain no payload.
   */
  ACK = 5,
}
// TODO - Replay prevention, on initiation send NACKS=8 and set to targets 32byte hash
// on receiving sync, check if the hash is in the list of NACKS field

enum FLAG_BITS {
  SYNC = 0,
  CLOSE = 1,
  RESET = 2,
  SIGNATURE_INCLUDED = 3,
  SIGNATURE_REQUESTED = 4,
  FROM_INCLUDED = 5,
  DELAY_REQUESTED = 6,
  MAX_PACKET_SIZE_INCLUDED = 7,
  PROFILE_INTERACTIVE = 8,
  ECHO = 9,
  NO_ACK = 10,
  OFFLINE_SIGNATURE = 11,
  // unused 12-15
}

type PacketArgs = {
  sendStreamId: number | undefined;
  receiveStreamId: number;
  sequenceNum: number;
  ackThrough: number;
  nacks: number[];
  resendDelay: number;
  payload: Buffer;
  localDestination: LocalDestination;
  sync: Boolean;
  close: Boolean;
  reset: Boolean;
  echo: Boolean;
  /**
   * max length of the payload,
   * send only with sync... bytes?
   * */
  maxPacketSize?: number;
  /**
   * Request the remote delay ack by this many milliseconds.
   * */
  delayRequested?: number;
};
export const createPacketBuffer = (args: PacketArgs) => {
  const needsSignature = args.sync || args.close || args.reset || args.echo;
  const needsFrom = args.sync || args.echo || args.reset;
  const includeMaxPacketSize = args.maxPacketSize && args.sync;
  let flagsInteger = 0;

  if (args.sync) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.SYNC);
    flagsInteger = setBit(flagsInteger, FLAG_BITS.NO_ACK);
  }
  if (args.close) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.CLOSE);
  }
  if (args.reset) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.RESET);
  }
  if (needsSignature) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.SIGNATURE_INCLUDED);
  }
  if (needsFrom) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.FROM_INCLUDED);
  }
  if (typeof args.delayRequested === "number") {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.DELAY_REQUESTED);
  }
  if (includeMaxPacketSize) {
    flagsInteger = setBit(flagsInteger, FLAG_BITS.MAX_PACKET_SIZE_INCLUDED);
  }
  const zeroBuffer = Buffer.alloc(0);
  const optionsDataBuffer = Buffer.concat([
    typeof args.delayRequested === "number"
      ? twoByteInteger(args.delayRequested)
      : zeroBuffer,
    needsFrom ? args.localDestination.buffer : zeroBuffer,
    includeMaxPacketSize && args.maxPacketSize
      ? twoByteInteger(args.maxPacketSize)
      : zeroBuffer,
    // offline signature would go here if supported
    needsSignature
      ? Buffer.alloc(args.localDestination.signatureByteLength)
      : zeroBuffer,
  ]);
  const buffer = Buffer.concat([
    fourByteInteger(args.sendStreamId || 0), //4
    fourByteInteger(args.receiveStreamId), // 8
    fourByteInteger(args.sequenceNum), // 12
    fourByteInteger(args.ackThrough), // 16
    oneByteInteger(args.nacks.length), //17
    ...args.nacks.map((nack) => fourByteInteger(nack)), // 17
    oneByteInteger(RESEND_DELAY_SECONDS), // 18
    twoByteInteger(flagsInteger), // 20
    twoByteInteger(optionsDataBuffer.length), // 22
    optionsDataBuffer,
    args.payload,
  ]);
  if (needsSignature) {
    const signatureBuffer = args.localDestination.sign(buffer);
    const position =
      buffer.byteLength - args.payload.byteLength - signatureBuffer.byteLength;
    signatureBuffer.copy(buffer, position);
  }
  return buffer;
};

export class Packet {
  public sendStreamId: number;
  public receiveStreamId: number;
  public sequenceNum: number;
  public ackThrough: number;
  public nacks: number[];
  public resendDelay: number;

  // flags
  public sync: boolean;
  public close: boolean;
  public reset: boolean;
  public echo: boolean;
  public payload: Buffer;

  // needed for signing stuff
  public from?: Destination | undefined;
  private signature?: Buffer;
  private signaturePosition?: number;

  public maxPacketSize: number | undefined;
  private buffer: Buffer;

  constructor(packetBuffer: Buffer) {
    this.buffer = packetBuffer;
    this.sendStreamId = packetBuffer.readUInt32BE(0);
    this.receiveStreamId = packetBuffer.readUInt32BE(4);
    this.sequenceNum = packetBuffer.readUInt32BE(8);
    this.ackThrough = packetBuffer.readUInt32BE(12);
    const nacksLength = packetBuffer.readUInt8(16);
    const nacksBuffer = packetBuffer.subarray(17, 17 + nacksLength * 4);
    this.nacks = [];
    for (let i = 0; i < nacksLength; i++) {
      this.nacks.push(nacksBuffer.readUInt32BE(i * 4));
    }
    this.resendDelay = packetBuffer.readUInt8(17 + nacksLength * 4);
    const flags = packetBuffer.readUInt16BE(18 + nacksLength * 4);
    const optionsLength = packetBuffer.readUInt16BE(20 + nacksLength * 4);
    const optionsPosition = 22 + nacksLength * 4;
    const optionsBuffer = packetBuffer.subarray(
      optionsPosition,
      optionsPosition + optionsLength,
    );
    this.payload = packetBuffer.subarray(
      22 + nacksLength * 4 + optionsLength,
      packetBuffer.length,
    );

    this.sync = !!getBit(flags, FLAG_BITS.SYNC);
    this.close = !!getBit(flags, FLAG_BITS.CLOSE);
    this.reset = !!getBit(flags, FLAG_BITS.RESET);
    const signatureIncluded = !!getBit(flags, FLAG_BITS.SIGNATURE_INCLUDED);
    this.echo = !!getBit(flags, FLAG_BITS.ECHO);

    const fromIncluded = !!getBit(flags, FLAG_BITS.FROM_INCLUDED);
    const delayRequested = !!getBit(flags, FLAG_BITS.DELAY_REQUESTED);
    const offlineSignatureIncluded = !!getBit(
      flags,
      FLAG_BITS.OFFLINE_SIGNATURE,
    );
    const includeMaxPacketSize = !!getBit(
      flags,
      FLAG_BITS.MAX_PACKET_SIZE_INCLUDED,
    );
    // options are in this order
    // 1. delay in ms
    // 2. from destination
    // 3. max packet size
    // 4. offline signature
    // 5. signature

    let offset = 0;
    if (delayRequested) offset += 2;
    let fromDestination: Destination | undefined;
    if (fromIncluded) {
      fromDestination = new Destination(optionsBuffer.subarray(offset));
      this.from = fromDestination;
      offset += fromDestination.buffer.length;
    }
    if (includeMaxPacketSize) {
      this.maxPacketSize = optionsBuffer.readUInt16BE(offset);
      offset += 2;
    }
    if (offlineSignatureIncluded) throw new Error("not supported");
    if (signatureIncluded) {
      this.signature = optionsBuffer.subarray(offset);
      this.signaturePosition =
        optionsPosition + optionsLength - this.signature.length;
      offset += this.signature.length;
    }
  }

  verify(fromDestination: Destination, myDestination?: Destination) {
    const needsSignature = this.sync || this.close || this.reset || this.echo;
    if (!needsSignature) return true;
    if (!this.signature) return false;
    if (!this.signaturePosition) return false;
    const tempBuffer = Buffer.alloc(this.buffer.byteLength);
    this.buffer.copy(tempBuffer);
    tempBuffer.fill(
      0,
      this.signaturePosition,
      this.signaturePosition + this.signature.length,
    );
    if (this.nacks.length === 8 && this.sync) {
      if (!myDestination) {
        throw new Error("myDestination is required");
      }
      const myHashBuffer = myDestination?.hashBuffer;
      const match = myHashBuffer.equals(this.buffer.subarray(17, 17 + 32));
      if (!match) {
        return false;
      }
    }
    return fromDestination.verify(tempBuffer, this.signature);
  }
}

const sortNumbersAscending = (a: number, b: number) => {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
};

export class I2CPSocket extends Duplex {
  // #region Class Variables
  private session: I2CPSession;

  /**
   * 4 byte Integer
   *
   * Random number selected by the packet originator before
   * sending the first SYN packet and constant for the life of
   * the connection, greater than zero.
   * May be 0 if unknown, for example in a RESET packet.
   */
  public streamId: number = Math.floor(Math.random() * 4_000_000_000) + 1;
  /**
   * Remote stream ID starts at 0, and is set to the stream ID of the incoming SYNC packet.
   */
  public remoteStreamId: number = 0;
  /**
   * Whether or not WE initiated the connection.
   */
  private initiator: boolean = false;

  /**
   * The remote destination that we're communicating with.
   */
  private remoteDestination: Destination;

  /**
   * Our local destination.
   */
  private localDestination: LocalDestination;

  /**
   * Packets that we've received, indexed by their sequence number.
   * We keep these in memory, particularly if they come out of order
   * and clear them as we flush the stream.
   */
  private receivedPackets: Record<number, Packet> = {};

  /**
   * A record of the packets that we've sent, indexed by their sequence number.
   * This is used to keep track of which packets have been acknowledged.
   * When we receive a packet, we check it's ACK through and remove entries from this list.
   * [The sent packet, when the packet was originally sent, and the callback]
   */
  private sentPackets: Record<
    number,
    [Packet, number, (error?: Error) => void]
  > = {};

  private ourSequenceNum: number = 0;

  private ackThrough: number = -1;

  private closeSent: boolean = false;
  private destroyCalled: boolean = false;

  public remoteAddress: string;
  // this shouldn't be used, but it's maaaaybe needed for bittorrent protocol
  public remotePort: number = 6881;

  private closing: undefined | ((error?: Error) => void) = undefined;
  public remoteRequestedClose: boolean = false;
  public connected: boolean = false;

  private missingPackets = new Set<number>();

  // #endregion
  constructor(
    session: I2CPSession,
    remoteDestination: Destination,
    localDestination: LocalDestination,
    initiator: boolean = false,
  ) {
    super({ objectMode: false });
    this.session = session;
    this.remoteDestination = remoteDestination;
    this.localDestination = localDestination;
    this.remoteAddress = `${remoteDestination.b32}.b32.i2p`;
    this.initiator = initiator;
  }

  /**
   * We're trying to drain the stream, so read packets that are in the buffer.
   * @param _size
   */
  public _read(_size: number) {
    Object.keys(this.receivedPackets)
      .map((a) => parseInt(a, 10))
      .sort(sortNumbersAscending)
      .forEach((int) => {
        if (int === this.ackThrough + 1) this.ackThrough++; // increment
        if (int <= this.ackThrough) {
          const packet = this.receivedPackets[int];
          this.flushPacket(packet);
        }
      });
  }

  // Implement the _write method to handle outgoing data
  public _write(
    chunk: Buffer,
    encoding: string,
    callback: (error?: Error) => void,
  ) {
    if (this.closeSent) {
      console.log("already sent close packet");
      return;
    }
    // set to the current sequence number, then increment
    const [sequenceNum, send] = this.createAckable(callback);
    const isSync = this.initiator && sequenceNum === 0;
    let nacks: number[] = [];
    if (isSync) {
      // replay prevention
      const hashBuffer = this.remoteDestination.hashBuffer;
      nacks = [
        hashBuffer.readUInt32BE(0),
        hashBuffer.readUInt32BE(4),
        hashBuffer.readUInt32BE(8),
        hashBuffer.readUInt32BE(12),
        hashBuffer.readUInt32BE(16),
        hashBuffer.readUInt32BE(20),
        hashBuffer.readUInt32BE(24),
        hashBuffer.readUInt32BE(28),
      ];
    }
    const packetBuffer = createPacketBuffer({
      sendStreamId: this.remoteStreamId,
      receiveStreamId: this.streamId,
      sequenceNum,
      ackThrough: Math.max(this.ackThrough, 0),
      nacks,
      maxPacketSize: 50_000,
      resendDelay: 0,
      delayRequested: 0,
      payload: chunk,
      sync: isSync,
      close: !!this.closing,
      reset: false,
      echo: false,
      localDestination: this.localDestination,
    });
    send(packetBuffer);
  }

  /**
   * Called when the local stream has written all the data, callback is passed
   * and should be called when the final data has been flushed.
   * @param callback
   */
  _final(callback: (error?: Error | null) => void): void {
    console.log("final called", this.streamId);
    this.closing = callback;
  }

  /**
   * Handle an incoming packet from the connected remote peer.
   * @param packet
   * @returns
   */
  handlePacket(packet: Packet) {
    if (this.closeSent) {
      // TODO - we shouldn't hit this, but we do.
      return;
    }
    if (!this.connected && !(packet.close || packet.reset)) {
      this.connected = true;
      this.emit("connect"); // TODO - this should be emitted when we receive the first packet
    }
    if (!packet.verify(this.remoteDestination, this.localDestination)) {
      console.error("Packet not verified, dropping...");
      return;
    }
    if (
      packet.sendStreamId !== this.streamId &&
      packet.sendStreamId &&
      packet.receiveStreamId !== this.streamId
    ) {
      throw new Error("Invalid packet for this stream");
    }

    if (packet.sync) {
      this.remoteStreamId = packet.receiveStreamId;
    }
    const isAckable = packet.sync || packet.sequenceNum !== 0;
    // ensure that our next packet acks this packet IF it's the next in line
    if (isAckable) {
      this.missingPackets.delete(packet.sequenceNum);
      if (packet.sequenceNum === this.ackThrough + 1) {
        this.ackThrough = packet.sequenceNum;
        this.flushPacket(packet);

        let nextSeq = this.ackThrough + 1;
        while (this.receivedPackets[nextSeq]) {
          this.ackThrough = nextSeq;
          this.flushPacket(this.receivedPackets[nextSeq]);
          nextSeq++;
        }
      } else if (packet.sequenceNum > this.ackThrough) {
        // if it's not the next packet, we need to store it for later
        this.receivedPackets[packet.sequenceNum] = packet;
        for (let i = this.ackThrough + 1; i < packet.sequenceNum; i++) {
          if (!this.receivedPackets[i]) {
            this.missingPackets.add(i);
          }
        }
      }
      this.ackPacket(packet);
    }
    // remove references to packets that have been acked by the remote peer
    Object.keys(this.sentPackets).forEach((key) => {
      const int = parseInt(key, 10);
      if (int <= packet.ackThrough && !packet.nacks.includes(int)) {
        const [_packet, _sentTime, callback] = this.sentPackets[int];
        delete this.sentPackets[int];
        if (callback) {
          callback();
        }
      }
    });
    if (Object.keys(this.sentPackets).length === 0 && this.closing) {
      this.closing(); // we've flushed all the written data, and they've acked everything
    }
  }

  _destroy(
    error: Error | null,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.destroyCalled) {
    } else {
      this.destroyCalled = true;
    }
    this.sendClose();
    callback(error);
  }

  /**
   * Flushes the packet to the stream, and removes it from the received packets buffer.
   */
  private flushPacket(packet: Packet) {
    delete this.receivedPackets[packet.sequenceNum];
    this.push(packet.payload);
  }

  /**
   * Sends an ACK packet to the remote peer, acknowledging the packet.
   * If the packet is a close packet, we destroy the stream on our end.
   */
  private ackPacket(packet: Packet) {
    const ackThrough = Math.max(this.ackThrough, packet.sequenceNum);
    const nacks =
      ackThrough !== this.ackThrough
        ? Array.from(this.missingPackets).filter((packetNum) => {
            return (
              packetNum > this.ackThrough && packetNum < packet.sequenceNum
            );
          })
        : [];
    const ackPacketBuffer = createPacketBuffer({
      sendStreamId: this.remoteStreamId,
      receiveStreamId: this.streamId,
      sequenceNum: 0,
      ackThrough: ackThrough,
      nacks: nacks,
      maxPacketSize: 50_000,
      resendDelay: 0,
      delayRequested: 0,
      payload: Buffer.alloc(0),
      sync: packet.sequenceNum === 0,
      close: packet.close,
      reset: false,
      echo: false,
      localDestination: this.localDestination,
    });
    if (packet.close && !this.destroyCalled) {
      this.remoteRequestedClose = true;
      this.destroy();
    }
    const ackPacket = new Packet(ackPacketBuffer);
    if (ackPacket.ackThrough < this.ackThrough) {
      console.log(
        "unexpected ack packet",
        ackPacket.ackThrough,
        this.ackThrough,
      );
    }
    this.session.sendStreamDatagram(
      this.remoteDestination.buffer,
      0,
      0,
      ackPacketBuffer,
    );
  }

  /**
   * Utility function to generate a sequence number and a function to send the packet.
   * Also handles resending the packet if it doesn't get acked.
   */
  private createAckable = (
    callback: (error?: Error) => void,
  ): [number, (buff: Buffer) => void] => {
    // assign THEN increment the sequence number
    let sequenceNum = this.ourSequenceNum++;
    if (sequenceNum === 0 && !this.initiator) {
      // if we are not the initiator, we can't send a sequence number of 0
      sequenceNum = this.ourSequenceNum++;
    }
    return [
      sequenceNum,
      (packetBuffer: Buffer) => {
        this.session.sendStreamDatagram(
          this.remoteDestination.buffer,
          0,
          0,
          packetBuffer,
        );
        this.sentPackets[sequenceNum] = [
          new Packet(packetBuffer),
          Date.now(),
          callback,
        ];
        const retryTime = RESEND_DELAY_SECONDS * 1000;
        const retryTimeMax = 300_000; // 5 minutes
        const timer = setInterval(() => {
          // retry sending the packet if we haven't received an ack
          if (this.sentPackets[sequenceNum] && !this.destroyed) {
            if (Date.now() - this.sentPackets[sequenceNum][1] > retryTimeMax) {
              console.log(
                `stream ${
                  this.streamId
                } - giving up on remote ${sequenceNum} after ${
                  Date.now() - this.sentPackets[sequenceNum][1]
                }ms`,
              );
              clearInterval(timer);
              this.destroy(new Error("Packet resend failed"));
            }
            this.session.sendStreamDatagram(
              this.remoteDestination.buffer,
              0,
              0,
              packetBuffer,
            );
          } else {
            clearInterval(timer);
          }
        }, retryTime);
      },
    ];
  };

  private sendClose(error?: Error | null) {
    if (this.closeSent) {
      // console.log("already sent close packet :/");
      return;
    }
    this.closeSent = true;
    const [sequenceNum, send] = this.createAckable((err) => {});
    const closePacketBuffer = createPacketBuffer({
      sendStreamId: this.remoteStreamId,
      receiveStreamId: this.streamId,
      sequenceNum,
      ackThrough: Math.max(this.ackThrough, 0),
      nacks: [],
      maxPacketSize: 50_000,
      resendDelay: 0,
      delayRequested: 0,
      payload: Buffer.alloc(0),
      sync: false,
      close: true,
      reset: false,
      echo: false,
      localDestination: this.localDestination,
    });
    send(closePacketBuffer);
  }
}
