import { promisify } from "node:util";
import { Destination } from "../../protocol/Destination";
import { gunzip as gunzipCallback } from "node:zlib";

const gunzip = promisify(gunzipCallback);

export enum I2P_PROTOCOL {
  STREAMING = 6,
  REPLIABLE_DATAGRAM = 17,
  RAW_DATAGRAM = 18,
}

export const SESSION_ID_BYTE_LENGTH = 2;
export const MESSAGE_ID_BYTE_LENGTH = 4;
export const MESSAGE_STATUS_BYTE_LENGTH = 1;
export const MESSAGE_SIZE_BYTE_LENGTH = 4;
export const NONCE_BYTE_LENGTH = 4;

export const unpackMessagePayloadMessage = async (
  data: Buffer,
): Promise<{
  payload: Buffer;
  sourcePort: number;
  destinationPort: number;
  from?: Destination;
  signature?: Buffer;
  protocol: I2P_PROTOCOL;
}> => {
  const payloadBuffer = data.subarray(
    SESSION_ID_BYTE_LENGTH + MESSAGE_ID_BYTE_LENGTH,
  );
  const payloadData = payloadBuffer.subarray(4);
  const sourcePort = payloadData.readUInt16BE(4);
  const destinationPort = payloadData.readUInt16BE(6);
  const protocol = payloadData.readUInt8(9);
  const originalPayload = await gunzip(payloadData);
  if (protocol === I2P_PROTOCOL.REPLIABLE_DATAGRAM) {
    const des = new Destination(originalPayload);
    const signature = originalPayload.subarray(
      des.byteLength,
      des.byteLength + des.signatureByteLength,
    );
    const payloadStart = des.byteLength + signature.byteLength;
    const payload = originalPayload.subarray(payloadStart);
    const verified = des.verifyPayload(payload, signature);
    if (!verified) {
      throw new Error("unable to verify payload!");
    }
    return {
      payload,
      sourcePort,
      destinationPort,
      protocol,
      from: des,
      signature,
    };
  }
  return {
    payload: originalPayload,
    sourcePort,
    destinationPort,
    protocol,
  };
};
