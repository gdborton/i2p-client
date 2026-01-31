import { createHash } from "node:crypto";
import { base32 } from "rfc4648";

export const bufferDestinationToString = (buffer: Buffer) => {
  const base64String = buffer
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "~");
  // .replaceAll("=", "");
  return base64String;
};

export const stringDestinationToBuffer = (string: string): Buffer => {
  const base64String = string.replaceAll("-", "+").replaceAll("~", "/");
  return Buffer.from(base64String, "base64");
};

export const destinationBufferToB32String = (
  destinationBuffer: Buffer,
): string => {
  return base32
    .stringify(createHash("sha256").update(destinationBuffer).digest(), {
      pad: false,
    })
    .toLowerCase();
};

/**
 *
 * @param base64Destination
 * @returns b32 string like "3g2s4h5j6k7l8m9n"
 */
// pulled from https://github.com/diva-exchange/i2p-sam/blob/develop/src/i2p-sam.ts
export const b64stringToB32String = (base64Destination: string): string => {
  return destinationBufferToB32String(
    stringDestinationToBuffer(base64Destination),
  );
};
