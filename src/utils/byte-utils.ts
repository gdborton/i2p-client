export const fourByteInteger = (value: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
};

export const oneByteInteger = (value: number): Buffer => {
  const buffer = Buffer.alloc(1);
  buffer.writeUInt8(value, 0);
  return buffer;
};

export const twoByteInteger = (value: number): Buffer => {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
};
/**
 * Sets a bit at the given position in a number to 1.
 */
export const setBit = (number: number, bitPosition: number): number => {
  return number | (1 << bitPosition);
};

export const getBit = (number: number, bitPosition: number): number => {
  return (number & (1 << bitPosition)) === 0 ? 0 : 1;
};
