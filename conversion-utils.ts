import bigInt from "big-integer";

export const bigIntFromHex = (hex: string): bigint => {
  // @ts-ignore
  return bigInt(hex.replace(/\s+/g, ""), 16).value as bigint;
};

export const bigIntToHex = (bigInt: bigint): string => {
  const str = bigInt.toString(16);
  return str.length % 2 === 0 ? str : `0${str}`;
};

export const bigIntToBuffer = (bigInt: bigint): Buffer => {
  return Buffer.from(bigIntToHex(bigInt), "hex");
};

export const bigIntFromBuff = (buff: Buffer): bigint => {
  return BigInt(`0x${buff.toString("hex")}`);
};
