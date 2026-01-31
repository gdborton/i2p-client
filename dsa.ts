import { DSA } from "micro-rsa-dsa-dh/dsa.js";
import bigInt from "big-integer";
import { sha1 } from "@noble/hashes/sha1";

// @ts-ignore
const prime = bigInt(
  "9C05B2AA 960D9B97 B8931963 C9CC9E8C 3026E9B8 ED92FAD0\
  A69CC886 D5BF8015 FCADAE31 A0AD18FA B3F01B00 A358DE23\
  7655C496 4AFAA2B3 37E96AD3 16B9FB1C C564B5AE C5B69A9F\
  F6C3E454 8707FEF8 503D91DD 8602E867 E6D35D22 35C1869C\
  E2479C3B 9D5401DE 04E0727F B33D6511 285D4CF2 9538D9E3\
  B6051F5B 22CC1C93".replace(/\s+/g, ""),
  16

  // @ts-ignore
).value as bigint;

// @ts-ignore
const quotient = bigInt(
  "A5DFC28F EF4CA1E2 86744CD8 EED9D29D 684046B7".replace(/\s+/g, ""),
  16

  // @ts-ignore
).value as bigint;

// @ts-ignore
const generator = bigInt(
  `
    0C1F4D27 D40093B4 29E962D7 223824E0 BBC47E7C 832A3923
    6FC683AF 84889581 075FF908 2ED32353 D4374D73 01CDA1D2
    3C431F46 98599DDA 02451824 FF369752 593647CC 3DDC197D
    E985E43D 136CDCFC 6BD5409C D2F45082 1142A5E6 F8EB1C3A
    B5D0484B 8129FCF1 7BCE4F7F 33321C3C B3DBB14A 905E7B2B
    3E93BE47 08CBCC82`.replace(/\s+/g, ""),
  16

  // @ts-ignore
).value as bigint;

const isValid = (privateKey: bigint, publicKey: bigint) => {
  if (Buffer.from(privateKey.toString(16), "hex").byteLength !== 20) {
    return false;
  }
  if (Buffer.from(publicKey.toString(16), "hex").byteLength !== 128) {
    return false;
  }
  return true;
};

const dsa = DSA({
  p: prime,
  q: quotient,
  g: generator,
  hash: sha1,
});
export const { sign, verify } = dsa;
export const generatePrivateKeyPair = () => {
  let privateKey = dsa.randomPrivateKey();
  let publicKey = dsa.getPublicKey(privateKey);
  // this shouldn't be needed, but I've seen this be 39 bytes before, and I don't know why
  while (!isValid(privateKey, publicKey)) {
    privateKey = dsa.randomPrivateKey();
    publicKey = dsa.getPublicKey(privateKey);
  }
  return {
    publicKey,
    privateKey,
  };
};
