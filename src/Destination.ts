import { randomBytes, createHash } from "crypto";
import { generatePrivateKeyPair, verify, sign } from "./crypto/dsa.js";

import {
  verify as verifyED25519,
  sign as signED25519,
  utils,
  getPublicKey,
} from "@noble/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import {
  b64stringToB32String,
  bufferDestinationToString,
  stringDestinationToBuffer,
} from "./utils/utils.js";
import { RedDSA } from "./crypto/RedDSA.js";
import {
  bigIntFromBuff,
  bigIntFromHex,
  bigIntToBuffer,
} from "./utils/conversion-utils.js";

export enum DESTINATION_CERT_TYPE {
  NULL = 0,
  HASHCASH = 1,
  HIDDEN = 2,
  SIGNED = 3,
  MULTIPLE = 4,
  KEY = 5,
}
export enum SIGNING_PUBLIC_KEY_TYPE {
  DSA_SHA1 = 0,
  ECDSA_SHA256_P256 = 1, //	64	0.9.12	Deprecated Older Destinations
  ECDSA_SHA384_P384 = 2, //	96	0.9.12	Deprecated Rarely if ever used for Destinations
  ECDSA_SHA512_P521 = 3, //	132	0.9.12	Deprecated Rarely if ever used for Destinations
  RSA_SHA256_2048 = 4, //	256	0.9.12	Deprecated Offline only; never used in Key Certificates for Router Identities or Destinations
  RSA_SHA384_3072 = 5, //	384	0.9.12	Deprecated Offline only; never used in Key Certificates for Router Identities or Destinations
  RSA_SHA512_4096 = 6, //	512	0.9.12	Offline only; never used in Key Certificates for Router Identities or Destinations
  EdDSA_SHA512_Ed25519 = 7, //	32	0.9.15	Recent Router Identities and Destinations
  EdDSA_SHA512_Ed25519ph = 8, //	32	0.9.25	Offline only; never used in Key Certificates for Router Identities or Destinations
  // reserved (GOST)	9	64	 	Reserved, see proposal 134
  // reserved (GOST)	10	128	 	Reserved, see proposal 134
  RedDSA_SHA512_Ed25519 = 11, //	32	0.9.39	For Destinations and encrypted leasesets only; never used for Router Identities
  // reserved	65280-65534	 	 	Reserved for experimental use
  // reserved	65535	 	 	Reserved for future expansion
}

type DESTINATION_SIGNING_KEYS =
  | SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1
  | SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256
  | SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384
  | SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521
  | SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519
  | SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519
  | SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256;

const SIGNING_PUBLIC_KEY_LENGTHS: Record<SIGNING_PUBLIC_KEY_TYPE, number> = {
  [SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1]: 128,
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256]: 64,
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384]: 96,
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521]: 132,
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA256_2048]: 256,
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA384_3072]: 384,
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA512_4096]: 512,
  [SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519]: 32,
  [SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519ph]: 32,
  [SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519]: 32,
};

const SIGNATURE_LENGTHS: Record<SIGNING_PUBLIC_KEY_TYPE, number> = {
  [SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1]: 40, //	 	Deprecated for Router Identities as of 09.58; discouraged for Destinations
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256]: 64, //	0.9.12	Deprecated Older Destinations
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384]: 96, //	0.9.12	Deprecated Rarely used for Destinations
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521]: 132, //	0.9.12	Deprecated Rarely used for Destinations
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA256_2048]: 256, //	0.9.12	Deprecated Offline signing, never used for Router Identities or Destinations
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA384_3072]: 384, //	0.9.12	Deprecated Offline signing, never used for Router Identities or Destinations
  [SIGNING_PUBLIC_KEY_TYPE.RSA_SHA512_4096]: 512, //	0.9.12	Offline signing, never used for Router Identities or Destinations
  [SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519]: 64, //	0.9.15	Recent Router Identities and Destinations
  [SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519ph]: 64, //	0.9.25	Offline signing, never used for Router Identities or Destinations
  [SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519]: 64, //	0.9.39	For Destinations and encrypted leasesets only, never used for Router Identities
};

enum CRYPTO_PUBLIC_KEY_TYPE {
  ElGamal = 0, //	256	Deprecated for Router Identities as of 0.9.58; use for Destinations, as the public key field is unused there
  P256 = 1, //	64	Reserved, see proposal 145
  P384 = 2, //	96	Reserved, see proposal 145
  P521 = 3, //	132	Reserved, see proposal 145
  X25519 = 4, //	32	See [ECIES] and proposal 156
  // reserved =	65280, //-65534	 	Reserved for experimental use
  // reserved =	65535, //	 	Reserved for future expansion
}

const CRYPTO_PUBLIC_KEY_LENGTHS: Record<CRYPTO_PUBLIC_KEY_TYPE, number> = {
  [CRYPTO_PUBLIC_KEY_TYPE.ElGamal]: 256,
  [CRYPTO_PUBLIC_KEY_TYPE.P256]: 64,
  [CRYPTO_PUBLIC_KEY_TYPE.P384]: 96,
  [CRYPTO_PUBLIC_KEY_TYPE.P521]: 132,
  [CRYPTO_PUBLIC_KEY_TYPE.X25519]: 32,
};

const PARTIAL_CRYPTO_MAX = 256;
const PARTIAL_SIGNIN_MAX = 128;
const PUB_PADD_SIGN_LEN = PARTIAL_CRYPTO_MAX + PARTIAL_SIGNIN_MAX;
const CERT_TYPE_LOC = 384;
const SIGN_TYPE_LOC = 387;
const CRYPT_TYPE_LOC = 389;
const SIGN_REMAI_LOC = 391;

/**
 * [publicKeyPortion][padding][signingKeyPortion][certType][certLength][signingType][cryptType][remainderSigningKey][remainderPublicKey]
 *                   |max-256                    |384      |385        |387         |389       |391
 */
export class Destination {
  public readonly byteLength: number;

  // store the destination as a string as these are deduplicated in memory
  // we want to keep the buffer versions in memory as little as possible
  private str: string;
  public readonly certType: DESTINATION_CERT_TYPE;
  public readonly cryptoPublicKey: string;
  public readonly publicSigningKey: string;
  public readonly signingPublicKeyType: DESTINATION_SIGNING_KEYS;
  public readonly cryptoPublicKeyType: CRYPTO_PUBLIC_KEY_TYPE;

  /**
   * Create a destination from a buffer.
   * The buffer must start with the destination, but can be longer.
   */
  constructor(dest: Buffer) {
    if (dest.byteLength < 387) {
      throw new Error("Too few bytes to be a destination");
    }
    this.certType = dest.readUint8(CERT_TYPE_LOC) as DESTINATION_CERT_TYPE;
    this.signingPublicKeyType =
      DESTINATION_CERT_TYPE.KEY === this.certType
        ? dest.readUInt16BE(SIGN_TYPE_LOC)
        : 0;
    this.cryptoPublicKeyType =
      DESTINATION_CERT_TYPE.KEY === this.certType
        ? dest.readUInt16BE(CRYPT_TYPE_LOC)
        : 0;
    const cryptoPublicKeyLength =
      CRYPTO_PUBLIC_KEY_LENGTHS[this.cryptoPublicKeyType];
    const signingPublicKeyLength =
      SIGNING_PUBLIC_KEY_LENGTHS[this.signingPublicKeyType];
    const signingRemainder = signingPublicKeyLength - PARTIAL_SIGNIN_MAX;
    const publicKeyRemainder = cryptoPublicKeyLength - PARTIAL_CRYPTO_MAX;
    const padding = Math.max(
      0,
      CERT_TYPE_LOC - cryptoPublicKeyLength - signingPublicKeyLength,
    );
    const publicSigningStartLoc =
      Math.min(cryptoPublicKeyLength, PARTIAL_CRYPTO_MAX) + padding;
    const publicSigningBuffer = Buffer.concat([
      dest.subarray(publicSigningStartLoc, CERT_TYPE_LOC),
      dest.subarray(SIGN_REMAI_LOC, SIGN_REMAI_LOC + signingRemainder),
    ]);
    if (publicSigningBuffer.byteLength !== signingPublicKeyLength) {
      console.log("part1", publicSigningStartLoc, CERT_TYPE_LOC);
      console.log("part2", SIGN_REMAI_LOC, SIGN_REMAI_LOC + signingRemainder);
      console.log("padding", padding);
      throw new Error();
    }
    this.publicSigningKey = publicSigningBuffer.toString("hex");
    this.cryptoPublicKey = Buffer.concat([
      dest.subarray(0, Math.max(PARTIAL_CRYPTO_MAX, cryptoPublicKeyLength)),
      dest.subarray(
        PUB_PADD_SIGN_LEN + signingRemainder,
        PUB_PADD_SIGN_LEN + signingRemainder + publicKeyRemainder,
      ),
    ]).toString("hex");
    this.byteLength =
      cryptoPublicKeyLength + padding + signingPublicKeyLength + 3;
    if (this.certType === DESTINATION_CERT_TYPE.KEY) {
      this.byteLength += 4;
    }
    this.str = bufferDestinationToString(dest.subarray(0, this.byteLength));
  }

  get string(): string {
    return this.str;
  }

  get buffer(): Buffer {
    return stringDestinationToBuffer(this.str);
  }

  /**
   * 32 byte hash of the destination
   */
  get hashBuffer(): Buffer {
    return createHash("sha256").update(this.buffer).digest();
  }

  get b32(): string {
    return b64stringToB32String(this.str);
  }

  public verify(data: Buffer, signature: Uint8Array) {
    if (
      this.certType === DESTINATION_CERT_TYPE.NULL ||
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1
    ) {
      return verify(bigIntFromHex(this.publicSigningKey), data, signature);
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519
    ) {
      /**
       * When a signature is composed of two elements (for example values R,S), it is serialized by padding each element to length/2 with leading zeros if necessary.
       */
      const verified = verifyED25519(signature, data, this.publicSigningKey);
      return verified;
    } else if (
      this.signingPublicKeyType ===
      SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519
    ) {
      const verified = RedDSA.verify(
        data,
        Buffer.from(signature),
        Buffer.from(this.publicSigningKey, "hex"),
      );
      return verified;
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256
    ) {
      const verified = p256.verify(
        signature,
        data,
        // see the notes in the public key generation function for why we add the 0x04 byte
        `04${this.publicSigningKey}`,
      );
      return verified;
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384
    ) {
      return p384.verify(signature, data, `04${this.publicSigningKey}`);
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521
    ) {
      return p521.verify(signature, data, `04${this.publicSigningKey}`);
    } else {
      console.log("sign type", this.signingPublicKeyType);
      throw new Error("Unsupported destination cert type");
    }
  }

  public verifyPayload(data: Buffer, signature: Uint8Array) {
    if (this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1) {
      return this.verify(createHash("sha256").update(data).digest(), signature);
    }
    return this.verify(data, signature);
  }

  get signatureByteLength() {
    return SIGNATURE_LENGTHS[this.signingPublicKeyType];
  }
}

export class LocalDestination extends Destination {
  private privateSigningKey: Uint8Array;
  constructor(dest: Buffer, privateSigningKey: Uint8Array) {
    super(dest);
    this.privateSigningKey = privateSigningKey;
  }

  sign(data: Buffer): Buffer {
    if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519
    ) {
      return Buffer.from(signED25519(data, this.privateSigningKey));
    } else if (this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1) {
      return Buffer.from(
        sign(bigIntFromBuff(Buffer.from(this.privateSigningKey)), data),
      );
    } else if (
      this.signingPublicKeyType ===
      SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519
    ) {
      return Buffer.from(
        RedDSA.sign(data, Buffer.from(this.privateSigningKey)),
      );
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256
    ) {
      const sig = p256.sign(data, this.privateSigningKey);
      return Buffer.from(sig.toCompactRawBytes());
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384
    ) {
      return Buffer.from(
        p384.sign(data, this.privateSigningKey).toCompactRawBytes(),
      );
    } else if (
      this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521
    ) {
      return Buffer.from(
        p521.sign(data, this.privateSigningKey).toCompactRawBytes(),
      );
    } else {
      throw new Error("Unsupported signing type");
    }
  }

  signPayload(data: Buffer): Buffer {
    if (this.signingPublicKeyType === SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1) {
      const sigBuff = this.sign(createHash("sha256").update(data).digest());
      return sigBuff;
    } else {
      return this.sign(data);
    }
  }
}

const keyPairMap: Record<
  DESTINATION_SIGNING_KEYS,
  () => {
    publicKey: Uint8Array<ArrayBufferLike>;
    privateKey: Uint8Array<ArrayBufferLike>;
  }
> = {
  [SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1]: () => {
    const { privateKey, publicKey } = generatePrivateKeyPair();
    return {
      privateKey: bigIntToBuffer(privateKey),
      publicKey: bigIntToBuffer(publicKey),
    };
  },
  [SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519]: () => {
    const privateKey = utils.randomPrivateKey();
    const publicKey = getPublicKey(privateKey);
    return { privateKey: privateKey, publicKey };
  },
  [SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519]: () => {
    const t = RedDSA.generateKeyPair();
    return {
      privateKey: t.privateKey,
      publicKey: t.publicKey,
    };
  },
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256]: () => {
    const privateKey = p256.utils.randomPrivateKey();
    const publicKey = p256.getPublicKey(privateKey, false);
    return {
      privateKey,
      // p256 public keys all start w/ the 0x04 byte
      // we don't include this in the destination bytes,
      // but instead add it back manually when utilizing the key
      publicKey: publicKey.slice(1),
    };
  },
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384]: () => {
    const privateKey = p384.utils.randomPrivateKey();
    const publicKey = p384.getPublicKey(privateKey, false);
    return {
      privateKey,
      publicKey: publicKey.slice(1),
    };
  },
  [SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521]: () => {
    const privateKey = p521.utils.randomPrivateKey();
    const publicKey = p521.getPublicKey(privateKey, false).slice(1);
    return {
      privateKey,
      publicKey,
    };
  },
};

export const generateLocalDestination = (
  signingType: DESTINATION_SIGNING_KEYS = SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1,
): {
  destination: LocalDestination;
  privateSigningKey: Uint8Array;
  publicSigningKey: Uint8Array;
} => {
  const { privateKey: privateSigningKey, publicKey: publicSigningKey } =
    keyPairMap[signingType]();
  if (publicSigningKey.byteLength !== SIGNING_PUBLIC_KEY_LENGTHS[signingType]) {
    console.log(Buffer.from(publicSigningKey));
    console.log(
      "Invalid public signing key length",
      publicSigningKey.byteLength,
      SIGNING_PUBLIC_KEY_LENGTHS[signingType],
    );
    throw new Error();
  }
  // hardcode the crypto public key to be 256 bytes,
  // this is no longer used for destinations
  const cryptoPublicKey = randomBytes(256);
  const cryptoPartialLength = Math.min(
    PARTIAL_CRYPTO_MAX,
    cryptoPublicKey.byteLength,
  );
  const signingPartialLength = Math.min(
    PARTIAL_SIGNIN_MAX,
    publicSigningKey.byteLength,
  );
  const cryptoRemainder = cryptoPublicKey.subarray(PARTIAL_CRYPTO_MAX);
  const signingRemainder = publicSigningKey.subarray(PARTIAL_SIGNIN_MAX);
  const padding = CERT_TYPE_LOC - cryptoPartialLength - signingPartialLength;
  const certTypeBuffer = Buffer.alloc(1);
  const certType =
    SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1 === signingType
      ? DESTINATION_CERT_TYPE.NULL
      : DESTINATION_CERT_TYPE.KEY;
  /**
   * From docs:
   * https://geti2p.net/spec/common-structures#certificate
   *
   * A KEY certificate with types 0,0 (ElGamal,DSA_SHA1) is allowed but
   * discouraged. It is not well-tested and may cause issues in some
   * implementations. Use a NULL certificate in the canonical representation of
   * a (ElGamal,DSA_SHA1) Destination or RouterIdentity, which will be 4 bytes
   * shorter than using a KEY certificate.
   *
   * ^ we don't support public/private keys yet, so ELGamal,DSA_SHA1 is
   * true when the signing type is DSA_SHA1
   */
  const isKey = certType === DESTINATION_CERT_TYPE.KEY;
  certTypeBuffer.writeUInt8(certType);
  const certLengthBuffer = Buffer.alloc(2);
  const certInfoBuffer = Buffer.alloc(isKey ? 4 : 0);
  if (isKey) {
    certLengthBuffer.writeUInt16BE(
      cryptoRemainder.byteLength + signingRemainder.byteLength + 4,
    );
  } else {
    certLengthBuffer.writeUInt16BE(0);
  }
  if (isKey) {
    certInfoBuffer.writeUInt16BE(signingType, 0);
    certInfoBuffer.writeUInt16BE(CRYPTO_PUBLIC_KEY_TYPE.ElGamal, 2);
  }
  const buffers = [
    cryptoPublicKey.subarray(0, PARTIAL_CRYPTO_MAX),
    Buffer.alloc(padding),
    publicSigningKey.subarray(0, PARTIAL_SIGNIN_MAX),
    certTypeBuffer,
    certLengthBuffer,
    certInfoBuffer,
    signingRemainder,
    cryptoRemainder,
  ];
  const destBuffer = Buffer.concat(buffers);
  console.log(
    "private signing key",
    Buffer.from(privateSigningKey).toString("hex"),
    signingType,
    Buffer.from(privateSigningKey).toString("hex").length,
  );
  return {
    destination: new LocalDestination(destBuffer, privateSigningKey),
    privateSigningKey,
    publicSigningKey,
  };
};
