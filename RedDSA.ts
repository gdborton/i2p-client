import { createHash, randomBytes } from "crypto";
import { etc, ExtendedPoint } from "@noble/ed25519";

//@ts-ignore
const sha512 = (...m) => {
  return createHash("sha512")
    .update(etc.concatBytes(...m))
    .digest();
};
// @ts-ignore
etc.sha512Sync = sha512;

const L = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989"
); // Ed25519 subgroup order
const B = ExtendedPoint.BASE; // Ed25519 base point
const cofactor = BigInt(8);

export function bytesToNumberLE(bytes: Uint8Array): bigint {
  let value = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    value += BigInt(bytes[i]) << (BigInt(8) * BigInt(i));
  }
  return value;
}

export function numberToBytesLE(num: bigint, byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  let n = num;
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = Number(n & BigInt(0xff));
    n >>= BigInt(8);
  }
  return bytes;
}

function hStar(prefix1: Uint8Array, prefix2: Uint8Array, msg: Buffer): bigint {
  const length1 = Buffer.from([msg.byteLength & 0xff]);
  const length2 = Buffer.from([(msg.byteLength >> 8) & 0xff]);
  const data = Buffer.concat([
    Buffer.from("I2P_Red25519H(x)"),
    prefix1,
    prefix2,
    length1,
    length2,
    msg,
  ]);
  const hash = sha512(data);
  return etc.mod(bytesToNumberLE(hash), L);
}

const computeScalar = (sk: Buffer): Buffer => {
  const sha = sha512(sk); // 64 bytes
  const s = Buffer.from(sha.slice(0, 32)); // Make a copy
  s[0] &= 248;
  s[31] &= 63;
  s[31] |= 64;
  return s;
};

export class RedDSA {
  static generateKeyPair(): {
    privateKey: Buffer;
    publicKey: Buffer;
  } {
    const privateKey = RedDSA.generatePrivateKey();
    return {
      privateKey,
      publicKey: RedDSA.derivePublicKey(privateKey),
    };
  }
  static generatePrivateKey(): Buffer {
    const privateKey = randomBytes(64);
    return Buffer.from(
      numberToBytesLE(
        etc.mod(bytesToNumberLE(computeScalar(privateKey)), L),
        32
      )
    );
  }
  static convertPrivateKey(key: Buffer): Buffer {
    return computeScalar(key);
  }

  static convertPublicKey(key: Buffer): Buffer {
    return key;
  }

  // DERIVE_PUBLIC(sk) := [sk] B
  static derivePublicKey(secretKey: Buffer): Buffer {
    const sk = bytesToNumberLE(secretKey);
    const vk = B.multiply(etc.mod(sk, L));
    return Buffer.from(vk.toRawBytes());
  }

  static sign(message: Buffer, secretKey: Buffer): Buffer {
    if (secretKey.length !== 32) {
      throw new Error("Secret key must be 32 bytes");
    }
    const sk = bytesToNumberLE(secretKey);

    const T = randomBytes(80);
    const vkBytes = this.derivePublicKey(secretKey);
    const r = hStar(T, vkBytes, message);

    const R = B.multiply(r);
    const Rbytes = R.toRawBytes();

    const c = hStar(Rbytes, vkBytes, message);

    const S = etc.mod(r + c * sk, L);
    return Buffer.concat([Rbytes, numberToBytesLE(S, 32)]);
  }

  static verify(message: Buffer, signature: Buffer, publicKey: Buffer) {
    if (signature.length !== 64) return false;
    if (publicKey.length !== 32) return false;

    const Rbytes = Buffer.copyBytesFrom(signature, 0, 32);
    const Sbytes = Buffer.copyBytesFrom(signature, 32, 64);

    let R: ExtendedPoint;
    try {
      R = ExtendedPoint.fromHex(Rbytes.toString("hex"));
    } catch (e) {
      return false;
    }

    const S = bytesToNumberLE(Sbytes);
    if (S >= L) return false;

    let vk: ExtendedPoint;
    try {
      vk = ExtendedPoint.fromHex(publicKey.toString("hex"));
    } catch (e) {
      return false;
    }

    const c = hStar(Rbytes, vk.toRawBytes(), message);

    // Calculate: (-[S]B + R + [c]vk)
    const SB = B.multiply(S).negate();
    const cVK = vk.multiply(c);
    const check = SB.add(R).add(cVK);

    // Multiply by cofactor and check identity
    const final = check.multiply(cofactor);
    return final.equals(ExtendedPoint.ZERO);
  }
}
