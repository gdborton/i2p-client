import { describe, test, expect } from "vitest";

import {
  generateLocalDestination,
  LocalDestination,
  SIGNING_PUBLIC_KEY_TYPE,
} from "./Destination";
import { randomBytes } from "crypto";
import { verify as verifyED25519, sign as signED25519 } from "@noble/ed25519";
import { RedDSA } from "./RedDSA";

describe("Destination", () => {
  test("DSA_SHA1 destinations", () => {
    const { destination } = generateLocalDestination(
      SIGNING_PUBLIC_KEY_TYPE.DSA_SHA1
    );
    expect(destination.byteLength).toBe(387);
    expect(destination instanceof LocalDestination).toBeTruthy();
    const data = randomBytes(32);
    const sig = destination.sign(data);
    expect(sig.byteLength).toBe(40);
    expect(destination.verify(data, sig)).toBeTruthy();
    expect(destination.hashBuffer.byteLength).toBe(32);
  });

  test("should support ed25519 destinations", () => {
    const { destination, privateSigningKey, publicSigningKey } =
      generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.EdDSA_SHA512_Ed25519);
    const data = randomBytes(32);
    expect(destination instanceof LocalDestination).toBeTruthy();
    expect(destination.byteLength).toBe(391);
    const sig = destination.sign(data);
    const sig2 = signED25519(data, privateSigningKey);
    expect(sig).toEqual(Buffer.from(sig2));
    expect(verifyED25519(sig2, data, publicSigningKey)).toBeTruthy();
    expect(sig.byteLength).toBe(64);
    expect(destination.verify(data, sig)).toBeTruthy();
  });

  test("should support RedDSA destinations", () => {
    const { destination, privateSigningKey, publicSigningKey } =
      generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.RedDSA_SHA512_Ed25519);

    const data = randomBytes(32);
    expect(destination instanceof LocalDestination).toBeTruthy();
    expect(destination.byteLength).toBe(391);

    const sig = destination.sign(data);
    const sig2 = RedDSA.sign(data, Buffer.from(privateSigningKey));

    expect(
      RedDSA.verify(data, sig2, Buffer.from(publicSigningKey))
    ).toBeTruthy();
    expect(sig.byteLength).toBe(64);
    expect(destination.verify(data, sig)).toBeTruthy();
  });

  test("should support ECDSA_SHA256_P256 destinations", () => {
    const { destination, privateSigningKey, publicSigningKey } =
      generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA256_P256);
    const data = randomBytes(32);
    expect(destination instanceof LocalDestination).toBeTruthy();
    expect(destination.byteLength).toBe(391);
    const sig = destination.sign(data);
    expect(sig.byteLength).toBe(64);
    expect(destination.verify(data, sig)).toBeTruthy();
  });

  test("should support ECDSA_SHA256_P384 destinations", () => {
    const { destination, privateSigningKey, publicSigningKey } =
      generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA384_P384);
    const data = randomBytes(32);
    expect(destination instanceof LocalDestination).toBeTruthy();
    expect(destination.byteLength).toBe(391);
    const sig = destination.sign(data);
    expect(sig.byteLength).toBe(96);
    expect(destination.verify(data, sig)).toBeTruthy();
  });

  test("should support ECDSA_SHA256_P521 destinations", () => {
    const { destination, privateSigningKey, publicSigningKey } =
      generateLocalDestination(SIGNING_PUBLIC_KEY_TYPE.ECDSA_SHA512_P521);
    const data = randomBytes(32);
    expect(destination instanceof LocalDestination).toBeTruthy();
    expect(destination.byteLength).toBe(395);
    const sig = destination.sign(data);
    expect(sig.byteLength).toBe(132);
    expect(destination.verify(data, sig)).toBeTruthy();
  });
});
