import { describe, test, expect } from "vitest";
import { bigIntFromBuff, bigIntToBuffer } from "./conversion-utils";

describe("conversion-utils", () => {
  test("bigint functions", () => {
    const hexString =
      "0456c53c39893ba04eb46c84f3d89482b65a01111878bd6d3f07a66b8706547f6daedd61d3cf933e8f790ad2dfbfce4d4eaa14b7414c29f0de65de6a24090a83db";
    const intRep = BigInt(`0x${hexString}`);
    const buffer = Buffer.from(hexString, "hex");
    expect(buffer.toString("hex")).toEqual(hexString);
    const bigInt = bigIntFromBuff(buffer);
    expect(bigInt).toEqual(intRep);
    expect(bigIntToBuffer(bigInt)).toEqual(buffer);
  });
});
