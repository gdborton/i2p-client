import { describe, it, expect } from "vitest";
import { createPacketBuffer, Packet } from "./I2CPSocket.js";
import { generateLocalDestination } from "./Destination.js";

describe("Packet", () => {
  it.skip("should verify correctly", () => {
    const packet = new Packet(
      Buffer.from(
        "00000000daf1174d0000000000000000085e25c5d82eafed80111f408b66f738a09d6a12b41c7d2b06f7bd1ff13770dfc10104e901cb0000f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf6528a91afe4dcac8c1aad3737053aad9f83a8fa435c7cd10b79e306e6cd10393c405000400070000071489c1414a7ee41fd4504c371bef4f89fdfbe9345b583f7570100f15dd5b0359ea89849ba9af4387206929570484c510bdc7437a295082187759917eb74dcf7b0c13426974546f7272656e742070726f746f636f6c80000000001000050fd4832bb40eccbb8c1d16d5c51a80fd2147b9412d4249333830302d5900c952dcf6eb9b5fa137af",
        "hex"
      )
    );
    expect(packet.verify(packet.from!)).toBeTruthy();
  });

  it("should not verify a modified packet", () => {
    const packet = new Packet(
      Buffer.from(
        "00000000daf1174d0000000000000000085e25c5d82eafed80111f408b66f738a09d6a12b41c7d2b06f7bd1ff13770dfc10104e901cb0000f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf65f843cac3abc688b2252cecd1f5e867932d04e0e14897ae9f433e1768cf0eaf6528a91afe4dcac8c1aad3737053aad9f83a8fa435c7cd10b79e306e6cd10393c405000400070000071489c1414a7ee41fd4504c371bef4f89fdfbe9345b583f7570100f15dd5b0359ea89849ba9af4387206929570484c510bdc7437a295082187759917eb74dcf7b0c13426974546f7272656e742070726f746f636f6c80000000001000050fd4832bb40eccbb8c1d16d5c51a80fd2147b9412d4249333830302d5900c952dcf6eb9b5fa137a1",
        "hex"
      )
    );
    expect(() => packet.verify(packet.from!)).toThrow();
  });

  it("should verify a locally constructed packet", () => {
    const { destination } = generateLocalDestination();
    const packetBuffer = createPacketBuffer({
      sendStreamId: 10,
      receiveStreamId: 10,
      sequenceNum: 0,
      ackThrough: 0,
      nacks: [],
      resendDelay: 0,
      payload: Buffer.from("hello world"),
      sync: false, // sync packet
      close: false,
      reset: false,
      echo: false,
      localDestination: destination,
    });
    const packet = new Packet(packetBuffer);
    expect(packet.verify(destination)).toBeTruthy();
  });
});
