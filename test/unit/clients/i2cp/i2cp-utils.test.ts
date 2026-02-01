import { describe, test, expect } from "vitest";
import { Destination } from "../../../../src/protocol/Destination";
import { fourByteInteger } from "../../../../src/utils/byte-utils";
import { unpackMessagePayloadMessage } from "../../../../src/clients/i2cp/i2cp-utils";

describe("i2cp-utils", () => {
  describe("unpack payload", () => {
    test("should unpack payload", async () => {
      const payload = Buffer.from(
        "000002401f8b08007fb0000d0211012902d6fd9d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e144c9520df82e026b69bc4d76429447e7248178929cb11f46e49c561ffc17660605000400070000bdc1eaad370b316450c6e09aca0a018d2a182c8a97f75c54aa9248dd48c0a09f67408829903c1e20de7bd06c0dc795e83c58295f24443ae0047e570fa6899f0364313a6164323a696432303a931ba64e646726a6a5696287b163ec328c631780363a74617267657432303a0c11bf48524ebbccc720d7b1470b74d02923af6565313a71393a66696e645f6e6f6465313a74383adc9c8f673a9119c9313a79313a716523d0ea4529020000",
        "hex",
      );
      const { from } = await unpackMessagePayloadMessage(
        Buffer.concat([
          Buffer.from([0x00, 0x01]), // session ID
          fourByteInteger(payload.byteLength),
          payload,
        ]),
      );
      expect(from instanceof Destination).toBeTruthy();
    });
  });
});
