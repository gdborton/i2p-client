import { describe, test, expect } from "vitest";
import { Destination } from "./Destination";
import { unpackPayload } from "./i2cp";
import { stringDestinationToBuffer } from "./utils";

describe("i2cp", () => {
  describe("unpack payload", () => {
    test("should unpack payload", async () => {
      const payload = Buffer.from(
        "000002401f8b08007fb0000d0211012902d6fd9d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e19d16e82a9a927fe5fc3fcad673834fea8c1e3b492b41328b3bf1c178ad26b0e144c9520df82e026b69bc4d76429447e7248178929cb11f46e49c561ffc17660605000400070000bdc1eaad370b316450c6e09aca0a018d2a182c8a97f75c54aa9248dd48c0a09f67408829903c1e20de7bd06c0dc795e83c58295f24443ae0047e570fa6899f0364313a6164323a696432303a931ba64e646726a6a5696287b163ec328c631780363a74617267657432303a0c11bf48524ebbccc720d7b1470b74d02923af6565313a71393a66696e645f6e6f6465313a74383adc9c8f673a9119c9313a79313a716523d0ea4529020000",
        "hex",
      );
      const { from } = await unpackPayload(payload);
      expect(from instanceof Destination).toBeTruthy();
      // expect(from?.byteLength).toBe(payload.byteLength);
    });
  });

  describe("pack payload", () => {
    test("stuff", () => {
      const d = new Destination(
        stringDestinationToBuffer(
          // "I5k3l5E9hKSoMgu3UHzZt8Y6DMckA4GAKounatYAaLwjmTeXkT2EpKgyC7dQfNm3xjoMxyQDgYAqi6dq1gBovCOZN5eRPYSkqDILt1B82bfGOgzHJAOBgCqLp2rWAGi8I5k3l5E9hKSoMgu3UHzZt8Y6DMckA4GAKounatYAaLwjmTeXkT2EpKgyC7dQfNm3xjoMxyQDgYAqi6dq1gBovCOZN5eRPYSkqDILt1B82bfGOgzHJAOBgCqLp2rWAGi8I5k3l5E9hKSoMgu3UHzZt8Y6DMckA4GAKounatYAaLwjmTeXkT2EpKgyC7dQfNm3xjoMxyQDgYAqi6dq1gBovCOZN5eRPYSkqDILt1B82bfGOgzHJAOBgCqLp2rWAGi8I5k3l5E9hKSoMgu3UHzZt8Y6DMckA4GAKounatYAaLwjmTeXkT2EpKgyC7dQfNm3xjoMxyQDgYAqi6dq1gBovGo5L82hzGJXSq3pLapfqzLpnhvF-KmKvdpuhtzVY0jfBQAEAAcAANIe4xJNJB-0Sio7KB43i9ZGVRK2I3pJmg2O7bDTMoIpqcoZH~ZvAHEvJuaMmJ72WRJhwo4jeFWJP1rVzpv~VySQy0tza~wkySNyA8Gu80Wjp2Wq2L2w~FTI4hw~iNMQCyOxaSx01G9JZUwB4epu392MXuJw1UinzMAPm7En54av~LPNY0QkFMtyvAXZBbZzeXZ~JrtxRUnrdz4zrEXF5w7jndrXuSRJf3lp0MOWaHneGLDZpRr1yr6Fh3RL7VXwYB7D3sKp2ugEUmu3d99YPe6OlwckLqzzEqnnvnG1VA23sv3kZRCsjSUFFZc3YXXqXgsMMMkWpMGp0z27zFGNehlPlz-eXTuwxhhjwaGc7lsWrnXUSlzDQvAi-IYtek1h-w==",
          "FZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhI~Tgvro2isW1Os3c7fwHUqk7tU7i6yd5yZkCYaOIlKlBQAEAAcAAA==",
        ),
      );
      console.log(d.certType, d.signingPublicKeyType, d.cryptoPublicKeyType);
    });
  });
});
