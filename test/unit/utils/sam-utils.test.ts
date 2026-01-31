import { describe, it, expect } from "vitest";
import { parseMessage } from "../../../src/utils/sam-utils";

describe("sam-utils", () => {
  const validDestinationString =
    "FZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhBWV4oZn6TSdNqbcqE7JSD2jn1hcgXa-8Me4cwT8ZSGEFZXihmfpNJ02ptyoTslIPaOfWFyBdr7wx7hzBPxlIYQVleKGZ-k0nTam3KhOyUg9o59YXIF2vvDHuHME~GUhhI~Tgvro2isW1Os3c7fwHUqk7tU7i6yd5yZkCYaOIlKlBQAEAAcAAA==";
  const fakePrivKey = "XXXXXXXXXXXXXXXX";
  describe("parseMessage", () => {
    it("parsed DEST REPLY with valid DEST and PRIV fields", () => {
      expect(
        parseMessage(
          `DEST REPLY PUB=${validDestinationString} PRIV=${fakePrivKey}`,
        ),
      ).toEqual({
        args: {
          PRIV: fakePrivKey,
          PUB: validDestinationString,
        },
        type: "DEST REPLY",
      });
    });

    it('should parse HELLO REPLY with RESULT="OK"', () => {
      expect(parseMessage("HELLO REPLY RESULT=OK VERSION=3.1")).toEqual({
        args: {
          RESULT: "OK",
          VERSION: "3.1",
        },
        type: "HELLO REPLY",
      });
    });
  });
});
