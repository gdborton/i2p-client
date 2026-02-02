import { PrimarySession } from "../clients/sam/sam";
import { HTTPParser } from "http-parser-js";

const chunkArr = <T>(arr: T[], chunkSize: number) => {
  const chunks = [];
  for (let i = 0; i < arr.length; i += chunkSize) {
    chunks.push(arr.slice(i, i + chunkSize));
  }
  return chunks;
};

export const createFetch = (opts: {
  session: PrimarySession;
}): typeof fetch => {
  const fetchStreamSession = opts.session.getOrCreateSubsession(
    "i2p-fetch",
    "STREAM",
  );
  const i2pFetch: typeof fetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    let parsed: URL;
    if (input instanceof Request) {
      parsed = new URL(input.url);
    } else {
      parsed = input instanceof URL ? input : new URL(input.toString());
    }
    const method =
      init?.method || (input instanceof Request ? input.method : "GET");
    const content =
      [
        `${method} ${parsed.pathname}${parsed.search} HTTP/1.1`,
        `Host: ${parsed.hostname}`,
      ].join("\r\n") + "\r\n\r\n";
    return new Promise(async (resolve, reject) => {
      try {
        const stream = await (
          await fetchStreamSession
        ).createStream({
          destination: parsed.hostname,
          toPort: parsed.port ? parseInt(parsed.port) : 80,
          fromPort: 0,
        });

        const parser = new HTTPParser(HTTPParser.RESPONSE);
        let shouldKeepAlive = false;
        let upgrade = false;
        let statusCode = 0;
        let statusMessage = "";
        let versionMajor = 0;
        let versionMinor = 0;
        let headers: [string, string][] = [];
        let bodyChunks: Buffer[] = [];
        let trailers = [];
        let complete = false;
        parser[HTTPParser.kOnHeadersComplete] = function (res) {
          shouldKeepAlive = res.shouldKeepAlive;
          upgrade = res.upgrade;
          statusCode = res.statusCode;
          statusMessage = res.statusMessage;
          versionMajor = res.versionMajor;
          versionMinor = res.versionMinor;
          headers = chunkArr(res.headers, 2) as [string, string][];
        };

        parser[HTTPParser.kOnBody] = function (chunk, offset, length) {
          bodyChunks.push(chunk.slice(offset, offset + length));
        };

        // This is actually the event for trailers, go figure.
        parser[HTTPParser.kOnHeaders] = function (t) {
          trailers = t;
        };

        parser[HTTPParser.kOnMessageComplete] = function () {
          complete = true;
          stream.destroy();
          parser.finish();
          resolve(
            new Response(Buffer.concat(bodyChunks), {
              status: statusCode,
              statusText: statusMessage,
              headers: new Headers(headers),
            }),
          );
        };

        // let's assume that the data is all sent in one shot for now
        /**
         *
         * @param {Buffer} data
         */
        stream.on("data", (data: Buffer) => parser.execute(data));
        stream.write(Buffer.from(content));
      } catch (error) {
        const e = error as Error;
        if (e.message && e.message.includes("CANT_REACH_PEER")) {
          resolve(
            new Response(null, {
              status: 404,
            }),
          );
        } else if (e.message && e.message.includes("Stream timeout")) {
          resolve(
            new Response(null, {
              status: 408,
            }),
          );
        } else {
          console.log("caught error", e);
          console.log("error message", e.message);
        }
      }
    });
  };
  return i2pFetch;
};
