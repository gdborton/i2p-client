import { type LocalDestination } from "./Destination";

export const createDatagram1 = (
  from: LocalDestination,
  payload: Buffer
): Buffer => {
  const signature = from.signPayload(payload);
  return Buffer.concat([from.buffer, signature, payload]);
};
