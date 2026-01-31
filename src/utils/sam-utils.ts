export enum SamReplies {
  REPLY_HELLO = "HELLO REPLY",
  REPLY_STREAM = "STREAM STATUS",
  REPLY_DESTINATION = "DEST REPLY",
  REPLY_SESSION = "SESSION STATUS",
  REPLY_NAMING = "NAMING REPLY",
  REPLY_QUIT = "QUIT STATUS",
  PING = "PING",
}

interface Args {
  [SamReplies.REPLY_HELLO]: {
    type: SamReplies.REPLY_HELLO;
    args:
      | {
          RESULT: "OK";
        }
      | {
          RESULT: "I2P_ERROR" | "NOVERSION";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_STREAM]: {
    type: SamReplies.REPLY_STREAM;
    args:
      | {
          RESULT: "OK";
        }
      | {
          RESULT:
            | "CANT_REACH_PEER"
            | "I2P_ERROR"
            | "INVALID_KEY"
            | "INVALID_ID"
            | "TIMEOUT";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_DESTINATION]: {
    type: SamReplies.REPLY_DESTINATION;
    args: {
      PUB: string;
      PRIV: string;
    };
  };
  [SamReplies.REPLY_SESSION]: {
    type: SamReplies.REPLY_SESSION;
    args:
      | {
          RESULT: "OK";
          ID: string;
          MESSAGE: string;
        }
      | {
          RESULT: "DUPLICATED_ID" | "INVALID_KEY" | "DUPLICATED_DEST";
        }
      | {
          RESULT: "I2P_ERROR";
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_NAMING]: {
    type: SamReplies.REPLY_NAMING;
    args:
      | {
          RESULT: "OK";
          NAME: string;
          VALUE: string;
        }
      | {
          RESULT: "INVALID_KEY" | "KEY_NOT_FOUND";
          NAME: string;
          MESSAGE: string;
        };
  };
  [SamReplies.REPLY_QUIT]: {
    type: SamReplies.REPLY_QUIT;
    args: {
      RESULT: "OK";
      MESSAGE: string;
    };
  };
  [SamReplies.PING]: {
    type: SamReplies.PING;
    args: {
      REMAINDER: string;
    };
  };
}

export const parseMessage = <T extends SamReplies>(msg: string): Args[T] => {
  if (msg.startsWith("PING")) {
    const remainder = msg.substring(4).trim();
    return {
      type: SamReplies.PING,
      args: {
        REMAINDER: remainder,
      },
    } as Args[T] satisfies {
      type: SamReplies;
      args: Record<string, string>;
    };
  }
  // Split on the second space character
  const firstSpaceIndex = msg.indexOf(" ");
  const secondSpaceIndex = msg.indexOf(" ", firstSpaceIndex + 1);
  const type = msg.substring(0, secondSpaceIndex);

  // Keep the original format of arguments as an array of key=value strings
  const remainingStr = msg.substring(secondSpaceIndex + 1);
  const pargs = parseArgString(remainingStr);

  const argsObj: Record<string, string> = {};
  for (const arg of pargs) {
    // split only on the first '=' so values that contain '=' (e.g. base64 padding)
    // are preserved intact
    const eqIndex = arg.indexOf("=");
    if (eqIndex === -1) continue;
    const key = arg.substring(0, eqIndex);
    const value = arg.substring(eqIndex + 1);
    if (key) {
      try {
        argsObj[key] = value.startsWith('"') ? JSON.parse(value) : value;
      } catch (e) {
        console.error(`Error parsing value '${value}'`, e);
        throw new Error("Error parsing value");
      }
    }
  }
  return {
    type: type,
    args: argsObj,
  } as Args[T] satisfies {
    type: SamReplies;
    args: Record<string, string>;
  };
};

const parseArgString = (argString: string): string[] => {
  // This function parses the argument string into an array of key=value strings
  // handling quoted values properly (e.g., MESSAGE="Unknown STYLE")
  const args: string[] = [];
  let currentArg = "";
  let inQuotes = false;

  for (let i = 0; i < argString.length; i++) {
    const char = argString[i];

    if (char === '"') {
      inQuotes = !inQuotes; // Toggle the inQuotes flag
      currentArg += char;
    } else if (char === " " && !inQuotes) {
      // Only treat space as a separator when not inside quotes
      if (currentArg) {
        args.push(currentArg);
        currentArg = "";
      }
    } else {
      currentArg += char;
    }
  }

  // Push the last argument if there's any
  if (currentArg) {
    args.push(currentArg);
  }

  return args;
};
