export {
  Account,
  AccountAddress,
  SubpoolId,
  PrivateIdentifier,
  PublicIdentifier,
  derivePublicIdentifier,
  deriveAccountFromPasskey,
} from "./account.js";
export type { HashBytes } from "./account.js";

export { SubpoolClient, SubpoolApiError } from "./api/index.js";
export type { RegisterRequest, RegisterResponse, ApiError } from "./api/index.js";
