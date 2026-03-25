export {
  Account,
  AccountAddress,
  AccountCommitment,
  AccountNullifier,
  SubpoolId,
  PrivateIdentifier,
  PublicIdentifier,
  SpendAuthPk,
  derivePrivateIdentifier,
  derivePublicIdentifier,
  deriveAccountFromPasskey,
} from "./account.js";
export type { HashBytes } from "./account.js";

export { SubpoolClient, SubpoolApiError } from "./api/index.js";
export type { RegisterRequest, RegisterResponse, AccountResponse, FreshAccStatus, FreshAccStatusResponse, ApiError } from "./api/index.js";
