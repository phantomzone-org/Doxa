export {
  Account,
  AccountAddress,
  AccountCommitment,
  AccountNullifier,
  AssetId,
  DepositNote,
  DepositNoteCommitment,
  DummyNote,
  InputNote,
  OutputNote,
  SpendTx,
  SpendTxBuilder,
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
export type { RegisterRequest, RegisterResponse, AccountResponse, FreshAccStatus, FreshAccStatusResponse, ApiError, NotePayload, SpendTxRequest, SpendTxResponse, NotesBalanceResponse, SpendTxStatus, SpendTxStatusResponse } from "./api/index.js";
