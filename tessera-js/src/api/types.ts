/** Request body for POST /register */
export interface RegisterRequest {
  /** 32 hex chars — 16-byte PrivateIdentifier([F; 2]), 2 × u64 LE */
  privateIdentifier: string;
  /** 80 hex chars — 40-byte CompressedPublicKey, 5 × u64 LE */
  spendAuthPk: string;
  /** Ethereum address, e.g. "0x..." (42 chars) */
  ethAddress: string;
  name: string;
  physicalAddress: string;
  /** ISO date string "YYYY-MM-DD" */
  dob: string;
}

/** Response body for a successful POST /register (HTTP 201) */
export interface RegisterResponse {
  /** 80-hex-char AccountAddress */
  privateAccAddress: string;
}

/** Body returned by the server on any error response */
export interface ApiError {
  error: string;
}
