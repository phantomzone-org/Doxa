The backend has a stateful database with following tables:

- Account table:
  - stored fields of Account instance (check tessera-client `StandardAccount` struct for respective fields).
  - More details on how to store individual fields:
    - private_identifier: 2 u64 elements
    - subpool_id: u64 constant SUBPOOL_ID
    - balance: as byte array
    - nonce: u64
    - spend_auth: byte array of length 40 (convert [F; 5] -> [u8;40])
    - consume_auth: 
      - if consume_auth.config == true:
        - then set as byte array of length 40 (convert consume_auth.pk from [F;5] -> [u8; 40])
      - otherwise, set is all 0s
    - ast: map of asset id to (u64, u256)

- User table:
  - stores user related information:
    - name
    - physical_address
    - DOB
    - private_acc_address: private account address (hex representation of struct AccountAddress in tessera-client)

- FreshAcc tx requests
  - stores FreshAcc tx requests from users
  - FreshAcc tx requests consists of following fields:
    - private_acc_address
    - spend_auth public key of the account (i.e. spend_auth field of Account struct)
    - approval signature: initial set to empty value
    - rejection note: initial set to empty value
    - status {PENDING, APPROVED, REJECTED}
    
The API service exposes following routes:

- register
  - posts a fresh acc tx request. Contains following information:
    - private_identifier (private_identifier field of `StandardAccount`)
    - spend_auth public key of the account
    - eth_address (ethereum address)
    - user related information
  - the API request validates the information
    - derives the private_acc_address = `AccountAddress {subpool_id: SUBPOOL_ID, public_identifier: StandardAccount::new_with(private_identifier, SUBPOOL_ID)}.address().to_hex()`, SUBPOOL_ID is a fixed constant.
    - checks no entry for private_acc_address exists in User table and in FreshAcc tx request table. If enty exists in either, return with failure.
  - then:
    - adds user related information with private_acc_address in user table
    - adds an entry for fresh acc tx request with private_acc_address, spend_auth public key and status::PENDING.
    - adds an Account entry in the Account table:
      - sample default account `StandardAccount::new_with(private_identifier, SUBPOOL_ID)` and set spend_auth to the one received over the request.
      - add the resulting account as an entry to the account table
  -
