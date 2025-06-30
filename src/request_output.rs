use serde::Serialize;

#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Success {
        success: bool,
        data: T,
    },
    Error {
        success: bool,
        error: String,
    },
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self::Success {
            success: true,
            data,
        }
    }

    pub fn error(message: String) -> Self {
        Self::Error {
            success: false,
            error: message,
        }
    }
}

#[derive(Serialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub program_id: String,
    pub accounts: AccountMetaResponse,
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct SolTransferResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct TokenTransferAccount {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

#[derive(Serialize)]
pub struct TokenTransferResponse {
    pub program_id: String,
    pub accounts: Vec<TokenTransferAccount>,
    pub instruction_data: String,
} 