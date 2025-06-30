mod request_input;
mod request_output;

use poem::{
    handler, listener::TcpListener, middleware::Cors, post, web::Json, EndpointExt, Route, Server, http::StatusCode, Result,
};
use request_input::*;
use request_output::*;
use serde_json;
use solana_program::{
    pubkey::Pubkey,
    system_instruction,
};
use solana_sdk::signer::{keypair::Keypair, Signer};
use spl_token::instruction as token_instruction;
use std::str::FromStr;

#[handler]
async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Json(ApiResponse::success(KeypairResponse { pubkey, secret }))
}   

#[handler]
async fn create_token(Json(payload): Json<CreateTokenRequest>) -> poem::Result<poem::Response> {
    match create_token_instruction(&payload) {
        Ok(instruction_response) => {
            let response = ApiResponse::success(instruction_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<InstructionResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn create_token_instruction(payload: &CreateTokenRequest) -> anyhow::Result<InstructionResponse> {
    let mint_pubkey = Pubkey::from_str(&payload.mint)?;
    let mint_authority_pubkey = Pubkey::from_str(&payload.mint_authority)?;

    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals,
    )?;

    let accounts: Vec<AccountMetaResponse> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &instruction.data),
    })
}

#[handler]
async fn mint_token(Json(payload): Json<MintTokenRequest>) -> poem::Result<poem::Response> {
    match mint_token_instruction(&payload) {
        Ok(instruction_response) => {
            let response = ApiResponse::success(instruction_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<InstructionResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn mint_token_instruction(payload: &MintTokenRequest) -> anyhow::Result<InstructionResponse> {
    let mint_pubkey = Pubkey::from_str(&payload.mint)?;
    let destination_pubkey = Pubkey::from_str(&payload.destination)?;
    let authority_pubkey = Pubkey::from_str(&payload.authority)?;

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        payload.amount,
    )?;

    let accounts: Vec<AccountMetaResponse> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &instruction.data),
    })
}

#[handler]
async fn sign_message(Json(payload): Json<SignMessageRequest>) -> poem::Result<poem::Response> {
    match sign_message_handler(&payload) {
        Ok(sign_response) => {
            let response = ApiResponse::success(sign_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<SignMessageResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn sign_message_handler(payload: &SignMessageRequest) -> anyhow::Result<SignMessageResponse> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(anyhow::anyhow!("Missing required fields"));
    }

    let secret_bytes = bs58::decode(&payload.secret).into_vec()?;
    let keypair = Keypair::from_bytes(&secret_bytes)?;
    
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    Ok(SignMessageResponse {
        signature: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
        message: payload.message.clone(),
    })
}

#[handler]
async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> poem::Result<poem::Response> {
    match verify_message_handler(&payload) {
        Ok(verify_response) => {
            let response = ApiResponse::success(verify_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<VerifyMessageResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn verify_message_handler(payload: &VerifyMessageRequest) -> anyhow::Result<VerifyMessageResponse> {
    let pubkey_bytes = bs58::decode(&payload.pubkey).into_vec()?;
    let signature_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &payload.signature)?;
    let message_bytes = payload.message.as_bytes();

    if pubkey_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid pubkey length"));
    }
    if signature_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid signature length"));
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);
    let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey_array)?;
    
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array)?;

    let valid = pubkey.verify_strict(message_bytes, &signature).is_ok();

    Ok(VerifyMessageResponse {
        valid,
        message: payload.message.clone(),
        pubkey: payload.pubkey.clone(),
    })
}

#[handler]
async fn send_sol(Json(payload): Json<SendSolRequest>) -> poem::Result<poem::Response> {
    match send_sol_instruction(&payload) {
        Ok(sol_response) => {
            let response = ApiResponse::success(sol_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<SolTransferResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn send_sol_instruction(payload: &SendSolRequest) -> anyhow::Result<SolTransferResponse> {
    if payload.lamports == 0 {
        return Err(anyhow::anyhow!("Invalid amount"));
    }

    let from_pubkey = Pubkey::from_str(&payload.from)?;
    let to_pubkey = Pubkey::from_str(&payload.to)?;

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    Ok(SolTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &instruction.data),
    })
}

#[handler]
async fn send_token(Json(payload): Json<SendTokenRequest>) -> poem::Result<poem::Response> {
    match send_token_instruction(&payload) {
        Ok(token_response) => {
            let response = ApiResponse::success(token_response);
            Ok(poem::Response::builder()
                .status(StatusCode::OK)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        },
        Err(e) => {
            let response = ApiResponse::<TokenTransferResponse>::error(e.to_string());
            Ok(poem::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(serde_json::to_string(&response).unwrap()))
        }
    }
}

fn send_token_instruction(payload: &SendTokenRequest) -> anyhow::Result<TokenTransferResponse> {
    let mint_pubkey = Pubkey::from_str(&payload.mint)?;
    let owner_pubkey = Pubkey::from_str(&payload.owner)?;
    let destination_pubkey = Pubkey::from_str(&payload.destination)?;

    let source_token_account = spl_associated_token_account::get_associated_token_address(
        &owner_pubkey,
        &mint_pubkey,
    );

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_token_account,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        payload.amount,
    )?;

    let accounts: Vec<TokenTransferAccount> = instruction
        .accounts
        .iter()
        .map(|acc| TokenTransferAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    Ok(TokenTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &instruction.data),
    })
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token))
        .with(Cors::new());

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
