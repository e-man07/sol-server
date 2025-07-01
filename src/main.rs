use actix_web::{web, App, HttpResponse, HttpServer, Result, middleware::Logger};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
    instruction::{AccountMeta, Instruction},
    message::Message,
};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier};
use bs58;
use base64;
use std::str::FromStr;
use anyhow::{Result as AnyhowResult, anyhow};


#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}


#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SimpleSolInstructionResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenInstructionResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}


fn validate_pubkey(pubkey_str: &str) -> AnyhowResult<Pubkey> {
    Pubkey::from_str(pubkey_str).map_err(|_| anyhow!("Invalid public key format"))
}

fn validate_keypair_from_secret(secret_str: &str) -> AnyhowResult<Keypair> {
    let secret_bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| anyhow!("Invalid secret key encoding"))?;
    
    if secret_bytes.len() != 64 {
        return Err(anyhow!("Invalid secret key length"));
    }
    
    Keypair::from_bytes(&secret_bytes)
        .map_err(|_| anyhow!("Invalid secret key format"))
}


async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {

    let mint_authority = match validate_pubkey(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid mint authority public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid mint public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };


    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        req.decimals,
    ).map_err(|e| {
        log::error!("Failed to create initialize mint instruction: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create instruction")
    })?;

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = base64::encode(&instruction.data);

    let response = ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    });

    Ok(HttpResponse::Ok().json(response))
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    
    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid mint public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let destination = match validate_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid destination public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let authority = match validate_pubkey(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid authority public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    
    let destination_ata = get_associated_token_address(&destination, &mint);

    
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination_ata,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| {
        log::error!("Failed to create mint-to instruction: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create instruction")
    })?;

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = base64::encode(&instruction.data);

    let response = ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    });

    Ok(HttpResponse::Ok().json(response))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    
    if req.message.is_empty() || req.secret.is_empty() {
        let response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    
    let keypair = match validate_keypair_from_secret(&req.secret) {
        Ok(kp) => kp,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid secret key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let signature_b64 = base64::encode(signature.as_ref());
    let public_key = bs58::encode(keypair.pubkey().to_bytes()).into_string();

    let response = ApiResponse::success(SignMessageResponse {
        signature: signature_b64,
        public_key,
        message: req.message.clone(),
    });

    Ok(HttpResponse::Ok().json(response))
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    
    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => {
            if bytes.len() != 32 {
                let response = ApiResponse::<()>::error("Invalid public key length".to_string());
                return Ok(HttpResponse::BadRequest().json(response));
            }
            bytes
        },
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid public key encoding".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let ed25519_pubkey = match Ed25519PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid signature encoding".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let ed25519_signature = match Ed25519Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid signature format".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let message_bytes = req.message.as_bytes();
    let is_valid = ed25519_pubkey.verify(message_bytes, &ed25519_signature).is_ok();

    let response = ApiResponse::success(VerifyMessageResponse {
        valid: is_valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    });

    Ok(HttpResponse::Ok().json(response))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    
    let from_pubkey = match validate_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid sender public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let to_pubkey = match validate_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid recipient public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };


    if req.lamports == 0 {
        let response = ApiResponse::<()>::error("Amount must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);
    let instruction_data = base64::encode(&instruction.data);

    let response = ApiResponse::success(SimpleSolInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: vec![
            from_pubkey.to_string(),
            to_pubkey.to_string(),
        ],
        instruction_data,
    });

    Ok(HttpResponse::Ok().json(response))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    
    let destination = match validate_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid destination public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid mint public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    let owner = match validate_pubkey(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid owner public key".to_string());
            return Ok(HttpResponse::BadRequest().json(response));
        }
    };

    
    if req.amount == 0 {
        let response = ApiResponse::<()>::error("Amount must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    
    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    
    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        req.amount,
    ).map_err(|e| {
        log::error!("Failed to create token transfer instruction: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create instruction")
    })?;

    let accounts = instruction.accounts.iter().map(|acc| TokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let instruction_data = base64::encode(&instruction.data);

    let response = ApiResponse::success(TokenInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    });

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("Starting Solana HTTP Server on port 8080...");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}