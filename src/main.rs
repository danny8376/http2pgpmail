#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use std::env;
use std::fs;

use dotenv::dotenv;
use lettre::message::header::ContentType;
use lettre::{Message as MailMessage, SmtpTransport, Transport};
use pgp::composed::{Deserializable, Message as PGPMessage, SignedPublicKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::PublicKeyTrait;
//use rand_core::{SeedablddeRng, RngCore};
//use rand_chacha::ChaCha20Core;
use rocket::form::Form;
use rocket::response::status::Custom;
use rocket::http::Status;

// ENV
const SMTP_URI: &str = "SMTP_URI";
const MAIL_FROM: &str = "MAIL_FROM";
const SECRET: &str = "SECRET";
const KEY_PATH: &str = "KEY_PATH";

const DEFAULT_KEY_PATH: &str = "keys";

#[derive(FromForm)]
struct MailReq {
    title: String,
    body: String,
}

#[post("/sendmail/<rcpt>?<secret>", data = "<mail>")]
fn sendmail(rcpt: &str, secret: Option<String>, mail: Form<MailReq>) -> Result<String, Custom<String>> {
    match env::var(SECRET) {
        Ok(expected) => match secret {
            Some(secret) if secret == expected => {}, // passed
            _ => return Err(Custom(Status::NotFound, "Not Found".to_string())), // 403 but fake 404
        },
        Err(_) => {}, // no secret set, ignore
    };
    let key_path = match env::var(KEY_PATH) {
        Ok(path) => path,
        Err(_) => DEFAULT_KEY_PATH.to_string(),
    };
    let pub_key_file = format!("{}/{}.pub.asc", key_path, rcpt);
    let key_string = match fs::read_to_string(pub_key_file) {
        Ok(res) => res,
        Err(_e) => return Err(Custom(Status::NotFound, format!("Key for {} doesn't exist!", rcpt))),
    };
    let (public_key, _headers_public) = match SignedPublicKey::from_string(&key_string) {
        Ok(res) => res,
        Err(_e) => return Err(Custom(Status::InternalServerError, format!("Invalid key for {}", rcpt))),
    };
    let sig_subkey = match public_key.public_subkeys.iter().find(|&k| match k.key.algorithm() {
        PublicKeyAlgorithm::RSA => true,
        PublicKeyAlgorithm::RSAEncrypt => true,
        PublicKeyAlgorithm::ECDH => true,
        PublicKeyAlgorithm::X25519 => true,
        PublicKeyAlgorithm::X448 => true,
        _ => false,
    }) {
        Some(res) => &res.key,
        None => return Err(Custom(Status::InternalServerError, format!("Invalid key for {}", rcpt))),
    };
    //let rng = ChaCha20Core::from_os_rng();
    let rng = rand::thread_rng();
    let message = match PGPMessage::new_literal_bytes("encrypted.asc", mail.body.as_bytes())
        .encrypt_to_keys_seipdv1(rng, SymmetricKeyAlgorithm::AES256, &[ &sig_subkey ]) {
            Ok(res) => res,
            Err(e) => return Err(Custom(Status::InternalServerError, format!("Failed to encrypt the message: {}", e))),
    };
    let armored = match message.to_armored_string(None.into()) {
        Ok(res) => res,
        Err(e) => return Err(Custom(Status::InternalServerError, format!("Unable to convert encrypted data: {}", e))),
    };

    let from = match env::var(MAIL_FROM) {
        Ok(res) => res,
        Err(_e) => return Err(Custom(Status::InternalServerError, "MAIL_FROM is not set!".to_string())),
    };

    let email = MailMessage::builder()
        .from(from.parse().unwrap())
        .to(rcpt.parse().unwrap())
        .subject(mail.title.clone())
        .header(ContentType::TEXT_PLAIN)
        .body(armored)
        .unwrap();
    let mailer = match env::var(SMTP_URI) {
        Ok(uri) => match SmtpTransport::from_url(&uri) {
            Ok(smtp) => smtp.build(),
            Err(_e) => return Err(Custom(Status::InternalServerError, "Invalid SMTP_URI!".to_string())),
        },
        Err(_e) => SmtpTransport::unencrypted_localhost(),
    };
    match mailer.send(&email) {
        Ok(_) => Ok("Sent!".to_string()),
        Err(e) => Err(Custom(Status::InternalServerError, format!("Failed to send mail: {}", e))),
    }
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    rocket::build()
        .mount("/", routes![sendmail])
}
