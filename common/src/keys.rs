use anyhow::anyhow;
use anyhow::Result;
use rand_core::OsRng;

pub fn generate_private_key() -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::new(OsRng);
    secret.to_bytes()
}

pub fn public_key_for_secret(secret: [u8; 32]) -> Result<[u8; 32]> {
    x25519_dalek::PublicKey::from(secret)
        .to_bytes()
        .try_into()
        .map_err(|_| anyhow!("shit"))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use base64::decode;
    // tests if this method is compatible with wg genkey | tee privatekey | wg pubkey > publickey
    #[test]
    fn test_if_public_key_is_same() -> Result<()> {
        let secret_from_wg = decode("cNXxrzWM8kXEF4rhnar/Hd8TrPkVglo0dqfrwzLWKmY=")?;
        let publickey_from_wg = decode("2axsD0xz7dfxQdQzRZuq7LKorOz3uaWI6zpcGvQxnlQ=")?;

        let secret: [u8; 32] = secret_from_wg[..].try_into()?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public_key = x25519_dalek::PublicKey::from(&secret);

        let public_key_from_wg: [u8; 32] = publickey_from_wg[..].try_into()?;
        assert_eq!(public_key.as_bytes(), &public_key_from_wg);
        Ok(())
    }
}
