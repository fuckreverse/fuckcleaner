//! API credentials are kept exclusively in the macOS login Keychain.

use crate::i18n::Tr;
use crate::{t, tf};

const SERVICE: &str = "com.petal.ai";
// Versioned accounts never fall back to the legacy provider-api-key entry.
fn account_for(origin: &str) -> Result<String, String> {
    let (url, protocol) = origin
        .rsplit_once('|')
        .ok_or_else(|| t!(Tr::CrScopeInvalid).to_string())?;
    if !matches!(protocol, "chat_completions" | "responses" | "anthropic") {
        return Err(t!(Tr::CrScopeProtocolInvalid).into());
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| t!(Tr::CrOriginInvalid).to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.origin().ascii_serialization() != url
        || origin.len() > 512
    {
        return Err(t!(Tr::CrScopeNotHttps).into());
    }
    Ok(format!("v2|{origin}"))
}
const MAX_KEY_BYTES: usize = 4096;

pub fn load_key_for(origin: &str) -> Result<Option<String>, String> {
    let account = account_for(origin)?;
    #[cfg(target_os = "macos")]
    {
        match security_framework::passwords::get_generic_password(SERVICE, &account) {
            Ok(bytes) => {
                let key = String::from_utf8(bytes)
                    .map_err(|_| t!(Tr::CrKeyEncodedInvalid).to_string())?;
                validate_key(&key)?;
                Ok(Some(key))
            }
            Err(error) if error.code() == -25300 => Ok(None),
            Err(error) => Err(tf!(Tr::CrReadFailed, "code" => error.code())),
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err("API key storage only supports the macOS Keychain".into())
}

pub fn save_key_for(origin: &str, key: &str) -> Result<(), String> {
    let account = account_for(origin)?;
    validate_key(key)?;
    #[cfg(target_os = "macos")]
    {
        security_framework::passwords::set_generic_password(SERVICE, &account, key.as_bytes())
            .map_err(|error| tf!(Tr::CrSaveFailed, "code" => error.code()))
    }
    #[cfg(not(target_os = "macos"))]
    Err("API key storage only supports the macOS Keychain".into())
}

pub fn delete_key_for(origin: &str) -> Result<(), String> {
    let account = account_for(origin)?;
    #[cfg(target_os = "macos")]
    {
        match security_framework::passwords::delete_generic_password(SERVICE, &account) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25300 => Ok(()),
            Err(error) => Err(tf!(Tr::CrDeleteFailed, "code" => error.code())),
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err("API key storage only supports the macOS Keychain".into())
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES || !key.bytes().all(|b| (33..=126).contains(&b))
    {
        return Err(t!(Tr::CrKeyFormatInvalid).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_distinct_and_never_legacy() {
        let a = account_for("https://example.com|responses").unwrap();
        assert_ne!(
            a,
            account_for("https://other.example.com|responses").unwrap()
        );
        assert_ne!(
            a,
            account_for("https://example.com:8443|responses").unwrap()
        );
        assert_ne!(a, account_for("https://example.com|anthropic").unwrap());
        assert_ne!(a, "provider-api-key");
        for scope in [
            "https://example.com",
            "http://localhost|responses",
            "https://u:secret@example.com|responses",
            "https://example.com/v1|responses",
            "https://example.com?key=secret|responses",
            "https://EXAMPLE.com|responses",
        ] {
            assert!(account_for(scope).is_err());
        }
    }

    #[test]
    fn rejects_header_injection_without_keychain_access() {
        assert!(validate_key("example-key").is_ok());
        for key in ["", "key\r\nInjected: yes", " key", "密钥"] {
            let error = validate_key(key).unwrap_err();
            assert!(!error.contains("Injected"));
        }
        assert!(validate_key(&"x".repeat(MAX_KEY_BYTES + 1)).is_err());
    }
}
