use secrecy::{ExposeSecret, SecretString};

const REDACTED: &str = "[REDACTED]";

pub fn redact_text(input: &str, secrets: &[&SecretString]) -> String {
    let mut output = input.to_owned();
    for secret in secrets {
        let value = secret.expose_secret();
        if !value.is_empty() {
            output = output.replace(value, REDACTED);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_every_occurrence() {
        let secret = SecretString::from("test-token-123".to_owned());
        let result = redact_text("a=test-token-123; again test-token-123", &[&secret]);
        assert_eq!(result, "a=[REDACTED]; again [REDACTED]");
    }
}
