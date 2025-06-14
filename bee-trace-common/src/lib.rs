#![no_std]

/// Map name storing blocked IPv4 addresses.
pub const BLOCK_LIST: &str = "BLOCK_LIST";

/// Map name storing explicitly allowed IPv4 addresses.
pub const ALLOW_LIST: &str = "ALLOW_LIST";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_values() {
        assert_eq!(BLOCK_LIST, "BLOCK_LIST");
        assert_eq!(ALLOW_LIST, "ALLOW_LIST");
    }
}
