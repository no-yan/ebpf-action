use bee_trace::config::{FileConfig, NetworkConfig, SecurityConfig};
use std::net::IpAddr;

mod security_config_tests {
    use super::*;

    mod config_loading {
        use super::*;

        #[test]
        fn should_load_config_from_yaml_string() {
            let yaml_content = r#"
network:
  block:
    - "192.168.1.100"
    - "malicious-domain.com"

files:
  watch_read:
    - "**/*.pem"
    - "**/id_rsa"
    - "**/credentials.json"
"#;

            let config = SecurityConfig::from_yaml_str(yaml_content).unwrap();

            assert_eq!(config.network.block.len(), 2);
            assert!(config.network.block.contains(&"192.168.1.100".to_string()));
            assert!(config
                .network
                .block
                .contains(&"malicious-domain.com".to_string()));

            assert_eq!(config.files.watch_read.len(), 3);
            assert!(config.files.watch_read.contains(&"**/*.pem".to_string()));
        }

        #[test]
        fn should_load_config_from_file() {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let yaml_content = r#"
network:
  block:
    - "evil.example.com"

files:
  watch_read:
    - "*.key"
"#;

            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(yaml_content.as_bytes()).unwrap();

            let config = SecurityConfig::from_file(temp_file.path()).unwrap();

            assert_eq!(config.network.block.len(), 1);
            assert_eq!(config.files.watch_read.len(), 1);
        }

        #[test]
        fn should_handle_missing_config_file() {
            let result = SecurityConfig::from_file("/nonexistent/path/config.yml");
            assert!(result.is_err());
        }

        #[test]
        fn should_handle_invalid_yaml() {
            let invalid_yaml = r#"
network:
  block:
    - "test"
  invalid_syntax: [
"#;

            let result = SecurityConfig::from_yaml_str(invalid_yaml);
            assert!(result.is_err());
        }
    }

    mod config_validation {
        use super::*;

        #[test]
        fn should_create_config_with_default_values() {
            let config = SecurityConfig::default();

            assert!(config.network.block.is_empty());
            assert!(config.files.watch_read.is_empty());
        }

        #[test]
        fn should_validate_ip_addresses() {
            let config = SecurityConfig {
                network: NetworkConfig {
                    block: vec!["192.168.1.1".to_string(), "invalid-ip".to_string()],
                },
                files: FileConfig { watch_read: vec![] },
            };

            let valid_ips = config.get_valid_blocked_ips();
            assert_eq!(valid_ips.len(), 1);
            assert_eq!(valid_ips[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        }

        #[test]
        fn should_handle_mixed_ipv4_and_ipv6() {
            let config = SecurityConfig {
                network: NetworkConfig {
                    block: vec![
                        "192.168.1.1".to_string(),
                        "2001:db8::1".to_string(),
                        "not-an-ip".to_string(),
                    ],
                },
                files: FileConfig { watch_read: vec![] },
            };

            let valid_ips = config.get_valid_blocked_ips();
            assert_eq!(valid_ips.len(), 2);
        }
    }

    mod pattern_matching {
        use super::*;

        #[test]
        fn should_match_file_patterns() {
            let config = SecurityConfig {
                network: NetworkConfig { block: vec![] },
                files: FileConfig {
                    watch_read: vec![
                        "**/*.pem".to_string(),
                        "**/id_rsa".to_string(),
                        "credentials.json".to_string(),
                    ],
                },
            };

            assert!(config.should_monitor_file("/home/user/.ssh/id_rsa"));
            assert!(config.should_monitor_file("/etc/ssl/private/cert.pem"));
            assert!(config.should_monitor_file("./credentials.json"));
            assert!(!config.should_monitor_file("/home/user/document.txt"));
        }

        #[test]
        fn should_handle_glob_patterns() {
            let config = SecurityConfig {
                network: NetworkConfig { block: vec![] },
                files: FileConfig {
                    watch_read: vec!["**/*.key".to_string(), "/etc/ssl/**".to_string()],
                },
            };

            assert!(config.should_monitor_file("/home/user/private.key"));
            assert!(config.should_monitor_file("/etc/ssl/certs/ca.pem"));
            assert!(!config.should_monitor_file("/var/log/app.log"));
        }
    }

    mod domain_blocking {
        use super::*;

        #[test]
        fn should_check_domain_blocking() {
            let config = SecurityConfig {
                network: NetworkConfig {
                    block: vec!["malicious.com".to_string(), "evil-domain.net".to_string()],
                },
                files: FileConfig { watch_read: vec![] },
            };

            assert!(config.is_domain_blocked("malicious.com"));
            assert!(config.is_domain_blocked("evil-domain.net"));
            assert!(!config.is_domain_blocked("google.com"));
            assert!(!config.is_domain_blocked("safe-domain.org"));
        }

        #[test]
        fn should_handle_subdomain_matching() {
            let config = SecurityConfig {
                network: NetworkConfig {
                    block: vec![
                        "*.malicious.com".to_string(),
                        "exact.domain.com".to_string(),
                    ],
                },
                files: FileConfig { watch_read: vec![] },
            };

            assert!(config.is_domain_blocked("sub.malicious.com"));
            assert!(config.is_domain_blocked("api.malicious.com"));
            assert!(config.is_domain_blocked("exact.domain.com"));
            assert!(!config.is_domain_blocked("malicious.com")); // No wildcard match
            assert!(!config.is_domain_blocked("other.domain.com"));
        }
    }
}
