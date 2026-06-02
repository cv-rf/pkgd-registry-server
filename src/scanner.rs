use std::io::Read;
use flate2::read::GzDecoder;
use tar::Archive;
use tracing::{warn, info};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub is_clean: bool,
    pub threats: Vec<String>,
}

pub fn scan_package(bytes: &[u8]) -> ScanResult {
    let mut threats = Vec::new();

    // 1. Basic check for EICAR test string
    // This is the standard string used to test if an AV is working.
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    if bytes.windows(eicar.len()).any(|window| window == eicar) {
        threats.push("EICAR Test Signature detected".to_string());
    }

    // 2. Inspect tarball contents
    let tar = GzDecoder::new(bytes);
    let mut archive = Archive::new(tar);

    match archive.entries() {
        Ok(entries) => {
            for entry in entries {
                if let Ok(mut file) = entry {
                    let path = file.path().unwrap().to_path_buf();
                    let path_str = path.to_string_lossy();

                    // Check for suspicious extensions
                    let suspicious_exts = [".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".sh", ".vbs"];
                    for ext in suspicious_exts {
                        if path_str.ends_with(ext) {
                            threats.push(format!("Suspicious file extension found: {}", path_str));
                        }
                    }

                    // Scan file content for suspicious patterns
                    let mut content = Vec::new();
                    if let Ok(_) = file.read_to_end(&mut content) {
                        let suspicious_patterns = [
                            ("Reverse Shell pattern", vec!["/bin/sh -i", "/bin/bash -i", "nc -e /bin/sh"]),
                            ("Obfuscated code", vec!["eval(base64_decode", "eval(gzinflate", "exec(base64"]),
                        ];

                        let content_str = String::from_utf8_lossy(&content);
                        for (category, patterns) in suspicious_patterns {
                            for pattern in patterns {
                                if content_str.contains(pattern) {
                                    threats.push(format!("{} detected in {}: '{}'", category, path_str, pattern));
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to read tarball for scanning: {}", e);
            // If we can't read the tarball, it's suspicious or corrupted
            threats.push("Corrupted or invalid tarball structure".to_string());
        }
    }

    let is_clean = threats.is_empty();
    if !is_clean {
        warn!("Malware scan detected threats: {:?}", threats);
    } else {
        info!("Malware scan completed: No threats found.");
    }

    ScanResult {
        is_clean,
        threats,
    }
}
