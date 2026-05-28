use std::collections::HashMap;
use sha2::{Sha256, Digest};
use crate::models::PackageManifest;

pub fn migrate_storage() {
    let storage_dir = std::path::Path::new("./storage");
    let packages_dir = storage_dir.join("packages");
    
    if !packages_dir.exists() {
        let _ = std::fs::create_dir_all(&packages_dir);
    }

    if let Ok(entries) = std::fs::read_dir(storage_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let file_name = entry.file_name().into_string().unwrap_or_default();

            if path.is_file() && (file_name.ends_with(".json") || file_name.ends_with(".tar.gz")) {
                if let Some(idx) = file_name.rfind('-') {
                    let name = &file_name[..idx];
                    let rest = &file_name[idx+1..];
                    
                    let version = if file_name.ends_with(".json") {
                        rest.strip_suffix(".json").unwrap_or(rest)
                    } else {
                        rest.strip_suffix(".tar.gz").unwrap_or(rest)
                    };

                    let target_dir = packages_dir.join(name).join(version);
                    let _ = std::fs::create_dir_all(&target_dir);

                    let target_name = if file_name.ends_with(".json") { "package.json" } else { "package.tar.gz" };
                    let target_path = target_dir.join(target_name);

                    if let Err(e) = std::fs::rename(&path, &target_path) {
                        eprintln!("Failed to migrate {}: {}", file_name, e);
                    } else {
                        println!("Migrated {} -> {:?}", file_name, target_path);
                    }
                }
            }
        }
    }
}

pub fn compute_checksum(file_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_bytes);
    let result = hasher.finalize();
    
    hex::encode(result)
}

pub fn build_initial_index() -> HashMap<String, PackageManifest> {
    let mut index: HashMap<String, PackageManifest> = HashMap::new();
    let root = std::path::Path::new("./storage/packages");
    
    if !root.exists() {
        let _ = std::fs::create_dir_all(root);
        return index;
    }

    fn walk_dir(dir: &std::path::Path, index: &mut HashMap<String, PackageManifest>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    walk_dir(&path, index);
                } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(json) = std::fs::read_to_string(&path) {
                        if let Ok(manifest) = serde_json::from_str::<PackageManifest>(&json) {
                            let should_insert = match index.get(&manifest.name) {
                                None => true,
                                Some(existing) => {
                                    if let (Ok(new_v), Ok(old_v)) = (
                                        semver::Version::parse(&manifest.version),
                                        semver::Version::parse(&existing.version)
                                    ) {
                                        new_v > old_v
                                    } else {
                                        true
                                    }
                                }
                            };

                            if should_insert {
                                index.insert(manifest.name.clone(), manifest);
                            }
                        }
                    }
                }
            }
        }
    }

    walk_dir(root, &mut index);
    println!("Loaded {} unique packages into memory index.", index.len());
    index
}

pub fn get_latest_version(pkg_name: &str) -> Option<String> {
    let mut versions = Vec::new();
    let pkg_path = format!("./storage/packages/{}", pkg_name);
    
    let entries = std::fs::read_dir(pkg_path).ok()?;

    for entry in entries.filter_map(Result::ok) {
        if let Ok(version_str) = entry.file_name().into_string() {
            if let Ok(version) = semver::Version::parse(&version_str) {
                versions.push(version);
            }
        }
    }

    versions.into_iter().max().map(|v| v.to_string())
}
