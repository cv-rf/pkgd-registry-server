use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserTier {
    Member,
    Supporter,
    Partner,
    Verified,
    Staff,
}

impl From<String> for UserTier {
    fn from(s: String) -> Self {
        match s.as_str() {
            "verified" => UserTier::Verified,
            "partner" => UserTier::Partner,
            "supporter" => UserTier::Supporter,
            "staff" => UserTier::Staff,
            _ => UserTier::Member,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub username: String,
    pub tier: UserTier,
    pub bio: String,
    pub packages: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageDisplay {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub downloads: i64,
    pub is_verified: bool,
    pub is_author_verified: bool,
}

#[derive(Serialize)]
pub struct ProfilePackage {
    pub name: String,
    pub downloads: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserDisplay {
    pub username: String,
    pub tier: String,
}

#[derive(Deserialize)]
pub struct UpgradeRequest {
    pub username: String,
    pub tier: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub name: String,
    pub verified: bool,
}

#[derive(Deserialize)]
pub struct BioRequest {
    pub bio: String,
}

#[derive(Serialize)]
pub struct ProfileEditResponse {
    pub username: String,
    pub tier: String,
    pub bio: String,
    pub token: String,
}
