use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
    #[serde(default)]
    pub dependencies: Option<Vec<String>>,
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
    pub avatar_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub website_url: Option<String>,
    pub packages: Vec<String>,
    pub total_downloads: i64,
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub website_url: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TokenDisplay {
    pub token: String,
    pub name: String,
    pub created_at: chrono::NaiveDateTime,
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
    pub avatar_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub website_url: Option<String>,
    pub token: String,
}

#[derive(Deserialize, Debug)]
pub struct AdminPaginationParams {
    pub q: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub total_pages: u32,
}
