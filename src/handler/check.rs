use crate::handler::http_client::ScanResult;

pub struct ResponseAnalyzer {
    hashes_404: Vec<String>,
    avg_response_time: u128,
}

impl ResponseAnalyzer {
    pub fn new() -> Self {
        Self {
            hashes_404: Vec::new(),
            avg_response_time: 0,
        }
    }

    pub fn store_404_hashes(&mut self, hash: String) {
        self.hashes_404.push(hash);
    }

    pub fn set_avg_response_time(&mut self, time: u128) {
        self.avg_response_time = time;
    }

    pub fn is_interesting(&self, result: &ScanResult) -> bool {
        if self.hashes_404.contains(&result.content_hash) {
            return false;
        }

        match result.status_code {
            200..=299 => true,
            300..=399 => true,
            401 => true,
            403 => true,
            500..=599 => true,
            _ => false,
        }
    }

    pub fn get_vuln_indicators(&self, result: &ScanResult) -> Vec<String> {
        let mut indicators = Vec::new();

        match result.status_code {
            401 => indicators.push("Authentication Required".to_string()),
            403 => indicators.push("Access Forbidden".to_string()),
            500..=599 => indicators.push("Server Error".to_string()),
            _ => {}
        }

        if result.url.contains(".bak")
            || result.url.contains(".backup")
            || result.url.contains(".old")
            || result.url.contains("~")
        {
            indicators.push("Backup File".to_string());
        }

        if result.url.contains("admin") || result.url.contains("login") {
            indicators.push("Admin Interface".to_string());
        }

        if result.url.contains("config") || result.url.contains(".env") {
            indicators.push("Configuration File".to_string());
        }

        indicators
    }

    pub fn get_risk_score(&self, result: &ScanResult) -> u8 {
        let mut score = 0;

        // score priority
        score += match result.status_code {
            200..=299 => 5,
            401 => 8,
            403 => 7,
            500..=599 => 6,
            _ => 1,
        };

        if result.url.contains("admin") || result.url.contains("login") {
            score += 3;
        }

        if result.url.contains("config") || result.url.contains(".env") {
            score += 4;
        }

        if result.url.contains(".bak") || result.url.contains(".backup") {
            score += 2;
        }

        score.min(10)
    }
}
