use reqwest::Client;
use std::collections::HashSet;
use std::fs;

pub struct WordlistLoader {
    client: Client,
}

impl WordlistLoader {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn load(
        &self,
        wordlist_path: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let words = if wordlist_path.starts_with("http://") || wordlist_path.starts_with("https://")
        {
            self.load_from_url(wordlist_path).await?
        } else {
            self.load_from_file(wordlist_path)?
        };

        let unique_words: HashSet<String> = words
            .into_iter()
            .filter(|word| !word.trim().is_empty())
            .map(|word| word.trim().to_string())
            .collect();

        Ok(unique_words.into_iter().collect())
    }

    async fn load_from_url(
        &self,
        url: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        println!("[+] Downloading wordlist from: {}", url);

        let response = self.client.get(url).send().await?;
        let content = response.text().await?;

        Ok(content.lines().map(|line| line.to_string()).collect())
    }

    fn load_from_file(
        &self,
        path: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        println!("[+] Loading wordlist from file: {}", path);

        let content = fs::read_to_string(path)?;
        Ok(content.lines().map(|line| line.to_string()).collect())
    }
}
