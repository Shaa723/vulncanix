use crate::config::Config;
use crate::handler::http_client::ScanResult;
use crate::scanner::autoscan::WebScanner;
use crate::wordlist::WordlistLoader;
use clap::Parser;
use colored::*;
use serde_json;
use std::process;

mod config;
mod handler;
mod scanner;
mod wordlist;

pub struct OutputFormatter {
    output_format: String,
    colors_enabled: bool,
}

impl OutputFormatter {
    pub fn new(fmt: &str) -> Self {
        Self {
            output_format: fmt.to_string(),
            colors_enabled: atty::is(atty::Stream::Stdout),
        }
    }

    pub fn display_result(
        &self,
        scan_result: &ScanResult,
        warning_flags: &[String],
        danger_level: u8,
    ) {
        match self.output_format.as_str() {
            "json" => self.print_json(scan_result, warning_flags, danger_level),
            _ => self.print_result(scan_result, warning_flags, danger_level),
        }
    }

    fn print_result(&self, scan_result: &ScanResult, warning_flags: &[String], danger_level: u8) {
        let status_display = if self.colors_enabled {
            self.colorize_status(scan_result.status_code)
        } else {
            scan_result.status_code.to_string()
        };

        let size_info = if scan_result.content_length > 0 {
            format!("(Size: {})", scan_result.content_length)
        } else {
            String::new()
        };

        let redirect_info = if let Some(ref redir_location) = scan_result.header_loc {
            format!(" -> {}", redir_location)
        } else {
            String::new()
        };

        print!(
            "{} {} {}{}",
            status_display, scan_result.url, size_info, redirect_info
        );

        if !warning_flags.is_empty() {
            print!(" [{}]", warning_flags.join(", "));
        }

        if danger_level > 7 {
            print!(" [HIGH RISK]");
        } else if danger_level > 5 {
            print!(" [MEDIUM RISK]");
        }

        println!();
    }

    fn print_json(&self, scan_result: &ScanResult, warning_flags: &[String], danger_level: u8) {
        let json_output = serde_json::json!({
            "url": scan_result.url,
            "status_code": scan_result.status_code,
            "content_length": scan_result.content_length,
            "response_time": scan_result.response_time,
            "server": scan_result.server_header,
            "location": scan_result.header_loc,
            "content_type": scan_result.content_type,
            "indicators": warning_flags,
            "risk_score": danger_level
        });

        println!("{}", json_output);
    }

    fn colorize_status(&self, status_num: u16) -> String {
        match status_num {
            200..=299 => status_num.to_string().green().to_string(),
            300..=399 => status_num.to_string().yellow().to_string(),
            400..=499 => status_num.to_string().red().to_string(),
            500..=599 => status_num.to_string().magenta().to_string(),
            _ => status_num.to_string().white().to_string(),
        }
    }

    pub fn show_summary(&self, total_reqs: usize, interesting_hits: usize, time_taken: u128) {
        println!();
        println!("===============================================");
        println!("[+] Scan Summary          :");
        println!("[+] Total requests        : {}", total_reqs);
        println!("[+] Interesting responses : {}", interesting_hits);
        println!("[+] Elapsed time          : {}ms", time_taken);
        println!(
            "[+] Requests per second        : {:.2}",
            total_reqs as f64 / (time_taken as f64 / 1000.0)
        );
    }
}

#[tokio::main]
async fn main() {
    let cli_args = Config::parse();

    println!("[+] Vulncanix - Simple Web Vulnerability Scanner");
    println!("[+] Target        : {}", cli_args.target);
    println!("[+] Concurrency   : {}", cli_args.concurrency);
    println!("[+] Timeout       : {}s", cli_args.timeout);

    let dict_loader = WordlistLoader::new();
    let word_list = match dict_loader.load(&cli_args.wordlist).await {
        Ok(words) => words,
        Err(e) => {
            eprintln!("[-] Failed to load wordlist: {}", e);
            process::exit(1);
        }
    };

    println!("[+] Loaded {} words from wordlist", word_list.len());
    println!("[+] Starting scan...");
    println!("===============================================");

    let vulnerability_scanner =
        match WebScanner::new(&cli_args.target, cli_args.concurrency, cli_args.timeout) {
            Ok(scanner) => scanner,
            Err(e) => {
                eprintln!("[-] Failed to create scanner: {}", e);
                process::exit(1);
            }
        };

    if let Err(e) = vulnerability_scanner.run_scan(word_list).await {
        eprintln!("[-] Scan failed: {}", e);
        process::exit(1);
    }

    println!("[+] Scan completed.");
}
