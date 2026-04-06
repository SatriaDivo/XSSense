use pyo3::prelude::*;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashSet;
use url::Url;
use regex::Regex;

/// Fungsi Basic Sinkron
#[pyfunction]
fn scan_url(url: &str, payload: &str) -> PyResult<bool> {
    let client = reqwest::blocking::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
    if let Ok(res) = client.get(url).send() {
        if let Ok(text) = res.text() {
            return Ok(text.contains(payload));
        }
    }
    Ok(false)
}

/// Fungsi Brutal Asynchronous: Menerima ratusan URL dan Payload, ditembak secara bersamaan!
#[pyfunction]
fn scan_batch(urls: Vec<String>, payloads: Vec<String>) -> PyResult<Vec<String>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let result = rt.block_on(async {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let client = Arc::new(client);
        let mut handles = vec![];

        // Menyebar thread untuk ratusan request sekaligus
        for (url, payload) in urls.into_iter().zip(payloads.into_iter()) {
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                if let Ok(res) = client.get(&url).send().await {
                    if let Ok(text) = res.text().await {
                        if text.contains(&payload) {
                            return Some(url);
                        }
                    }
                }
                None
            }));
        }

        // Mengumpulkan semua URL yang ternyata RENTAN (vuln)
        let mut vulnerable_urls = vec![];
        for handle in handles {
            if let Ok(Some(vuln_url)) = handle.await {
                vulnerable_urls.push(vuln_url);
            }
        }
        vulnerable_urls
    });

    Ok(result)
}

/// Crawler Performa Brutal: Menyisir seluruh link target dari HTML via Async Rust
#[pyfunction]
fn run_crawler(base_url: String, max_depth: u32) -> PyResult<Vec<String>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let result = rt.block_on(async {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
            
        let visited = Arc::new(Mutex::new(HashSet::new()));
        let mut to_visit = vec![(base_url.clone(), 0)];
        
        let base_parsed = match Url::parse(&base_url) {
            Ok(u) => u,
            Err(_) => return vec![]
        };
        let host = base_parsed.host_str().unwrap_or("").to_owned();

        // Menggunakan regex untuk menyedot tag href secepat kilat (mengabaikan kutip 1 atau 2)
        let re = Regex::new(r#"(?i)href\s*=\s*["']([^"']+)["']"#).unwrap();

        while !to_visit.is_empty() {
            let mut handles = vec![];
            let mut next_level = vec![];

            for (url, depth) in to_visit {
                if depth > max_depth { continue; }
                
                let mut v = visited.lock().await;
                if !v.insert(url.clone()) { continue; }
                drop(v);

                let client_clone = client.clone();
                let re_clone = re.clone();
                let base_clone = base_parsed.clone();
                let host_clone = host.clone();

                handles.push(tokio::spawn(async move {
                    let mut found = vec![];
                    if let Ok(res) = client_clone.get(&url).send().await {
                        if let Ok(text) = res.text().await {
                            for cap in re_clone.captures_iter(&text) {
                                let link = &cap[1];
                                if link.starts_with("javascript:") || link.starts_with("mailto:") || link.starts_with("tel:") || link.starts_with("#") {
                                    continue;
                                }
                                
                                // Gabungkan relative url (misal: /login.php) ke url dasar
                                if let Ok(parsed_link) = base_clone.join(link) {
                                    let link_host = parsed_link.host_str().unwrap_or("");
                                    // Hanya kumpulkan URL yang domain utamanya masih sama (mencegah merayap ke google.com dll)
                                    if link_host == host_clone {
                                        found.push((parsed_link.to_string(), depth + 1));
                                    }
                                }
                            }
                        }
                    }
                    found
                }));
            }

            // Tunggu semua thread di level kedalaman ini selesai
            for handle in handles {
                if let Ok(mut links) = handle.await {
                    for link_data in links.drain(..) {
                        let v = visited.lock().await;
                        if !v.contains(&link_data.0) {
                            next_level.push(link_data);
                        }
                    }
                }
            }

            to_visit = next_level;
        }

        let final_visited = visited.lock().await;
        let mut final_urls = Vec::new();
        for url in final_visited.iter() {
            final_urls.push(url.clone());
        }
        final_urls
    });

    Ok(result)
}

#[pymodule]
fn xssense_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_url, m)?)?;
    m.add_function(wrap_pyfunction!(scan_batch, m)?)?;
    m.add_function(wrap_pyfunction!(run_crawler, m)?)?;
    Ok(())
}
