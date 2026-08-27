use crate::Tool;
use mrml_error::{Result, anyhow};
use mrml_runtime::{Text, Vector};
use mrml_runtime::{Text as String, mrml_format as format};
use serde_json::json;

fn owned_string(value: &str) -> String {
    value.into()
}

fn text_string(value: Text) -> String {
    value
}

pub async fn fetch_http_text(url: &str) -> Result<String> {
    validate_public_https_url(url)?;
    if let Ok(mut response) = mrml_http::Client::new()
        .user_agent("Mozilla/5.0 (compatible; MRML/0.4)")
        .get_follow_checked(url, &[], 8, is_public_https_endpoint)
    {
        if (200..300).contains(&response.status) {
            let body = response
                .read_to_end(16 * 1024 * 1024)
                .map_err(|error| anyhow!("HTTPS body read failed: {}", error))?;
            if !body.is_empty() {
                return Ok(text_string(Text::from_utf8_lossy(&body)));
            }
        }
    }

    Err(anyhow!(
        "Failed to fetch web content from '{}' via the authenticated HTTPS client.",
        url
    ))
}

pub(crate) fn validate_public_https_url(input: &str) -> Result<()> {
    let url =
        mrml_http::Url::parse(input).map_err(|_| anyhow!("Only valid HTTPS URLs are allowed"))?;
    let host = url.host.as_str();
    if is_local_hostname(host) || parse_ipv4(host).is_some_and(is_non_public_ipv4) {
        return Err(anyhow!("Local, private, and special-use network URLs are not allowed"));
    }
    Ok(())
}

fn is_public_https_endpoint(url: &mrml_http::Url, address: [u8; 4]) -> bool {
    !is_local_hostname(url.host.as_str()) && !is_non_public_ipv4(address)
}

fn is_local_hostname(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "local"
        || host.ends_with(".local")
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

// Reject addresses that are unsuitable as public web endpoints.
fn is_non_public_ipv4(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [0, ..]
            | [10, ..]
            | [127, ..]
            | [169, 254, ..]
            | [192, 0, 0, ..]
            | [192, 0, 2, ..]
            | [192, 88, 99, ..]
            | [192, 168, ..]
            | [198, 18, ..]
            | [198, 19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
    ) || matches!(octets, [100, second, ..] if (64..=127).contains(&second))
        || matches!(octets, [172, second, ..] if (16..=31).contains(&second))
        || octets[0] >= 224
}

pub struct WebSearchTool;

impl Tool for WebSearchTool {
    fn name(&self) -> &'static str {
        "web_search"
    }

    fn description(&self) -> &'static str {
        "Search the internet for live web results, technical documentation, Wikipedia articles, images, and news."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query keywords (e.g. 'cute fruit bat', 'Rust async-trait', 'Bicycle Race Queen')"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, _workspace_root: &str, args: serde_json::Value) -> Result<String> {
        let query = args["query"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing query"))?;
        let mut results = Vector::new();

        // 1. First search Wikipedia directly
        let clean_query = Text::from(query)
            .replace("find an image of a ", "")
            .replace("find an image of ", "")
            .replace("show an image of a ", "")
            .replace("show an image of ", "")
            .replace("image of a ", "")
            .replace("image of ", "")
            .replace("picture of ", "")
            .replace("photo of ", "");

        let wiki_url = format!(
            "https://en.wikipedia.org/wiki/Special:Search?search={}&go=Go",
            mrml_percent_encoding::encode(&clean_query)
        );

        if let Ok(html) = fetch_http_text(&wiki_url).await {
            let heading = crate::html::elements(&html, "h1", None)
                .iter()
                .next()
                .map(|element| element.text.clone())
                .unwrap_or_else(|| mrml_runtime::Text::from(query));

            let mut img_url: Option<String> = None;
            let metadata = crate::html::elements(&html, "meta", None);
            let images = crate::html::elements(&html, "img", None);
            for elements in [&metadata, &images] {
                for element in elements {
                    if let Some(content) = element.attributes.get("content") {
                        if content.starts_with("http") {
                            img_url = Some(owned_string(content));
                            break;
                        }
                    }
                    if let Some(src) = element.attributes.get("src") {
                        let full = if src.starts_with("//") {
                            format!("https:{}", src)
                        } else {
                            owned_string(src)
                        };
                        if full.starts_with("http")
                            && !full.contains("static/favicon")
                            && !full.contains("apple-touch")
                        {
                            img_url = Some(full);
                            break;
                        }
                    }
                }
                if img_url.is_some() {
                    break;
                }
            }

            let mut p_text = String::new();
            for element in crate::html::elements(&html, "p", None).iter().take(4) {
                if !element.text.is_empty() && element.text.len() > 20 {
                    if !p_text.is_empty() {
                        p_text.push_str("\n\n");
                    }
                    p_text.push_str(&element.text);
                }
            }

            if !p_text.is_empty() || img_url.is_some() {
                let mut entry = format!("- **{}** (Wikipedia)\n  URL: {}\n", heading, wiki_url);
                if let Some(ref img) = img_url {
                    entry.push_str(&format!(
                        "  Image URL: {}\n  Markdown Image: ![{}]({})\n",
                        img, heading, img
                    ));
                }
                if !p_text.is_empty() {
                    entry.push_str(&format!(
                        "  Summary: {}\n",
                        crate::markdown::truncate_utf8(&p_text, 1000)
                    ));
                }
                results.push(entry);
            }
        }

        // 2. Search DuckDuckGo HTML
        let ddg_url = format!(
            "https://html.duckduckgo.com/html/?q={}",
            mrml_percent_encoding::encode(query)
        );
        if let Ok(html) = fetch_http_text(&ddg_url).await {
            let links = crate::html::elements(&html, "a", Some("result__a"));
            let snippets = crate::html::elements(&html, "a", Some("result__snippet"));
            for (index, link) in links.iter().take(6).enumerate() {
                let title = &link.text;
                let raw_href = link
                    .attributes
                    .get("href")
                    .map(|value| value.as_str())
                    .unwrap_or("");
                let snippet = snippets
                    .get(index)
                    .map(|item| item.text.clone())
                    .unwrap_or_default();

                let clean_url = if let Some(pos) = raw_href.find("uddg=") {
                    let after = &raw_href[pos + 5..];
                    let raw_encoded = after.split('&').next().unwrap_or(after);
                    let decoded = mrml_percent_encoding::decode(raw_encoded)
                        .unwrap_or(mrml_percent_encoding::TextResult::Borrowed(raw_encoded));
                    owned_string(&decoded)
                } else if raw_href.starts_with("http") {
                    owned_string(raw_href)
                } else {
                    continue;
                };

                if !title.is_empty()
                    && clean_url.starts_with("http")
                    && !clean_url.contains("duckduckgo.com")
                {
                    if !snippet.is_empty() {
                        results.push(format!(
                            "- **{}**\n  URL: {}\n  Summary: {}",
                            title, clean_url, snippet
                        ));
                    } else {
                        results.push(format!("- **{}**\n  URL: {}", title, clean_url));
                    }
                }
            }
        }

        if results.is_empty() {
            Ok(format!(
                "Web search executed for '{}', but no public search results were returned. Try searching with more specific keywords or use web_fetch on a known URL.",
                query
            ))
        } else {
            let mut output = String::new();
            for (index, result) in results.iter().enumerate() {
                if index != 0 {
                    output.push_str("\n\n");
                }
                output.push_str(result);
            }
            Ok(output)
        }
    }
}

pub struct WebFetchTool;

impl Tool for WebFetchTool {
    fn name(&self) -> &'static str {
        "web_fetch"
    }

    fn description(&self) -> &'static str {
        "Fetch a public HTTPS page with the authenticated HTTP client and return clean text extracted from its response body."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full web page URL to fetch and dump text from"
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, _workspace_root: &str, args: serde_json::Value) -> Result<String> {
        let url_str = args["url"].as_str().ok_or_else(|| anyhow!("Missing url"))?;
        let html = fetch_http_text(url_str).await?;

        let full_text = crate::html::visible_text(&html);
        if full_text.is_empty() {
            Ok(format!(
                "Successfully fetched URL '{}', but no clean body text was extracted.",
                url_str
            ))
        } else if full_text.len() > 10000 {
            Ok(format!(
                "{}... (truncated at 10,000 characters)",
                crate::markdown::truncate_utf8(&full_text, 10000)
            ))
        } else {
            Ok(text_string(full_text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_tool_definitions_and_public_url_policy_are_stable() {
        assert_eq!(WebSearchTool.name(), "web_search");
        assert_eq!(WebFetchTool.name(), "web_fetch");
        assert!(!WebFetchTool.description().contains("headless browser"));
        assert!(WebFetchTool.description().contains("public HTTPS"));
        assert!(validate_public_https_url("https://example.com/path").is_ok());
        assert!(validate_public_https_url("http://example.com").is_err());
        assert!(validate_public_https_url("https://127.0.0.1/private").is_err());
        assert!(validate_public_https_url("https://192.168.1.2/private").is_err());
        assert!(validate_public_https_url("https://localhost/private").is_err());
        assert!(validate_public_https_url("https://printer.local/private").is_err());

        let public = mrml_http::Url::parse("https://example.com/").unwrap();
        for address in [[1, 1, 1, 1], [8, 8, 8, 8], [100, 63, 255, 255], [223, 1, 1, 1]] {
            assert!(is_public_https_endpoint(&public, address));
        }
        for address in [
            [0, 0, 0, 0],
            [10, 0, 0, 1],
            [100, 64, 0, 1],
            [127, 0, 0, 1],
            [169, 254, 169, 254],
            [172, 16, 0, 1],
            [192, 0, 0, 1],
            [192, 168, 0, 1],
            [198, 18, 0, 1],
            [203, 0, 113, 1],
            [224, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            assert!(!is_public_https_endpoint(&public, address));
        }
    }
}
