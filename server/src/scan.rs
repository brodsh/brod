// SPDX-License-Identifier: AGPL-3.0-only
// The deploy-time phishing check: a cheap heuristic scan of a version's HTML and JavaScript, with no outside service.
// It works on bytes (every pattern is ASCII) and is tested on small abstract snippets with a made-up brand list.
//
// A version is flagged when it asks for a password or a card number AND carries enough impersonation signals (a brand
// name in the title, a heading or a logo, "sign in to your <brand> account", "verify your account", a form that posts to
// another site, code that sends data to a Telegram bot). A seed-phrase prompt, a "connect your wallet to claim" prompt,
// or a page that writes itself from an encoded string is flagged on its own. A login form for the app's own data, with
// none of those signals, is not.
use crate::tar::BundleFile;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Scan {
    pub flagged: bool,
    pub score: i64,
    pub reasons: Vec<String>,
}

/// Read at most this much of each file, and of the whole bundle.
const FILE_BYTES: usize = 1024 * 1024;
const TOTAL_BYTES: usize = 8 * 1024 * 1024;
const TEXT: [&str; 6] = ["html", "htm", "js", "mjs", "cjs", "svg"];
const THRESHOLD: i64 = 3;

/// Names phishing pages imitate. Multi-word names match with single spaces.
pub const BRANDS: &[&str] = &[
    "microsoft",
    "office 365",
    "office365",
    "outlook",
    "onedrive",
    "sharepoint",
    "google",
    "gmail",
    "apple",
    "icloud",
    "paypal",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "dropbox",
    "docusign",
    "adobe",
    "chase bank",
    "wells fargo",
    "bank of america",
    "citibank",
    "hsbc",
    "barclays",
    "santander",
    "lloyds",
    "natwest",
    "coinbase",
    "binance",
    "metamask",
    "trust wallet",
    "ledger live",
    "trezor",
    "kraken",
    "blockchain.com",
    "dhl",
    "fedex",
    "usps",
    "hmrc",
    "yahoo",
    "venmo",
    "revolut",
];
/// Brands that are also everyday words or common integrations: they count in a title or next to sign-in words, never as a bare mention.
const AMBIGUOUS: [&str; 6] = ["apple", "amazon", "google", "outlook", "office 365", "office365"];
const STRONG_BEFORE: [&str; 10] = [
    "sign in to your ",
    "sign in to ",
    "log in to your ",
    "log in to ",
    "login to your ",
    "login to ",
    "verify your ",
    "confirm your ",
    "unlock your ",
    "restore your ",
];
const WEAK_AFTER: [&str; 9] = [" account", " id", " login", " sign in", " sign-in", " password", " wallet", " verification", " security"];
const PHRASES: [&str; 22] = [
    "verify your account",
    "verify your identity",
    "confirm your identity",
    "confirm your account",
    "validate your account",
    "sign in to continue",
    "log in to continue",
    "login to continue",
    "unusual activity",
    "unusual sign-in activity",
    "account has been suspended",
    "account has been locked",
    "account has been limited",
    "account is suspended",
    "account is locked",
    "update your payment",
    "update your billing",
    "re-enter your password",
    "reenter your password",
    "your session has expired",
    "unlock your account",
    "security alert",
];
const SEED: [&str; 12] = [
    "seed phrase",
    "recovery phrase",
    "mnemonic phrase",
    "secret phrase",
    "12 word phrase",
    "12-word phrase",
    "24 word phrase",
    "24-word phrase",
    "12 word seed",
    "12-word seed",
    "24 word seed",
    "24-word seed",
];
const WALLET: [&str; 4] = ["walletconnect", "wallet connect", "connect wallet", "connect your wallet"];
const WALLET_ACTION: [&str; 18] = [
    "validate wallet",
    "validate your wallet",
    "rectify",
    "sync wallet",
    "sync your wallet",
    "synchronize wallet",
    "restore wallet",
    "restore your wallet",
    "recover wallet",
    "import wallet",
    "import your wallet",
    "claim airdrop",
    "claim your airdrop",
    "claim reward",
    "claim your reward",
    "claim your tokens",
    "migrate wallet",
    "unlock wallet",
];
const CARD_VALUES: [&str; 10] =
    ["cardnumber", "card-number", "card_number", "ccnumber", "cc-number", "cc_number", "cvv", "cvv2", "cvc", "csc"];
const CARD_AUTOCOMPLETE: [&str; 4] = ["autocomplete=cc-number", "autocomplete:cc-number", "autocomplete=cc-csc", "autocomplete:cc-csc"];
const PASSWORD: [&str; 4] = ["type=password", "type:password", "autocomplete=current-password", "autocomplete:current-password"];
const OBFUSCATED: [&str; 4] =
    ["document.write(unescape(", "document.write(atob(", "document.write(window.atob(", "document.write(decodeuricomponent("];
const EXFIL: [(&str, &str); 3] = [
    ("api.telegram.org/bot", "code that sends data to a Telegram bot"),
    ("discord.com/api/webhooks", "code that sends data to a Discord webhook"),
    ("discordapp.com/api/webhooks", "code that sends data to a Discord webhook"),
];
const IP_LOOKUP: [&str; 5] = ["api.ipify.org", "ipapi.co", "ip-api.com", "ipinfo.io", "geoplugin.net"];
const HEADINGS: [&str; 4] = ["title", "h1", "h2", "h3"];
const ATTRS: [&str; 4] = ["alt=", "aria-label=", "placeholder=", "title="];
const INPUTS: [&str; 6] = ["<input", "<textarea", "\"textarea\"", "'textarea'", "\"input\"", "'input'"];
const PUNCT: &[u8] = b"=:(),;{}[]<>";

fn alnum(c: Option<&u8>) -> bool {
    c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{c}' | '\u{b}')
}

/// The first index of `needle` in `hay` at or after `from`, like indexOf.
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    memchr::memmem::find(hay.get(from..)?, needle).map(|i| from + i)
}
fn contains(hay: &[u8], needle: &str) -> bool {
    find(hay, needle.as_bytes(), 0).is_some()
}
/// Every index of `needle` in `hay`, overlapping ones included.
fn all(hay: &[u8], needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = find(hay, needle.as_bytes(), from) {
        out.push(i);
        from = i + 1;
    }
    out
}

/// Lower case, with every run of whitespace made one space.
pub fn collapse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for ch in s.to_lowercase().chars() {
        if is_space(ch) {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(ch);
    }
    out
}

/// Lower case, without quotes and backslashes, with whitespace collapsed and dropped next to punctuation:
/// `type = "password" name` and `{type:\"password\"}` read type=password name and {type:password}.
pub fn compact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in collapse(s).chars() {
        if matches!(ch, '"' | '\'' | '`' | '\\') {
            continue;
        }
        let last = out.as_bytes().last().copied();
        if ch == ' ' && last.is_some_and(|l| l == b' ' || PUNCT.contains(&l)) {
            continue;
        }
        if ch.is_ascii() && PUNCT.contains(&(ch as u8)) && last == Some(b' ') {
            out.pop();
        }
        out.push(ch);
    }
    out
}

/// Every index where `word` occurs in `hay` with no letter or digit on either side.
fn word_at(hay: &[u8], word: &str) -> Vec<usize> {
    all(hay, word).into_iter().filter(|&i| !(alnum(hay.get(i + word.len())) || i > 0 && alnum(hay.get(i - 1)))).collect()
}
fn has_word(hay: &[u8], word: &str) -> bool {
    !word_at(hay, word).is_empty()
}
/// `needle` occurs with no letter or digit right after it.
fn ends_clean(hay: &[u8], needle: &str) -> bool {
    all(hay, needle).into_iter().any(|i| !alnum(hay.get(i + needle.len())))
}

/// The text between `<tag ...>` and `</tag>`, for each such element. `s` is lower case.
fn elements(s: &[u8], tag: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let (open_tag, close_tag) = (format!("<{tag}"), format!("</{tag}"));
    for i in all(s, &open_tag) {
        if alnum(s.get(i + tag.len() + 1)) {
            continue;
        }
        let Some(open) = find(s, b">", i) else { break };
        let end = find(s, close_tag.as_bytes(), open).unwrap_or_else(|| s.len().min(open + 1 + 400));
        out.push(s[open + 1..end.max(open + 1)].to_vec());
    }
    out
}

/// The value after `name` (which ends in "="), quoted or not. `s` is collapsed.
fn attr_values(s: &[u8], name: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in all(s, name) {
        if i > 0 && (alnum(s.get(i - 1)) || s[i - 1] == b'-') {
            continue;
        }
        let j = i + name.len();
        match s.get(j) {
            Some(&q) if q == b'"' || q == b'\'' => {
                let end = find(s, &[q], j + 1).unwrap_or(s.len());
                out.push(s[j + 1..end].to_vec());
            }
            _ => {
                let mut end = j;
                while end < s.len() && !matches!(s[end], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | b'>') {
                    end += 1;
                }
                out.push(s[j.min(s.len())..end.max(j.min(s.len()))].to_vec());
            }
        }
    }
    out
}

/// Drop `<script>`, `<style>` and comments, then every tag, then words that are addresses or emails: roughly what a visitor reads.
fn visible_text(s: &[u8]) -> Vec<u8> {
    let mut t = s.to_vec();
    for (a, b) in [("<script", "</script"), ("<style", "</style"), ("<!--", "-->")] {
        let mut out = Vec::with_capacity(t.len());
        let mut i = 0;
        loop {
            let Some(start) = find(&t, a.as_bytes(), i) else {
                out.extend_from_slice(&t[i..]);
                break;
            };
            out.extend_from_slice(&t[i..start]);
            out.push(b' ');
            let Some(end) = find(&t, b.as_bytes(), start) else { break };
            i = end + b.len();
        }
        t = out;
    }
    let mut out = Vec::with_capacity(t.len());
    let mut in_tag = false;
    for &c in &t {
        match c {
            b'<' => {
                in_tag = true;
                out.push(b' ');
            }
            b'>' => {
                in_tag = false;
                out.push(b' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let words: Vec<&[u8]> =
        out.split(|&c| c == b' ').filter(|w| !contains(w, "://") && !contains(w, "www.") && !contains(w, "@")).collect();
    collapse(&String::from_utf8_lossy(&words.join(&b' '))).into_bytes()
}

/// `s` with each of `chars` made a space.
fn spaced(s: &[u8], chars: &[u8]) -> Vec<u8> {
    s.iter().map(|c| if chars.contains(c) { b' ' } else { *c }).collect()
}

/// The host a form's action sends to, if it is another site: "email" for mailto:.
fn form_host(v: &[u8]) -> Option<String> {
    if v.starts_with(b"mailto:") {
        return Some("email".into());
    }
    let rest = [&b"https://"[..], b"http://", b"//"].iter().find_map(|p| v.strip_prefix(*p))?;
    let host: Vec<u8> = rest.iter().take_while(|c| !matches!(c, b'/' | b'?' | b'#')).copied().collect();
    (!host.is_empty()).then(|| String::from_utf8_lossy(&host).into_owned())
}

/// Look at a bundle's pages and scripts with the built-in brand list.
pub fn scan_bundle(files: &[BundleFile]) -> Scan {
    scan_with(files, BRANDS)
}

/// Look at a bundle's pages and scripts. `brands` is replaceable for tests.
pub fn scan_with(files: &[BundleFile], brands: &[&str]) -> Scan {
    let mut budget = TOTAL_BYTES;
    let (mut password, mut card, mut seed, mut wallet_ask, mut wallet_act, mut obfuscated, mut input) =
        (false, false, false, false, false, false, false);
    let (mut prominent, mut strong, mut weak, mut mention, mut exfil, mut ip_lookup) =
        (String::new(), String::new(), String::new(), String::new(), String::new(), String::new());
    let (mut phrases, mut forms): (Vec<&str>, Vec<String>) = (Vec::new(), Vec::new());
    let card_needles: Vec<String> = CARD_AUTOCOMPLETE
        .iter()
        .map(|s| s.to_string())
        .chain(
            ["name", "id"]
                .iter()
                .flat_map(|k| ["=", ":"].iter().flat_map(move |sep| CARD_VALUES.iter().map(move |v| format!("{k}{sep}{v}")))),
        )
        .collect();

    for f in files {
        let base = f.path.to_lowercase().rsplit('/').next().unwrap_or("").to_string();
        // A logo file named after a brand, such as microsoft-logo.svg.
        if prominent.is_empty() && base.contains("logo") {
            let words = spaced(base.as_bytes(), b"-_.");
            prominent = brands.iter().find(|b| has_word(&words, b)).map(|b| b.to_string()).unwrap_or_default();
        }
        let ext = if base.contains('.') { base.rsplit('.').next().unwrap_or("") } else { "" };
        if !TEXT.contains(&ext) || budget == 0 {
            continue;
        }
        let take = f.bytes.len().min(FILE_BYTES).min(budget);
        budget -= take;
        let raw = String::from_utf8_lossy(&f.bytes[..take]);
        let (text, tight) = (collapse(&raw).into_bytes(), compact(&raw).into_bytes());
        let html = matches!(ext, "html" | "htm" | "svg");

        password |= PASSWORD.iter().any(|n| ends_clean(&tight, n));
        card |= card_needles.iter().any(|n| ends_clean(&tight, n));
        obfuscated |= OBFUSCATED.iter().any(|n| contains(&tight, n));
        input |= INPUTS.iter().any(|n| contains(&text, n));
        seed |= SEED.iter().any(|n| contains(&text, n));
        wallet_ask |= WALLET.iter().any(|n| contains(&text, n));
        wallet_act |= WALLET_ACTION.iter().any(|n| contains(&text, n));
        for p in PHRASES {
            if !phrases.contains(&p) && contains(&text, p) {
                phrases.push(p);
            }
        }
        if exfil.is_empty() {
            exfil = EXFIL.iter().find(|(n, _)| contains(&text, n)).map(|(_, why)| why.to_string()).unwrap_or_default();
        }
        if ip_lookup.is_empty() {
            ip_lookup = IP_LOOKUP.iter().find(|n| contains(&text, n)).map(|n| n.to_string()).unwrap_or_default();
        }

        for b in brands {
            for at in word_at(&text, b) {
                let before = &text[at.saturating_sub(24)..at];
                let after = &text[at + b.len()..(at + b.len() + 16).min(text.len())];
                if strong.is_empty()
                    && let Some(p) = STRONG_BEFORE.iter().find(|p| before.ends_with(p.as_bytes()))
                {
                    strong = format!("\"{p}{b}\"");
                }
                if weak.is_empty()
                    && let Some(s) = WEAK_AFTER.iter().find(|s| after.starts_with(s.as_bytes()) && !alnum(after.get(s.len())))
                {
                    weak = format!("\"{b}{s}\"");
                }
            }
        }
        if !html {
            continue;
        }
        let shown: Vec<u8> = HEADINGS
            .iter()
            .flat_map(|t| elements(&text, t))
            .chain(ATTRS.iter().flat_map(|a| attr_values(&text, a)))
            .collect::<Vec<_>>()
            .join(&b' ');
        if prominent.is_empty() {
            prominent = brands.iter().find(|b| has_word(&shown, b)).map(|b| b.to_string()).unwrap_or_default();
        }
        if prominent.is_empty() {
            let srcs = attr_values(&text, "src=");
            prominent = brands
                .iter()
                .find(|b| srcs.iter().any(|v| contains(v, "logo") && has_word(&spaced(v, b"-_./"), b)))
                .map(|b| b.to_string())
                .unwrap_or_default();
        }
        if mention.is_empty() {
            let visible = visible_text(&text);
            // "Sign in with Google" is a button for another provider, not an imitation of it.
            mention = brands
                .iter()
                .find(|b| {
                    !AMBIGUOUS.contains(b) && word_at(&visible, b).iter().any(|&at| !visible[at.saturating_sub(5)..at].ends_with(b"with "))
                })
                .map(|b| b.to_string())
                .unwrap_or_default();
        }
        for i in all(&text, "<form") {
            let end = find(&text, b">", i).map_or(text.len(), |e| e + 1);
            // `action = "x"` reads as `action="x"`.
            let mut tag = Vec::with_capacity(end - i);
            let raw_tag = &text[i..end];
            let mut k = 0;
            while k < raw_tag.len() {
                let c = raw_tag[k];
                if c == b' ' && raw_tag.get(k + 1) == Some(&b'=') {
                    k += 1;
                    continue;
                }
                tag.push(c);
                if c == b'=' && raw_tag.get(k + 1) == Some(&b' ') {
                    k += 1;
                }
                k += 1;
            }
            for v in attr_values(&tag, "action=") {
                if let Some(host) = form_host(&v)
                    && !forms.contains(&host)
                {
                    forms.push(host);
                }
            }
        }
    }

    let mut reasons = Vec::new();
    let mut score = 0;
    if password {
        reasons.push("a password field".to_string());
    }
    if card {
        reasons.push("card number or security code fields".to_string());
    }
    if !prominent.is_empty() {
        score += 2;
        reasons.push(format!("the brand \"{prominent}\" in the page title, a heading, a label or a logo"));
    }
    if !strong.is_empty() {
        score += 3;
        reasons.push(format!("sign-in words next to a brand ({strong})"));
    } else if !weak.is_empty() {
        score += 2;
        reasons.push(format!("a brand account name ({weak})"));
    }
    // A brand already counted for the title or a heading is not counted again for being in the text.
    if !mention.is_empty() && mention != prominent {
        score += 1;
        reasons.push(format!("the brand \"{mention}\" in the page text"));
    }
    if !phrases.is_empty() {
        score += phrases.len().min(2) as i64;
        let quoted: Vec<String> = phrases.iter().take(3).map(|p| format!("\"{p}\"")).collect();
        reasons.push(format!("the words {}", quoted.join(", ")));
    }
    if !forms.is_empty() {
        score += 2;
        reasons.push(format!(
            "a form that sends what is typed to another site ({})",
            forms.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if !exfil.is_empty() {
        score += 3;
        reasons.push(exfil);
    }
    if !ip_lookup.is_empty() {
        score += 1;
        reasons.push(format!("a lookup of the visitor's IP address ({ip_lookup})"));
    }
    let (seed_ask, wallet) = (seed && input, wallet_ask && wallet_act);
    if seed_ask {
        reasons.push("a prompt for a wallet seed or recovery phrase".into());
    }
    if wallet {
        reasons.push("a prompt to connect a crypto wallet to claim, sync or restore it".into());
    }
    if obfuscated {
        reasons.push("a page that writes itself from an encoded string, as phishing kits do to hide from scanners".into());
    }
    let flagged = obfuscated || seed_ask || wallet || ((password || card) && score >= THRESHOLD);
    Scan { flagged, score, reasons: if flagged { reasons } else { Vec::new() } }
}

#[cfg(test)]
mod tests {
    // The same cases as test/scan.test.ts. No test here imitates a real sign-in page.
    use super::*;

    const BRANDS: &[&str] = &["examplebank", "example mail"];
    const PASSWORD: &str = "<input type=\"password\" name=\"p\">";

    fn scan(files: &[(&str, &str)]) -> Scan {
        scan_with(&bundle(files), BRANDS)
    }
    fn bundle(files: &[(&str, &str)]) -> Vec<BundleFile> {
        files.iter().map(|(p, s)| BundleFile { path: p.to_string(), bytes: s.as_bytes().to_vec() }).collect()
    }

    #[test]
    fn flags_a_password_field_with_a_brand_in_the_title_and_a_verification_phrase() {
        let r = scan(&[("index.html", &format!("<title>ExampleBank</title><p>Verify your account</p>{PASSWORD}"))]);
        assert!(r.flagged);
        assert_eq!(r.score, 3);
        assert_eq!(
            r.reasons,
            [
                "a password field",
                "the brand \"examplebank\" in the page title, a heading, a label or a logo",
                "the words \"verify your account\""
            ]
        );
    }

    #[test]
    fn flags_sign_in_words_next_to_a_brand() {
        let r = scan(&[("index.html", &format!("<p>Sign in to your  examplebank account</p>{PASSWORD}"))]);
        assert!(r.flagged);
        assert!(r.reasons.contains(&"sign-in words next to a brand (\"sign in to your examplebank\")".to_string()));
    }

    #[test]
    fn flags_a_password_form_that_posts_to_another_site() {
        let r = scan(&[(
            "index.html",
            &format!("<form action=\"https://collector.example.net/x\">{PASSWORD}</form><p>Verify your account</p>"),
        )]);
        assert!(r.flagged);
        assert!(r.reasons.contains(&"a form that sends what is typed to another site (collector.example.net)".to_string()));
    }

    #[test]
    fn flags_card_fields_with_code_that_posts_to_a_chat_bot() {
        let r = scan(&[("index.html", "<input name=\"cvv\">"), ("app.js", "fetch('https://api.telegram.org/bot1/sendMessage')")]);
        assert!(r.flagged);
        assert_eq!(r.reasons, ["card number or security code fields", "code that sends data to a Telegram bot"]);
    }

    #[test]
    fn flags_a_seed_phrase_prompt_and_a_page_written_from_an_encoded_string_on_their_own() {
        assert!(scan(&[("index.html", "<p>Enter your recovery phrase</p><textarea></textarea>")]).flagged);
        assert!(scan(&[("index.html", "<script>document.write(atob(\"PHA+\"))</script>")]).flagged);
    }

    #[test]
    fn reads_a_brand_from_a_logo_file_name() {
        let html = format!("{PASSWORD}<p>Verify your account</p>");
        assert!(scan(&[("index.html", &html), ("img/examplebank-logo.svg", "<svg/>")]).flagged);
    }

    #[test]
    fn leaves_an_internal_tools_own_login_form_alone() {
        let r = scan(&[(
            "index.html",
            &format!(
                "<title>Stock room</title><h1>Sign in</h1><form action=\"/login\"><input name=\"user\">{PASSWORD}<button>Sign in</button></form>"
            ),
        )]);
        assert_eq!(r, Scan { flagged: false, score: 0, reasons: vec![] });
    }

    #[test]
    fn leaves_a_sign_in_with_google_button_next_to_a_login_form_alone_with_the_real_brand_list() {
        let r =
            scan_bundle(&bundle(&[("index.html", &format!("<title>Team notes</title><button>Sign in with Google</button>{PASSWORD}"))]));
        assert!(!r.flagged);
        assert_eq!(r.score, 0);
    }

    #[test]
    fn leaves_a_newsletter_form_that_posts_elsewhere_alone() {
        let r = scan(&[(
            "index.html",
            "<title>ExampleBank news</title><form action=\"https://letters.example.org/join\"><input type=\"email\" placeholder=\"Your email\"></form>",
        )]);
        assert!(!r.flagged);
    }

    #[test]
    fn needs_more_than_a_brand_name_next_to_a_password_field() {
        let r = scan(&[("index.html", &format!("<title>ExampleBank</title>{PASSWORD}"))]);
        assert!(!r.flagged);
        assert_eq!(r.score, 2);
    }

    #[test]
    fn compacts_attributes_the_same_way_as_the_typescript() {
        assert_eq!(compact("type = \"password\"  name"), "type=password name");
        assert_eq!(compact("{ type: \\\"password\\\" }"), "{type:password}");
    }
}
