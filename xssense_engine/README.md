<p align="center">   
 <img src="images/logo.png" height="200"><br/>
A Brutal Hybrid XSS scanner made in Python + Rust<br/>

## Installing

Requirements: <br/>

* Python 3.10+
* Rust Toolchain (Rustc & Cargo)

Commands:

```bash
# 1. Clone the repository
git clone https://github.com/SatriaDivo/XSSense.git
chmod +x -R XSSense
cd XSSense

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build the Rust Engine (xssense_engine)
cd xssense_engine
maturin build --release
pip install target/wheels/xssense_engine-0.1.0-*

# 4. Run!
cd ..
python xssense.py --help
```

## Usage
Basic usage:

```bash
python xssense.py -u http://testphp.vulnweb.com
```

Advanced usage (with External Wordlist payload):

```bash
python xssense.py -u http://testphp.vulnweb.com --wordlist payloads.txt --depth 3
```

## Main features

* Blazing Fast Crawler Engine (Powered by Rust Tokio + Async)
* Brutal Batch Scanning (Shoot Hundreds of Payloads Parallelly in Rust 🚀)
* Support external Wordlist payloads (`--wordlist`).
* POST and GET forms are fully supported
* Customizable settings (Proxy, Cookies, User-Agent)
* Automated Regex Link scraping in backend.

## Roadmap & Updates

**v1.0 (The Rust Awakening) [April 6, 2026]**:
* Migrated Crawler Engine to Rust Async (Tokio).
* Added Batch Asynchronous Injection support for massive GET Payloads in Rust memory.
* Custom external wordlist support added (`--wordlist`).
* Fixed Regex Escape characters in python strings.

**v0.5**:
* Added cookie support, Bug fixes

## Warning
* Do not use this tool on a website where you do not have permission. We take no responsibility for the damage caused by this tool.
* Note: Output doesn`t support DOM XSS rendering yet.
