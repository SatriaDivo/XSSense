<p align="center">
  <img src="images/logo.png" alt="XSSense Logo" width="240" />
</p>

<h1 align="center">XSSense</h1>
<p align="center">Hybrid XSS scanner built with Python + Rust crawler engine.</p>

## Overview

XSSense helps you test reflected XSS points from:

- URL query parameters
- HTML forms (`GET` and `POST`)
- Optional fast crawler mode powered by Rust (`xssense_engine`)

## Requirements

- Python 3.10+
- `pip`
- Rust toolchain (`cargo`, `rustc`) only if you want crawler mode (`-u`)

## Install

```bash
git clone https://github.com/SatriaDivo/XSSense.git
cd XSSense
pip install -r requirements.txt
```

Enable Rust crawler engine:

```bash
cd xssense_engine
maturin develop --release
cd ..
```

You can still use non-crawler mode without Rust extension:

```bash
python xssense.py --help
python xssense.py --about
python xssense.py --single https://target.example/
```

## Usage

Single target scan (no crawling):

```bash
python xssense.py --single https://testphp.vulnweb.com
```

Scan with crawler mode:

```bash
python xssense.py -u https://testphp.vulnweb.com --depth 2
```

Use a custom payload:

```bash
python xssense.py --single https://testphp.vulnweb.com --payload "<script>alert(1)</script>"
```

Use payload wordlist:

```bash
python xssense.py -u https://testphp.vulnweb.com --wordlist payloads/payloads_reflected.txt --depth 3
```

## Payload Wordlists

Payload files are provided in the `payloads/` folder:

- `payloads_reflected.txt` for baseline reflected checks
- `payloads_aggressive.txt` for broader attack surface checks
- `payloads_waf_bypass.txt` for obfuscation/bypass attempts
- `payloads.txt` combined list

## Features

- Reflected XSS probing on query params and forms
- `GET` and `POST` form injection support
- External payload wordlist support via `--wordlist`
- Rust-based same-host link crawling
- Configurable cookie, proxy, user-agent, method, and depth

## Legal Notice

- Use only on systems you own or are authorized to test.
- DOM XSS detection is not implemented yet.

