# PendragonDI Cloud Audit

> **Find stale, oversized, or duplicate files in cloud storage — without touching your data.**

PendragonDI Cloud Audit is a lightweight command-line tool that helps you uncover hidden cost drivers in your cloud storage buckets:
- Unused or stale files
- Duplicate objects
- Oversized resources
- Cold data that hasn’t been touched in months

It runs **entirely locally** using your own credentials. No file content is ever read. No objects are ever modified.

---

## 🔍 Why It Exists

Most teams store more than they realize—and rarely clean up:

- ☁️ Cloud object stores are treated like infinite file systems
- 💸 Many orgs pay for **millions of forgotten or duplicate files**
- 🧱 Native tools are clunky, slow, or deeply integrated with billing

PendragonDI Cloud Audit gives you **a fast, metadata-only snapshot** of wasteful storage across AWS S3, Google Cloud Storage, and Azure Blob—**before it shows up on your invoice**.

---

## ✅ Features

- 🔍 Identifies stale files based on last-modified timestamp
- 🐘 Flags oversized files based on a size threshold you define
- 🪞 Detects potential duplicates using file size, name, and timestamp
- 🧾 Outputs clean, readable HTML or CSV reports
- 🧪 Supports limit-based sampling for fast iteration
- 🔐 Operates with your credentials — no external access required
- 🔒 Never reads, moves, or deletes content

---

## 🛠️ Installation

### Core CLI only (no provider):

```bash
pip install pendragondi-cloud-audit
````

### With a provider:

```bash
pip install pendragondi-cloud-audit[aws]
pip install pendragondi-cloud-audit[gcs]
pip install pendragondi-cloud-audit[azure]
pip install pendragondi-cloud-audit[all]  # for all providers
```

---

## 🚀 Quickstart

### 1. Run a scan:

```bash
pendragondi-cloud-audit scan aws my-bucket --days-stale 90 --output report.html
```

You can also limit the number of objects scanned:

```bash
pendragondi-cloud-audit scan gcs my-bucket --days-stale 60 --limit 10000 --output audit.csv
```

### 2. Find large files:

You can also flag files over a certain size. The following command flags all files over 100MB as oversized:

```bash
pendragondi-cloud-audit scan s3 my-important-bucket --oversized-mb 100
```

---

## 📄 Example Report

```html
Total Files: 3200 • Stale: 1800 • Duplicates: 400 • Oversized: 50
```

Results can be opened in any browser or spreadsheet tool.

---

## 🧰 Supported Providers

| Provider | Install Extra | Credential Method                  |
| -------- | ------------- | ---------------------------------- |
| AWS S3   | `aws`         | Boto3 profile / ENV                |
| GCS      | `gcs`         | Application Default / keyfile      |
| Azure    | `azure`       | Connection string or container URL |

---

## 🔐 Security & Compliance

PendragonDI Cloud Audit was built for **zero-risk analysis**:

| Layer          | Behavior                  |
| -------------- | ------------------------- |
| Access         | Uses your own credentials |
| Data Privacy   | Never reads file content  |
| Write Behavior | **Read-only** (no writes) |
| Output         | Local CSV or HTML report  |

---

## 📜 License

[MIT License](LICENSE)

---

## 🧭 Why PendragonDI?

Cloud billing surprises happen when small inefficiencies scale.
PendragonDI Cloud Audit was designed to help teams **see storage drift before it gets expensive**.

* No dashboard logins.
* No waiting on IT.
* Just insight.

---

## 🤝 Contributing

We welcome contributions!

To contribute:

* Fork this repo and work from `main`
* Use type hints and docstrings
* Submit focused pull requests
* Report bugs or ideas via [Issues](https://github.com/PendragonDI/pendragondi-cloud-audit/issues)

Questions or feedback? Email us: [pendragondi@pendragondi.dev](mailto:pendragondi@pendragondi.dev)

---

## 💖 Support the Project

PendragonDI Cloud Audit is free and open-source.
If this tool saved you time or money, consider supporting us on GitHub:

[![Sponsor on GitHub](https://img.shields.io/badge/Sponsor-💖-pink?style=flat)](https://github.com/sponsors/jinpendragon)
