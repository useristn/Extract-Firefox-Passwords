# Extract Firefox Passwords

## Team Members

[![Team](https://img.shields.io/badge/Team-Firefox%20Extractors-blueviolet?style=flat-square&logo=firefox-browser)](https://github.com/useristn/Extract-Firefox-Passwords)

| Name                  | Student ID |
|-----------------------|------------|
| Nguyen Thanh Nhat     | 23162072   |
| Truong Xuan Nhat      | 23162073   |
| Ngo Tuan Phat         | 23162075   |
| Le Van Anh Thong      | 23162097   |

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/useristn/Extract-Firefox-Passwords.git
cd Extract-Firefox-Passwords
```

### 2. Create and Activate a Virtual Environment

#### On Windows:
```bash
python -m venv venv

# Open Git Bash and use
source venv/bin/activate

# Or use depending on the computer
source venv/Scripts/activate
```

### 3. Install required libraries

```bash
pip install -r requirements.txt
```

## Usage Guide

### Generate Custom Wordlists

#### Basic Usage:

```bash
python generator.py
```

### Extract Passwords

#### Basic Usage:
```bash
python extractor.py
```

#### Select other Profile
```bash
python extractor.py -d <path_to_profile>
```

#### If a Primary Password is Set:
```bash
python extractor.py -d <path_to_profile> -p <primary_password>
```

#### Brute-Force Primary Password:
```bash
python extractor.py -d <path_to_profile> -f <path_to_wordlist>
```