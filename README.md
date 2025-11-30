# SQLsweePHPer
<p align="center">
<img alt="Image" src="pipelineflow.png" />
</p>

SQLsweePHPer is a tool that automates SQL injection vulnerability discovery in public repositories on GitHub.
At the moment, given documents, it produces strong keywords for GitHub search, allowing circumvention of its inherent limitations regarding number of results.
This allows the tool to discover a vast number of repositories that could contain vulnerabilities.
Once files are found within the scope of our interest, we run SemGrep to semantically consider whether these contain an actual vulnerability.
Future research could be automated proof-of-concept generation.

## 🔧 Installation

This program was developed and tested on **GNU/Linux**, and partially tested on **macOS**.  
**Windows/WSL are not tested nor recommended.** Running the project inside a docker container(DIND) is not recommended as this way the nested containers can bypass the sandbox.

Please read the instructions carefully before running the program, as incorrect usage may result in **spamming reports**.  

Requirements:  
- Docker and Docker Compose installed and available in your CLI.  
- Pipeline must run either as **root** (recommended for Docker commands), or with Docker accessible to the current user (⚠️ this may reduce security).  
- CodeQL and Semgrep must be installed.  

```bash
# Clone repo
git clone https://github.com/JafarAkhondali/DotDotDefender.git
cd DotDotDefender

# Configure environment variables
cp env.example .env
nano .env 

# Run database image
sudo docker-compose up -d

# Set up Python environment 
python3 -m venv venv

# Below 3 steps must be done for each time you want to run the code
source ./venv/bin/activate
export PYTHONPATH=$(pwd)
pip3 install -r requirements.txt

# Install CodeQL - https://github.com/github/codeql-action/releases
# Install SemGrep CLI - https://semgrep.dev/docs/cli-reference
```

## Usage

This program consists of several components. Each one is designed to run independently, contributing to the overall pipeline:

1. **Scraper**  
   Searches for specific patterns of vulnerable code using GitHub Code Search feature.  
   File: `scrapper/recursive-scrapper.py`

2. **Static Analysis**  
   Validates the vulnerability by running **SemGrep** with specific payloads.  
   File: `sast/grep.py`

3. **PoC Checker**  
   Executes the program with the payload.  
   - Must be run as **root** for Docker commands.  
   - There are 3 different PoC checkers — **all must be run** to complete this step:  
     - `run-poc-network.py`  
     - `run-poc-local.py`  
     - `run-poc-dos.py`

4. **Reporter (Scoring & Patching)**  
   - Calculates CVSS Score → `calculate_cvss_scores.py`  
   - Prepares a fix using GPT-4 → `patcher.py`

5. **Reporter (Verification & Patch Application)**  
   - Verifies the vulnerability still exists → `patcher.py`  
   - Applies a verified patch using an LLM.

6. **Pull Requester (Commit History)**  
   Retrieves the time when the first vulnerable commit appeared.  
   File: `add_first_appeared.py`

7. **Pull Requester (PR Submission)**  
   ⚠️ **Warning**: If you are testing, **DO NOT RUN** `run.py` - it will re-verify the patch and send an actual pull request.
   
## 🤝 Contributing
We welcome contributions to improve **SQLsweePHPer**! Morover you are more than welcome to maintain your own fork and research.

If you’d like to add features, fix bugs, or improve documentation, please follow these steps:  
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request

## License
Although the source code of this pipeline is free to use, parts related to SAST (SemGrep and CodeQL) may have **different licenses** depending on your usage.  It is the user’s responsibility to verify and comply with all applicable license agreements.  
