# VulnerabilityAgent 🛡️

An autonomous BeeAI agent built on the [BeeAI Framework](https://github.com/i-am-bee/beeai-framework) and [AgentStack](https://github.com/i-am-bee/agentstack) that scans a GitHub repository's Python dependencies for known vulnerabilities and files remediation issues on your behalf. 

![Agent workflow overview](img/img.png)

## Purpose
- Detect vulnerable packages declared in `uv.lock` files.
- Cross-reference dependencies against the Sonatype OSS Index to surface known CVEs.
- Draft and file GitHub issues describing each finding and the recommended remediation.

## Prerequisites
- Python 3.13 or newer.
- [uv](https://docs.astral.sh/uv/) (recommended) or another tool for managing virtual environments.
- [BeeAI platform](https://docs.beeai.dev/introduction/quickstart) and CLI.
- Access to the following external services:
  - GitHub account that can create Personal Access Tokens.
  - Sonatype OSS Index account (free).
  - LLM provider credentials (tested with `openai/gpt-4.1-mini` via Agent Stack Platform).

## Install Dependencies
```bash
# Clone and enter the project
git clone https://github.com/sandijean90/VulnerabilityAgent.git
cd VulnerabilityAgent

# Create the environment and install dependencies
uv sync          # preferred
# or: uv pip install -e .
# or: python -m venv .venv && source .venv/bin/activate && pip install -e .
```

## Required Secrets
All secrets can be provided through the BeeAI UI when prompted, or stored in a local `.env` file for development. Never commit real credentials.

- **GitHub Personal Access Token (`GITHUB_PAT`)**
  - Go to [https://github.com/settings/tokens](https://github.com/settings/tokens).
  - Create a classic token with the `repo` scope (minimum: `repo:status`, `public_repo`, and `repo_deployment` if you expect to work with private repositories).
  - Copy the token for later; GitHub only shows it once.

- **OSS Index Credentials (`OSS_INDEX_API`, `OSS_INDEX_EMAIL`)**
  - Register or sign in at [https://ossindex.sonatype.org](https://ossindex.sonatype.org).
  - Navigate to *Account* → *API Tokens* and generate a token.
  - Use your account email for `OSS_INDEX_EMAIL` and the generated token for `OSS_INDEX_API`.

- **LLM Provider (OpenAI recommended)**
  - In the BeeAI UI, set your preferred provider and supply the API key.
  - If running locally, you can export `OPENAI_API_KEY` (or the equivalent for your provider) before starting the agent.

For local testing outside Agent Stack, create a `.env` file with the variables above and load it before running `main.py` (e.g., `export $(cat .env | xargs)` in shells that support it). This may require some code modification as the main.py file is meant to read secrets from the Agent Stack Platform.

## Running the Agent (main entry point only)
1. Start the Agent Stack platform with observability (optional but recommended):
   ```bash
   beeai platform start --set phoenix.enabled=true
   ```
2. Launch the BeeAI UI in a new terminal to configure your LLM provider and secrets:
   ```bash
   beeai ui
   ```
3. Run the agent service from this repository (this is the only executable entry point you need):
   ```bash
   uv run src/agents/main.py
   ```
4. In the Agent Stack UI, select the **Dependency Defender** agent. Submit the form with:
   - `Repo URL` – the public GitHub repository you want to scan.
   - `Github Issue Style` – choose `concise` or `detailed` to control the generated issue format.
   - Accept the terms checkbox.

The agent orchestrates all tool calls, streams progress through trajectories, and posts a final summary with citation metadata.

### Sample Repositories for Dry Runs
- [KenOcheltree/bad-repo](https://github.com/KenOcheltree/bad-repo) – contains vulnerable dependencies to exercise issue creation.
- [KenOcheltree/good-repo](https://github.com/KenOcheltree/good-repo) – clean baseline to validate the “no vulnerabilities found” path.

## How the System Works
1. **Form Intake** – The agent receives the repository URL and preferred issue style through the Agent stack form extension.
2. **Secret Retrieval** – Agent Stack secrets extension supplies the GitHub PAT and OSS Index credentials on demand.
3. **Tool Preparation** – Through Agent Stack, the agent builds repository-scoped MCP tools for creating issues, then instantiates the dependency reader and vulnerability scanner.
4. **Dependency Extraction** – `GitHubUvLockReaderURLMinimal` locates every `uv.lock` file in the target repository and returns a normalized list of packages.
5. **Vulnerability Scan** – `OSSIndexFromContextTool` batches the package list into Sonatype OSS Index queries and captures CVE data.
6. **Issue Creation** – When vulnerabilities exist, the agent drafts GitHub issues (concise or detailed) and files them via the MCP GitHub issue tool.
7. **Final Report** – The agent streams its reasoning, emits citation metadata for every link, and stores a final message summarizing the findings.

## Relevant Modules
- `src/agents/main.py` – Registers the **Dependency Defender** agent on BeeAI Framework + Agent Stack, orchestrates tool calls, manages session memory, and streams output.
- `src/agents/fetch_dependencies_tool.py` – GitHub UV lock reader tool that extracts dependency metadata from `uv.lock`.
- `src/agents/dependency_search_tool.py` – OSS Index integration that converts packages into PURLs and fetches vulnerability reports with retry logic.
- `src/agents/utils.py` – Utility helpers for wrapping MCP tools to a specific repository and shared session management.
- `src/agents/session_manager.py` – Maintains the MCP HTTP session required for GitHub issue management tools.
- Coming soon
    - `src/agents/github_issue_writer_agent.py` – Secondary agent that renders a single GitHub issue payload from structured vulnerability data (Not used in current version- ).

## Next Steps
- Review the BeeAI traces at [http://localhost:6006](http://localhost:6006) (Phoenix) to audit each tool call.
- Check the analyzed repo for new issues created by the Vulnerability Agent.
