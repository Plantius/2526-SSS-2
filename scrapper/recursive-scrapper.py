import glob
import json
import logging
import os
import re
import time

import dotenv
import nltk
import requests
from nltk.tokenize import RegexpTokenizer
from sklearn.feature_extraction.text import TfidfVectorizer

import utils.database as db
from utils.enums import *
from utils.tools import gh_url_to_raw

# Ensure that NLTK tokens are downloaded
nltk.download("punkt")

# if not os.path.exists("downloads"):
#     os.mkdir("downloads")

dotenv.load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SEARCH_API_URL = "https://api.github.com/search/code"
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
REPOS = []
REPO_DETAILS = {}
TRIED_QUERIES = set()
PAGE_SIZE = 100
MAX_PAGES = 10
MIN_GITHUB_STARS = int(os.getenv("MIN_GITHUB_STARS", 200))

# Base query focused on SQL injection input vectors
BASE_QUERY = "$_GET OR $_POST OR $_REQUEST OR $_COOKIE"

# SQL-related keywords and functions for boosting in TF-IDF
SQL_INDICATORS = [
    "mysqli_query",
    "mysql_query",
    "mysqli_real_query",
    "mysql_unbuffered_query",
    "mysql_db_query",
    "mysqli_multi_query",
    "pg_query",
    "pg_send_query",
    "sqlite_query",
    "sqlite_exec",
    "oci_parse",
    "oci_execute",
    "query",
    "multi_query",
    "real_query",
    "exec",
    "prepare",
    "execute",
    "wpdb",
    "get_results",
    "get_row",
    "get_var",
    "select",
    "insert",
    "update",
    "delete",
    "where",
    "from",
    "join",
    "concat",
    "mysqli_real_escape_string",
    "mysql_real_escape_string",
    "sprintf",
    "vsprintf",
    "implode",
]

# Known SQL injection patterns - Phase 1 searches
SQL_INJECTION_QUERIES = [
    # Direct MySQL/MySQLi functions with user input
    "mysqli_query $_GET",
    "mysqli_query $_POST",
    "mysql_query $_GET",
    "mysql_query $_POST",
    "mysqli_real_query $_POST",
    "mysql_unbuffered_query $_GET",
    # PostgreSQL
    "pg_query $_GET",
    "pg_query $_POST",
    # SQLite
    "sqlite_query $_POST",
    # WordPress database class
    "wpdb query $_GET",
    "wpdb query $_POST",
    "wpdb get_results $_POST",
    # Object-oriented query methods
    "->query $_GET",
    "->query $_POST",
    "->exec $_POST",
    # SQL keywords with user input (concatenation patterns)
    "SELECT $_GET",
    "SELECT $_POST",
    "WHERE $_GET",
    "WHERE $_POST",
    "INSERT $_POST",
    "UPDATE $_POST",
    "DELETE $_GET",
    # String concatenation patterns (classic SQLi indicators)
    '". $_GET',
    '". $_POST',
    "'. $_GET",
    "'. $_POST",
]


def tokenize_code(content):
    """
    Tokenize PHP code while preserving SQL injection-relevant patterns.
    Captures SQL keywords, string concatenation, PHP variables, and function calls.
    """
    # Patterns to preserve
    function_call = r"\w+\s*\("
    php_superglobal = r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\["
    php_variable = r"\$\w+"
    sql_keyword = r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|UNION|ORDER|GROUP|LIMIT|OFFSET)\b"
    string_concat = r'"\s*\.\s*|' + r"'\s*\.\s*"
    object_method = r"->\w+\s*\("

    # Combine all patterns
    combined = f"({sql_keyword}|{function_call}|{php_superglobal}|{php_variable}|{object_method}|{string_concat}|\w+)"
    tokenizer = RegexpTokenizer(combined)
    tokens = tokenizer.tokenize(content)

    # Filter out common PHP keywords that don't indicate vulnerabilities
    php_keywords = {
        "if",
        "else",
        "elseif",
        "endif",
        "for",
        "foreach",
        "endforeach",
        "while",
        "endwhile",
        "do",
        "switch",
        "case",
        "default",
        "break",
        "continue",
        "function",
        "return",
        "class",
        "interface",
        "trait",
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "const",
        "var",
        "true",
        "false",
        "null",
        "this",
        "self",
        "parent",
        "new",
        "clone",
        "try",
        "catch",
        "finally",
        "throw",
        "extends",
        "implements",
        "namespace",
        "use",
        "as",
        "echo",
        "print",
        "die",
        "exit",
        "require",
        "include",
        "require_once",
        "include_once",
        "array",
        "list",
        "empty",
        "isset",
        "unset",
        "and",
        "or",
        "xor",
        "instanceof",
        "insteadof",
        "global",
        "declare",
        "enddeclare",
    }

    return [t for t in tokens if t.lower() not in php_keywords]


def compute_tfidf(directory_path):
    """
    Compute TF-IDF for SQL injection vulnerable code sections.
    Optimized for short code snippets (vulnerable sections, not full files).
    """
    vectorizer = TfidfVectorizer(
        tokenizer=tokenize_code,
        lowercase=True,
        binary=False,  # Keep frequency information
        ngram_range=(1, 4),  # Capture longer patterns like "WHERE id = $_GET"
        max_features=400,
        min_df=1,  # Vulnerable sections might be unique
        max_df=0.95,  # Ignore terms that appear in >95% of documents
    )

    file_contents = []
    skipped = 0

    for filename in glob.glob(os.path.join(directory_path, "*.php")):
        if os.path.isfile(filename):
            with open(filename, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
                line_count = len(content.split("\n"))

                # Only process small snippets (vulnerable sections)
                if line_count < 100:
                    file_contents.append(content)
                else:
                    skipped += 1

    if skipped > 0:
        logging.info(
            f"Skipped {skipped} files (>100 lines, likely full files not vulnerable sections)"
        )

    if not file_contents:
        logging.warning(f"No suitable PHP files found in {directory_path}")
        return []

    if len(file_contents) < 2:
        logging.warning(
            f"Only {len(file_contents)} file(s) found - TF-IDF works best with multiple samples"
        )

    # Fit the TF-IDF model
    tfidf_matrix = vectorizer.fit_transform(file_contents)

    # Sum TF-IDF scores across all documents
    sums = tfidf_matrix.sum(axis=0)

    # Map terms to their aggregate scores
    terms = vectorizer.get_feature_names_out()
    scores = [(term, sums[0, idx]) for term, idx in zip(terms, range(sums.shape[1]))]

    # Boost SQL injection-relevant terms
    boosted_scores = []
    for term, score in scores:
        boost = 1.0

        # Strong boost for SQL functions/keywords
        if any(indicator in term.lower() for indicator in SQL_INDICATORS):
            boost = 4.0

        # Extra boost for patterns combining user input + SQL
        if "$_" in term and any(
            sql in term.lower()
            for sql in ["query", "select", "where", "insert", "update", "delete"]
        ):
            boost = 5.0

        # Boost string concatenation patterns (high SQLi risk)
        if "." in term and "$" in term:
            boost = 3.5

        boosted_scores.append((term, score * boost))

    # Sort by boosted score
    boosted_scores.sort(key=lambda x: x[1], reverse=True)

    # Filter out base query terms
    base_query_terms = {t.strip().lower() for t in BASE_QUERY.replace("OR", "").split()}
    filtered_scores = [
        item for item in boosted_scores if item[0].lower() not in base_query_terms
    ]

    return filtered_scores


def has_sqli_pattern(content):
    """
    Heuristic check if PHP code likely contains SQL injection vulnerability.
    Returns True if code shows patterns of user input flowing into SQL queries.
    """
    # Must have user input
    has_input = re.search(r"\$_(GET|POST|REQUEST|COOKIE)", content)
    if not has_input:
        return False

    # Check for SQL query execution functions
    has_query_func = re.search(
        r"\b(mysqli_query|mysql_query|pg_query|sqlite_query|wpdb.*query)\s*\(",
        content,
        re.IGNORECASE,
    )

    # Check for object method queries
    has_method_query = re.search(r"->(query|exec|multi_query|real_query)\s*\(", content)

    # Check for SQL keywords
    has_sql_keywords = re.search(
        r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b", content, re.IGNORECASE
    )

    # Check for dangerous concatenation patterns
    has_concat = re.search(r'["\'].*?\.\s*\$_(GET|POST|REQUEST|COOKIE)', content)

    # Check if using prepared statements (good practice - likely safe)
    has_prepare = re.search(r"\bprepare\s*\(", content, re.IGNORECASE)
    has_bind = re.search(
        r"\bbind(param|value|_param|_result)\s*\(", content, re.IGNORECASE
    )

    # If properly using prepared statements throughout, probably safe
    if has_prepare and has_bind and not has_concat:
        return False

    # Positive indicators: user input + (SQL function OR SQL keywords OR concatenation)
    return has_input and (
        has_query_func or has_method_query or has_sql_keywords or has_concat
    )


def make_safe_filename(s):
    """Create a safe filename by replacing invalid characters."""
    return re.sub(r"[^a-zA-Z0-9_\.-]", "_", s)


def get_rate_limit_reset_time(headers):
    """Extract rate limit reset time from response headers."""
    return int(headers.get("X-RateLimit-Reset", 0))


def get_repo_details(repo_api_url):
    """Get repository details including star count."""
    response = requests.get(repo_api_url, headers=HEADERS)
    return response.json()


def get_rate_limit_remaining(headers):
    """Extract remaining rate limit from response headers."""
    return int(headers.get("X-RateLimit-Remaining", 0))


def search_code(query, page, items):
    """
    Search for PHP code snippets with pagination and rate limit handling.
    """
    logging.info(f"  Searching page {page} for: {query}")
    params = {"q": f"language:PHP {query}", "per_page": PAGE_SIZE, "page": page}

    try:
        response = requests.get(SEARCH_API_URL, headers=HEADERS, params=params)
        response.raise_for_status()

        results = response.json()
        items.extend(results.get("items", []))

        # Handle rate limiting
        rate_limit_remaining = get_rate_limit_remaining(response.headers)
        if rate_limit_remaining <= 1:
            reset_time = get_rate_limit_reset_time(response.headers)
            sleep_time = reset_time - time.time() + 5
            if sleep_time > 0:
                logging.info(
                    f"  Rate limit reached. Sleeping for {int(sleep_time)}s..."
                )
                time.sleep(sleep_time)

        # Check if there are more pages
        if page < MAX_PAGES and "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            has_next = any('rel="next"' in link for link in links)
            if has_next:
                search_code(query, page + 1, items)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            logging.warning("  Rate limit hit (403), sleeping 60s...")
            time.sleep(60)
            search_code(query, page, items)
        else:
            logging.error(f"  HTTP error: {e}")
    except Exception as e:
        logging.error(f"  Search error: {e}")
        time.sleep(5)


def find_repos(query, keyword_index, keywords):
    """
    Find repositories matching query. If results are maxed out, recursively
    refine with additional keywords.
    """
    items = []
    search_code(query, 1, items)

    if len(items) == 0:
        logging.info(f"  No results for query")
        return items

    logging.info(f"  Found {len(items)} items")

    # If we maxed out results, refine the query with next keyword
    if len(items) >= (PAGE_SIZE * MAX_PAGES) and keyword_index < len(keywords):
        logging.info(f"  Results maxed out, refining query...")

        # Find next unused keyword
        next_keyword = None
        for i in range(keyword_index, len(keywords)):
            candidate = keywords[i][0]
            refined_query = f"{query} {candidate}"

            # Skip if we've already tried this query
            if refined_query not in TRIED_QUERIES:
                next_keyword = candidate
                keyword_index = i
                break

        if next_keyword:
            refined_query = f"{query} {next_keyword}"
            TRIED_QUERIES.add(refined_query)
            # Recursively search with refined query
            refined_items = find_repos(refined_query, keyword_index + 1, keywords)
            items.extend(refined_items)

    return items


def save_state():
    """Save current state to JSON file."""
    with open("./state.json", "w") as f:
        json.dump(
            {
                "REPOS": REPOS,
                "REPO_DETAILS": REPO_DETAILS,
                "TRIED_QUERIES": list(TRIED_QUERIES),
            },
            f,
            indent=2,
        )


def read_state():
    """Load state from JSON file if it exists."""
    if not os.path.isfile("./state.json"):
        return

    global REPOS, REPO_DETAILS, TRIED_QUERIES
    with open("./state.json", "r") as f:
        data = json.load(f)
        REPOS = data.get("REPOS", [])
        REPO_DETAILS = data.get("REPO_DETAILS", {})
        TRIED_QUERIES = set(data.get("TRIED_QUERIES", []))


def download_file(url, path, proj_id):
    """Download a file from GitHub and save locally."""
    db.change_project_step(proj_id, STEP_CLONING)

    try:
        # response = requests.get(url, headers=HEADERS)
        # response.raise_for_status()

        # with open(f"./downloads/{path}", "wb") as f:
        #     f.write(response.content)

        db.update_filename(proj_id, path)
        db.change_project_step(proj_id, STEP_CLONED)
        logging.info(f"  Downloaded: {path}")

    except requests.exceptions.HTTPError as e:
        db.pause_project(proj_id, PAUSED_HTTP_CLONE_FAILED)
        logging.error(f"  Failed to download {path}: HTTP {e.response.status_code}")
    except Exception as error:
        db.pause_project(proj_id, PAUSED_CLONE_FS_SAVE_FAILED)
        logging.error(f"  Failed to save {path}: {error}")


def pass_to_db(repo):
    """
    Process a repository: check stars, verify SQLi pattern, and download.
    """
    repo_details = REPO_DETAILS[repo]
    repo_api_url = repo_details["repository"]["url"]

    # Get repository metadata
    try:
        repo_data = get_repo_details(repo_api_url)
        stars = repo_data.get("stargazers_count", 0)
    except Exception as e:
        logging.error(f"  Failed to get repo details for {repo}: {e}")
        return

    if stars < MIN_GITHUB_STARS:
        logging.debug(
            f"  Skipping {repo}: only {stars} stars (min: {MIN_GITHUB_STARS})"
        )
        return

    # Prepare file details
    file_path = os.path.basename(repo_details["path"])
    name_with_owner = repo_details["repository"]["full_name"]
    filename = make_safe_filename(f"{name_with_owner}-{file_path.split('/')[-1]}")
    download_url = gh_url_to_raw(repo_details["html_url"])

    # Verify file contains SQLi pattern before adding
    try:
        response = requests.get(download_url, headers=HEADERS)
        response.raise_for_status()
        content = response.text

        if not has_sqli_pattern(content):
            logging.info(f"  Skipping {filename}: no SQL injection pattern detected")
            return

    except Exception as e:
        logging.warning(f"  Could not verify pattern for {filename}: {e}")
        return

    # Add to database and download
    logging.info(f"  Adding to database: {name_with_owner}")
    pending_project_id = db.add_project(name_with_owner, download_url, stars)
    # download_file(download_url, filename, pending_project_id)


def main():
    """
    Main workflow:
    1. Search with known SQL injection patterns
    2. Compute TF-IDF from downloaded vulnerable sections
    3. Search with TF-IDF keywords for discovery
    """
    read_state()

    # logging.info("=" * 70)
    # logging.info("PHP SQL INJECTION VULNERABILITY SEARCH")
    # logging.info("=" * 70)

    # # Phase 1: Known SQL injection patterns (primary method)
    # logging.info("\n[Phase 1] Searching with known SQL injection patterns...")
    # logging.info("-" * 70)

    # for i, vuln_query in enumerate(SQL_INJECTION_QUERIES, 1):
    #     logging.info(f"\n[{i}/{len(SQL_INJECTION_QUERIES)}] Query: {vuln_query}")
    #     TRIED_QUERIES.add(vuln_query)

    #     items = []
    #     search_code(vuln_query, 1, items)

    #     # Deduplicate by repository
    #     found = {}
    #     for item in items:
    #         repo_name = item["repository"]["full_name"]
    #         found[repo_name] = item

    #     # Process new repositories
    #     new_repos = 0
    #     for repo_name, repo_data in found.items():
    #         if repo_name not in REPOS:
    #             REPOS.append(repo_name)
    #             REPO_DETAILS[repo_name] = repo_data
    #             pass_to_db(repo_name)
    #             new_repos += 1

    #     logging.info(f"  New repos: {new_repos} | Total repos: {len(REPOS)}")
    #     save_state()
    #     time.sleep(2)  # Be nice to GitHub API

    # Phase 2: Compute TF-IDF from vulnerable sections
    logging.info("\n[Phase 2] Computing TF-IDF from downloaded vulnerable sections...")
    logging.info("-" * 70)

    keywords = compute_tfidf("../MoreFixes/output/")

    if not keywords:
        logging.warning("No TF-IDF keywords extracted. Ending here.")
        logging.info(f"\n{'=' * 70}")
        logging.info(f"COMPLETED: {len(REPOS)} total repositories found")
        logging.info(f"{'=' * 70}")
        return

    # Filter to high-scoring keywords
    keywords = [k for k in keywords if k[1] >= 0.3]
    logging.info(f"Extracted {len(keywords)} high-value SQL injection keywords")

    # Display top keywords
    for i, (keyword, score) in enumerate(keywords[:20], 1):
        logging.info(f"  {i:2d}. {keyword:40s} (score: {score:.3f})")

    # Phase 3: Search with TF-IDF keywords (discovery phase)
    logging.info("\n[Phase 3] Searching with TF-IDF keywords for discovery...")
    logging.info("-" * 70)

    top_keywords = keywords[:30]

    for i, (keyword, score) in enumerate(top_keywords, 1):
        query = f"{BASE_QUERY} {keyword}"

        # Skip if already tried
        if query in TRIED_QUERIES:
            continue

        logging.info(
            f"\n[{i}/{len(top_keywords)}] Keyword: '{keyword}' (score: {score:.3f})"
        )
        TRIED_QUERIES.add(query)

        try:
            items = find_repos(query, 0, keywords)

            # Deduplicate by repository
            found = {}
            for item in items:
                repo_name = item["repository"]["full_name"]
                found[repo_name] = item

            # Process new repositories
            new_repos = 0
            for repo_name, repo_data in found.items():
                if repo_name not in REPOS:
                    REPOS.append(repo_name)
                    REPO_DETAILS[repo_name] = repo_data
                    pass_to_db(repo_name)
                    new_repos += 1

            logging.info(f"  New repos: {new_repos} | Total repos: {len(REPOS)}")
            save_state()
            time.sleep(2)

        except Exception as e:
            logging.error(f"  Error processing keyword '{keyword}': {e}")

    # Final summary
    logging.info(f"\n{'='*70}")
    logging.info(f"COMPLETED: {len(REPOS)} total repositories with SQL injection patterns found")
    logging.info(f"{'='*70}")


if __name__ == "__main__":
    main()