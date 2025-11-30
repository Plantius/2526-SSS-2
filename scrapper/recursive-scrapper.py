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
    'mysqli_query', 'mysql_query', 'mysqli_real_query', 'mysql_unbuffered_query',
    'mysql_db_query', 'mysqli_multi_query', 'pg_query', 'pg_send_query',
    'sqlite_query', 'sqlite_exec', 'oci_parse', 'oci_execute',
    'query', 'multi_query', 'real_query', 'exec', 'prepare', 'execute',
    'wpdb', 'get_results', 'get_row', 'get_var',
    'select', 'insert', 'update', 'delete', 'where', 'from', 'join',
    'concat', 'mysqli_real_escape_string', 'mysql_real_escape_string',
    'sprintf', 'vsprintf', 'implode'
]

# Known SQL injection pattern bases (will be combined with TF-IDF keywords)
SQL_INJECTION_PATTERN_BASES = [
    # Direct MySQL/MySQLi functions
    "mysqli_query",
    "mysql_query",
    "mysqli_real_query",
    "mysql_unbuffered_query",
    
    # PostgreSQL
    "pg_query",
    
    # SQLite
    "sqlite_query",
    
    # WordPress database class
    "wpdb query",
    "wpdb get_results",
    
    # Object-oriented query methods
    "->query",
    "->exec",
    
    # SQL keywords (concatenation patterns)
    "SELECT",
    "WHERE",
    "INSERT",
    "UPDATE",
    "DELETE",
    
    # String concatenation patterns
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
    # Patterns to preserve (using non-capturing groups (?:...) or no groups)
    function_call = r'\w+\s*\('
    php_superglobal = r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\['
    php_variable = r'\$\w+'
    sql_keyword = r'\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|UNION|ORDER|GROUP|LIMIT|OFFSET)\b'
    string_concat = r'"\s*\.\s*|' + r"'\s*\.\s*"
    object_method = r'->\w+\s*\('
    
    # Combine all patterns - use alternation without outer capturing group
    combined = f'{sql_keyword}|{function_call}|{php_superglobal}|{php_variable}|{object_method}|{string_concat}|\w+'
    tokenizer = RegexpTokenizer(combined)
    tokens = tokenizer.tokenize(content)
    
    # Ensure tokens are strings (flatten if needed)
    flat_tokens = []
    for token in tokens:
        if isinstance(token, tuple):
            # If it's a tuple, take the first non-empty element
            flat_tokens.append(next((t for t in token if t), ''))
        else:
            flat_tokens.append(token)
    
    # Filter out common PHP keywords that don't indicate vulnerabilities
    php_keywords = {
        'if', 'else', 'elseif', 'endif', 'for', 'foreach', 'endforeach',
        'while', 'endwhile', 'do', 'switch', 'case', 'default', 'break',
        'continue', 'function', 'return', 'class', 'interface', 'trait',
        'public', 'private', 'protected', 'static', 'final', 'abstract',
        'const', 'var', 'true', 'false', 'null', 'this', 'self', 'parent',
        'new', 'clone', 'try', 'catch', 'finally', 'throw', 'extends',
        'implements', 'namespace', 'use', 'as', 'echo', 'print', 'die',
        'exit', 'require', 'include', 'require_once', 'include_once',
        'array', 'list', 'empty', 'isset', 'unset', 'and', 'or', 'xor',
        'instanceof', 'insteadof', 'global', 'declare', 'enddeclare'
    }
    
    return [t for t in flat_tokens if t and t.lower() not in php_keywords]

    return [t for t, _, _ in tokens if t.lower() not in php_keywords]


def compute_tfidf(directory_path):
    """
    Compute TF-IDF for SQL injection vulnerable code sections.
    Returns keywords that can be combined with known SQL injection patterns.
    """
    vectorizer = TfidfVectorizer(
        tokenizer=tokenize_code,
        lowercase=True,
        binary=False,
        ngram_range=(1, 4),  # Capture longer patterns
        max_features=400,
        min_df=1,
        max_df=0.95,
    )

    file_contents = []
    skipped = 0

    for filename in glob.glob(os.path.join(directory_path, "*.php")):
        if os.path.isfile(filename):
            with open(filename, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
                line_count = len(content.split('\n'))
                
                # Only process small snippets (vulnerable sections)
                if line_count < 100:
                    file_contents.append(content)
                else:
                    skipped += 1

    if skipped > 0:
        logging.info(f"  Skipped {skipped} files (>100 lines)")

    if not file_contents:
        logging.warning(f"  No suitable PHP files found in {directory_path}")
        return []

    if len(file_contents) < 2:
        logging.warning(f"  Only {len(file_contents)} file(s) found - TF-IDF works best with multiple samples")

    # Fit the TF-IDF model
    tfidf_matrix = vectorizer.fit_transform(file_contents)
    sums = tfidf_matrix.sum(axis=0)
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
        if '$_' in term and any(sql in term.lower() for sql in ['query', 'select', 'where', 'insert', 'update', 'delete']):
            boost = 5.0
        
        # Boost string concatenation patterns
        if '.' in term and '$' in term:
            boost = 3.5
            
        boosted_scores.append((term, score * boost))

    # Sort by boosted score
    boosted_scores.sort(key=lambda x: x[1], reverse=True)
    
    # Filter out base query terms and known pattern bases
    base_query_terms = {t.strip().lower() for t in BASE_QUERY.replace('OR', '').split()}
    known_patterns = {p.lower() for p in SQL_INJECTION_PATTERN_BASES}
    
    filtered_scores = [
        item for item in boosted_scores 
        if item[0].lower() not in base_query_terms 
        and item[0].lower() not in known_patterns
    ]
    
    return filtered_scores


def has_sqli_pattern(content):
    """
    Heuristic check if PHP code likely contains SQL injection vulnerability.
    """
    has_input = re.search(r'\$_(GET|POST|REQUEST|COOKIE)', content)
    if not has_input:
        return False
    
    has_query_func = re.search(
        r'\b(mysqli_query|mysql_query|pg_query|sqlite_query|wpdb.*query)\s*\(',
        content,
        re.IGNORECASE
    )
    
    has_method_query = re.search(r'->(query|exec|multi_query|real_query)\s*\(', content)
    has_sql_keywords = re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b', content, re.IGNORECASE)
    has_concat = re.search(r'["\'].*?\.\s*\$_(GET|POST|REQUEST|COOKIE)', content)
    
    # Check if using prepared statements properly
    has_prepare = re.search(r'\bprepare\s*\(', content, re.IGNORECASE)
    has_bind = re.search(r'\bbind(param|value|_param|_result)\s*\(', content, re.IGNORECASE)
    
    if has_prepare and has_bind and not has_concat:
        return False
    
    return has_input and (has_query_func or has_method_query or has_sql_keywords or has_concat)


def make_safe_filename(s):
    """Create a safe filename by replacing invalid characters."""
    return re.sub(r"[^a-zA-Z0-9_\.-]", "_", s)


def get_rate_limit_reset_time(headers):
    return int(headers.get("X-RateLimit-Reset", 0))


def get_repo_details(repo_api_url):
    response = requests.get(repo_api_url, headers=HEADERS)
    return response.json()


def get_rate_limit_remaining(headers):
    return int(headers.get("X-RateLimit-Remaining", 0))


def search_code(query, page, items):
    """
    Search for PHP code snippets with pagination and rate limit handling.
    """
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
                logging.info(f"    Rate limit reached. Sleeping for {int(sleep_time)}s...")
                time.sleep(sleep_time)
        
        # Check if there are more pages
        if page < MAX_PAGES and "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            has_next = any('rel="next"' in link for link in links)
            if has_next:
                search_code(query, page + 1, items)
                
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            logging.warning("    Rate limit hit (403), sleeping 60s...")
            time.sleep(60)
            search_code(query, page, items)
        else:
            logging.error(f"    HTTP error: {e}")
    except Exception as e:
        logging.error(f"    Search error: {e}")
        time.sleep(5)


def find_repos(query, keyword_index, keywords):
    """
    Find repositories matching query. If results are maxed out, recursively
    refine with additional keywords.
    """
    items = []
    search_code(query, 1, items)

    if len(items) == 0:
        logging.info("  No results for query")
        return items

    logging.info(f"  Found {len(items)} items")

    # If we maxed out results, refine the query with next keyword
    if len(items) >= (PAGE_SIZE * MAX_PAGES) and keyword_index < len(keywords):
        logging.info("  Results maxed out, refining query...")

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
        json.dump({
            "REPOS": REPOS,
            "REPO_DETAILS": REPO_DETAILS,
            "TRIED_QUERIES": list(TRIED_QUERIES),
        }, f, indent=2)


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


def add_to_db(repo):
    """
    Add repository to database after validation.
    No longer downloads files - just stores metadata.
    """
    repo_details = REPO_DETAILS[repo]
    repo_api_url = repo_details["repository"]["url"]
    
    # Get repository metadata
    try:
        repo_data = get_repo_details(repo_api_url)
        stars = repo_data.get("stargazers_count", 0)
    except Exception as e:
        logging.error(f"    Failed to get repo details for {repo}: {e}")
        return False

    if stars < MIN_GITHUB_STARS:
        return False

    # Prepare file details
    name_with_owner = repo_details["repository"]["full_name"]
    download_url = gh_url_to_raw(repo_details["html_url"])

    # Verify file contains SQLi pattern
    try:
        response = requests.get(download_url, headers=HEADERS)
        response.raise_for_status()
        content = response.text
        
        if not has_sqli_pattern(content):
            return False
            
    except Exception as e:
        logging.warning(f"    Could not verify pattern: {e}")
        return False

    # Add to database (no download)
    db.add_project(name_with_owner, download_url, stars)
    return True


def generate_combined_queries(tfidf_keywords, top_n_tfidf=30):
    """
    Generate queries by combining known SQL injection patterns with TF-IDF keywords.
    
    Strategy: For each known SQLi pattern, combine it with top TF-IDF keywords
    to create more specific and targeted queries.
    
    Example: "mysqli_query" + "username" -> "mysqli_query username"
    This finds code that uses mysqli_query with a username variable (likely vulnerable)
    """
    combined_queries = []
    
    # Take top N TF-IDF keywords
    top_keywords = [kw for kw, score in tfidf_keywords[:top_n_tfidf]]
    
    logging.info(f"  Generating queries from {len(SQL_INJECTION_PATTERN_BASES)} base patterns × {len(top_keywords)} TF-IDF keywords")
    
    for base_pattern in SQL_INJECTION_PATTERN_BASES:
        for tfidf_keyword in top_keywords:
            # Create combined query: base_query + base_pattern + tfidf_keyword
            query = f"{BASE_QUERY} {base_pattern} {tfidf_keyword}"
            
            # Skip if already tried
            if query not in TRIED_QUERIES:
                combined_queries.append({
                    'query': query,
                    'base': base_pattern,
                    'tfidf_kw': tfidf_keyword
                })
    
    logging.info(f"  Generated {len(combined_queries)} unique combined queries")
    return combined_queries


def main():
    """
    Single-phase approach: Combine known SQL injection patterns with TF-IDF keywords
    to create highly specific and targeted search queries.
    """
    read_state()
    
    logging.info("="*70)
    logging.info("PHP SQL INJECTION VULNERABILITY SEARCH")
    logging.info("Combined Pattern + TF-IDF Approach")
    logging.info("="*70)
    
    # Step 1: Compute TF-IDF from existing vulnerable code sections
    logging.info("\n[Step 1] Computing TF-IDF from vulnerable code sections...")
    logging.info("-"*70)
    
    tfidf_keywords = compute_tfidf("./downloads")
    
    if not tfidf_keywords:
        logging.error("No TF-IDF keywords found. Please ensure ./downloads contains PHP vulnerable code sections.")
        return
    
    # Filter to high-scoring keywords
    tfidf_keywords = [k for k in tfidf_keywords if k[1] >= 0.3]
    logging.info(f"Extracted {len(tfidf_keywords)} high-value TF-IDF keywords")
    
    # Display top keywords
    logging.info("\nTop 20 TF-IDF keywords:")
    for i, (keyword, score) in enumerate(tfidf_keywords[:20], 1):
        logging.info(f"  {i:2d}. {keyword:40s} (score: {score:.3f})")
    
    # Step 2: Generate combined queries
    logging.info("\n[Step 2] Generating combined queries...")
    logging.info("-"*70)
    
    combined_queries = generate_combined_queries(tfidf_keywords, top_n_tfidf=30)
    
    if not combined_queries:
        logging.warning("No new queries to try. All combinations already attempted.")
        return
    
    logging.info(f"\nExample combined queries:")
    for i, query_info in enumerate(combined_queries[:5], 1):
        logging.info(f"  {i}. Base: '{query_info['base']}' + TF-IDF: '{query_info['tfidf_kw']}'")
        logging.info(f"     → {query_info['query']}")
    
    # Step 3: Execute combined queries
    logging.info(f"\n[Step 3] Executing {len(combined_queries)} combined queries...")
    logging.info("-"*70)
    
    total_new_repos = 0
    
    for i, query_info in enumerate(combined_queries, 1):
        query = query_info['query']
        base = query_info['base']
        tfidf_kw = query_info['tfidf_kw']
        
        logging.info(f"\n[{i}/{len(combined_queries)}] {base} + {tfidf_kw}")
        TRIED_QUERIES.add(query)
        
        try:
            items = []
            search_code(query, 1, items)
            
            if not items:
                logging.info(f"    No results")
                continue
            
            # Deduplicate by repository
            found = {}
            for item in items:
                repo_name = item["repository"]["full_name"]
                found[repo_name] = item
            
            logging.info(f"    Found {len(items)} items from {len(found)} repositories")
            
            # Process new repositories
            new_repos = 0
            for repo_name, repo_data in found.items():
                if repo_name not in REPOS:
                    REPO_DETAILS[repo_name] = repo_data
                    if add_to_db(repo_name):
                        REPOS.append(repo_name)
                        new_repos += 1
            
            if new_repos > 0:
                total_new_repos += new_repos
                logging.info(f"    ✓ Added {new_repos} new repos | Total: {len(REPOS)}")
            
            save_state()
            time.sleep(2)  # Be nice to GitHub API
            
        except Exception as e:
            logging.error(f"    Error: {e}")
    
    # Final summary
    logging.info(f"\n{'='*70}")
    logging.info(f"COMPLETED")
    logging.info(f"  New repositories found: {total_new_repos}")
    logging.info(f"  Total repositories: {len(REPOS)}")
    logging.info(f"  Queries tried: {len(TRIED_QUERIES)}")
    logging.info(f"{'='*70}")
    logging.info(f"\n{'=' * 70}")
    logging.info(
        f"COMPLETED: {len(REPOS)} total repositories with SQL injection patterns found"
    )
    logging.info(f"{'=' * 70}")


if __name__ == "__main__":
    main()
