import os
import requests
import subprocess
import json
import csv
import hashlib
import re
import math
from datetime import datetime

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv is not installed, read .env file manually
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#') and '=' in line:
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value.strip('"\'')

# Optional dependencies for statistical analysis
try:
    from scipy.stats import chi2_contingency, fisher_exact
    from scipy import stats
    import numpy as np
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    print("Warning: scipy not available. Statistical tests will be skipped.")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Optimized search queries prioritizing backend/database student projects >3MB
SEARCH_QUERIES = [
    # High-priority: Backend languages + database + size filter
    "language:javascript database API student university created:>=2023-01-01 fork:false size:>3000",
    "language:python django flask database student project created:>=2023-01-01 fork:false size:>3000", 
    "language:java spring database student university created:>=2023-01-01 fork:false size:>3000",
    "language:csharp database student university project created:>=2023-01-01 fork:false size:>3000",
    "language:php database student university college created:>=2023-01-01 fork:false size:>3000",
    "language:typescript database API student project created:>=2023-01-01 fork:false size:>3000",
    
    # Backend frameworks with database indicators
    "student react nodejs mongodb mysql created:>=2023-01-01 fork:false size:>3000",
    "university spring boot database created:>=2023-01-01 fork:false size:>3000",
    "college django postgresql mysql created:>=2023-01-01 fork:false size:>3000",
    "student express mongodb database created:>=2023-01-01 fork:false size:>3000",
    
    # Management systems (high likelihood of secrets)
    "student management system database created:>=2023-01-01 fork:false size:>3000",
    "university library management created:>=2023-01-01 fork:false size:>3000",
    "college booking reservation system created:>=2023-01-01 fork:false size:>3000",
    "student hospital management created:>=2023-01-01 fork:false size:>3000",
    "university inventory management created:>=2023-01-01 fork:false size:>3000",
    
    # E-commerce and web applications
    "student ecommerce database created:>=2023-01-01 fork:false size:>3000",
    "university web application database created:>=2023-01-01 fork:false size:>3000",
    "college online shopping created:>=2023-01-01 fork:false size:>3000",
    
    # Authentication/login systems
    "student authentication login database created:>=2023-01-01 fork:false size:>3000",
    "university login system created:>=2023-01-01 fork:false size:>3000",
    
    # Full-stack applications
    "student fullstack application created:>=2023-01-01 fork:false size:>3000",
    "MERN stack student created:>=2023-01-01 fork:false size:>3000",
    "MEAN stack university created:>=2023-01-01 fork:false size:>3000",
    
    # Academic project fallbacks (medium size)
    "final year project database created:>=2023-01-01 fork:false size:>1000",
    "capstone project backend created:>=2023-01-01 fork:false size:>1000",
    "student project in:readme database created:>=2023-01-01 fork:false size:>1000",
]

API_URL = "https://api.github.com/search/repositories"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}

OUT_DIR = "repos"
REPORT_DIR = "reports/raw"
PRIVATE_DIR = "reports/private"  # For raw sensitive data (not for submission)
TOOLS_DIR = "tools"
GITLEAKS_PATH = os.path.join(TOOLS_DIR, "gitleaks.exe")
TRUFFLEHOG_PATH = os.path.join(TOOLS_DIR, "trufflehog.exe")

os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(PRIVATE_DIR, exist_ok=True)  # Private folder for raw reports
os.makedirs("reports", exist_ok=True)

def anonymize_username(username):
    """Hash username with SHA256, keep first 8 characters"""
    return hashlib.sha256(str(username).encode()).hexdigest()[:8]

def redact_secrets(findings):
    """Replace actual secret values with [REDACTED] for anonymization"""
    anonymized_findings = []
    
    for finding in findings:
        if isinstance(finding, dict):
            anonymized = finding.copy()
            
            # Common secret fields to redact
            secret_fields = ['secret', 'match', 'raw', 'rawV2', 'decoded', 'value', 'line']
            
            for field in secret_fields:
                if field in anonymized:
                    if isinstance(anonymized[field], str) and len(anonymized[field]) > 5:
                        # Keep first 3 and last 2 characters, redact middle
                        original = anonymized[field]
                        if len(original) > 10:
                            anonymized[field] = f"{original[:3]}[REDACTED]{original[-2:]}"
                        else:
                            anonymized[field] = "[REDACTED]"
            
            anonymized_findings.append(anonymized)
        else:
            anonymized_findings.append("[REDACTED]")
    
    return anonymized_findings

def save_raw_findings(repo_name, gitleaks_findings, truffle_findings):
    """Save raw findings to private directory (not for submission)"""
    raw_data = {
        "repository": repo_name,
        "timestamp": datetime.now().isoformat(),  # Remove json.dumps wrapper
        "gitleaks_raw": gitleaks_findings,
        "trufflehog_raw": truffle_findings
    }
    
    private_file = os.path.join(PRIVATE_DIR, f"{repo_name}-raw.json")
    with open(private_file, "w") as f:
        json.dump(raw_data, f, indent=2)

def calculate_prevalence_ci(positive_cases, total_cases, confidence=0.95):
    """Calculate prevalence percentage with 95% confidence interval using Wilson score"""
    if total_cases == 0:
        return 0, (0, 0)
    
    p = positive_cases / total_cases
    z = 1.96 if confidence == 0.95 else 1.645
    n = total_cases
    
    # Wilson score interval (more accurate for small samples)
    denom = 1 + (z**2 / n)
    center = p + (z**2 / (2 * n))
    width = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)
    
    lower = max(0, (center - width) / denom)
    upper = min(1, (center + width) / denom)
    
    return p * 100, (lower * 100, upper * 100)

def extract_secret_types(all_findings):
    """Extract secret types from gitleaks and trufflehog findings"""
    secret_types = {}
    
    for finding in all_findings:
        # Handle Gitleaks findings (have RuleID)
        if 'RuleID' in finding:
            secret_type = finding['RuleID']
        # Handle TruffleHog findings (have DetectorName)
        elif 'DetectorName' in finding:
            secret_type = finding['DetectorName']
        else:
            secret_type = 'unknown'
        
        # Normalize common secret types
        secret_type_normalized = normalize_secret_type(secret_type)
        secret_types[secret_type_normalized] = secret_types.get(secret_type_normalized, 0) + 1
    
    return secret_types

def normalize_secret_type(secret_type):
    """Normalize secret type names for consistency"""
    if not secret_type:
        return 'unknown'
    
    # Convert to lowercase for comparison
    secret_type_lower = secret_type.lower()
    
    # Normalize common patterns
    type_mappings = {
        'private-key': 'Private Key',
        'privatekey': 'Private Key',
        'private_key': 'Private Key',
        'api-key': 'API Key',
        'apikey': 'API Key',
        'api_key': 'API Key',
        'generic-api-key': 'API Key',
        'password': 'Password',
        'jwt': 'JWT Token',
        'jwt-token': 'JWT Token',
        'oauth': 'OAuth Token',
        'oauth-token': 'OAuth Token',
        'access-token': 'Access Token',
        'access_token': 'Access Token',
        'secret-key': 'Secret Key',
        'secret_key': 'Secret Key',
        'database-url': 'Database URL',
        'database_url': 'Database URL',
        'connection-string': 'Connection String',
        'connection_string': 'Connection String',
        'aws-access-key': 'AWS Access Key',
        'aws_access_key': 'AWS Access Key',
        'github-token': 'GitHub Token',
        'github_token': 'GitHub Token',
        'google-api-key': 'Google API Key',
        'google_api_key': 'Google API Key',
    }
    
    return type_mappings.get(secret_type_lower, secret_type.title())

def generate_frequency_tables(summary_data):
    """Generate frequency tables for categorical variables"""
    tables = {}
    
    # Language frequency
    languages = {}
    for repo in summary_data:
        lang = repo.get('language', 'Unknown')
        if lang is None:
            lang = 'Unknown'
        languages[lang] = languages.get(lang, 0) + 1
    tables['languages'] = languages
    
    # Risk level frequency
    risk_levels = {}
    for repo in summary_data:
        level = repo.get('secrets_risk_level', 'Low')
        risk_levels[level] = risk_levels.get(level, 0) + 1
    tables['risk_levels'] = risk_levels
    
    # Size categories
    size_categories = {'Small (<1MB)': 0, 'Medium (1-3MB)': 0, 'Large (>3MB)': 0}
    for repo in summary_data:
        size_mb = repo.get('size_mb', 0)
        if size_mb < 1:
            size_categories['Small (<1MB)'] += 1
        elif size_mb < 3:
            size_categories['Medium (1-3MB)'] += 1
        else:
            size_categories['Large (>3MB)'] += 1
    tables['size_categories'] = size_categories
    
    # Secret presence by category
    secrets_by_lang = {}
    for repo in summary_data:
        lang = repo.get('language', 'Unknown')
        if lang is None:
            lang = 'Unknown'
        has_secrets = repo.get('has_secrets', False)
        
        if lang not in secrets_by_lang:
            secrets_by_lang[lang] = {'with_secrets': 0, 'total': 0}
        
        secrets_by_lang[lang]['total'] += 1
        if has_secrets:
            secrets_by_lang[lang]['with_secrets'] += 1
    
    tables['secrets_by_language'] = secrets_by_lang
    
    return tables

def perform_statistical_tests(summary_data):
    """Perform chi-square and Fisher's exact tests for categorical associations"""
    if not SCIPY_AVAILABLE:
        return {"error": "scipy not available for statistical tests"}
    
    results = {}
    
    # Test: Language vs Secret Presence
    # Create contingency table
    languages = {}
    for repo in summary_data:
        lang = repo.get('language', 'Unknown')
        if lang is None:
            lang = 'Unknown'
        has_secrets = repo.get('has_secrets', False)
        
        if lang not in languages:
            languages[lang] = [0, 0]  # [no_secrets, has_secrets]
        
        if has_secrets:
            languages[lang][1] += 1
        else:
            languages[lang][0] += 1
    
    # Filter out languages with very few samples
    filtered_langs = {k: v for k, v in languages.items() if sum(v) >= 3}
    
    if len(filtered_langs) >= 2:
        contingency_table = list(filtered_langs.values())
        chi2, p_value, dof, expected = chi2_contingency(contingency_table)
        
        results['language_vs_secrets'] = {
            'test': 'Chi-square',
            'chi2': float(chi2),
            'p_value': float(p_value),
            'degrees_of_freedom': int(dof),
            'significant': bool(p_value < 0.05)  # Explicitly convert to JSON-serializable bool
        }
    
    # Test: Size vs Secret Presence
    size_secrets = {'small': [0, 0], 'medium': [0, 0], 'large': [0, 0]}
    
    for repo in summary_data:
        size_mb = repo.get('size_mb', 0)
        has_secrets = repo.get('has_secrets', False)
        
        if size_mb < 1:
            category = 'small'
        elif size_mb < 3:
            category = 'medium'
        else:
            category = 'large'
        
        if has_secrets:
            size_secrets[category][1] += 1
        else:
            size_secrets[category][0] += 1
    
    size_table = list(size_secrets.values())
    if all(sum(row) > 0 for row in size_table):
        chi2, p_value, dof, expected = chi2_contingency(size_table)
        
        results['size_vs_secrets'] = {
            'test': 'Chi-square',
            'chi2': float(chi2),
            'p_value': float(p_value),
            'degrees_of_freedom': int(dof),
            'significant': bool(p_value < 0.05)  # Explicitly convert to JSON-serializable bool
        }
    
    return results

def generate_analysis_report(summary_data, all_findings=None):
    """Generate comprehensive statistical analysis report"""
    total_repos = len(summary_data)
    repos_with_secrets = sum(1 for repo in summary_data if repo.get('has_secrets', False))
    
    # Calculate prevalence with confidence interval
    prevalence, ci = calculate_prevalence_ci(repos_with_secrets, total_repos)
    
    # Generate frequency tables
    freq_tables = generate_frequency_tables(summary_data)
    
    # Extract secret types if findings provided
    if all_findings:
        secret_types = extract_secret_types(all_findings)
        freq_tables['secrets_types'] = secret_types
    
    # Perform statistical tests
    stat_tests = perform_statistical_tests(summary_data)
    
    report = {
        "summary_statistics": {
            "total_repositories": total_repos,
            "repositories_with_secrets": repos_with_secrets,
            "prevalence_percentage": round(prevalence, 2),
            "confidence_interval_95": (round(ci[0], 2), round(ci[1], 2))
        },
        "frequency_tables": freq_tables,
        "statistical_tests": stat_tests,
        "risk_distribution": {
            "high_risk": sum(1 for r in summary_data if r.get('secrets_risk_level') == 'High'),
            "medium_risk": sum(1 for r in summary_data if r.get('secrets_risk_level') == 'Medium'),
            "low_risk": sum(1 for r in summary_data if r.get('secrets_risk_level') == 'Low')
        }
    }
    
    return report

def filter_repos_by_risk(repos):
    """Filter repositories prioritizing those with databases, backend servers, >3MB size, and clear student indicators"""
    
    # High-priority backend languages
    HIGH_RISK_LANGUAGES = {
        'javascript', 'python', 'java', 'csharp', 'php', 'ruby', 'go', 
        'typescript', 'kotlin', 'swift', 'dart', 'rust', 'scala', 'c++', 'c'
    }
    
    # Consolidated keyword categories with weights
    SCORING_CATEGORIES = {
        'database': {
            'keywords': {'mysql', 'postgresql', 'mongodb', 'redis', 'sqlite', 'database', 'db', 'firebase', 'dynamodb'},
            'weight': 4  # High priority for database systems
        },
        'backend': {
            'keywords': {'api', 'backend', 'server', 'rest', 'express', 'django', 'flask', 'spring', 'nodejs'},
            'weight': 3
        },
        'auth_security': {
            'keywords': {'auth', 'login', 'jwt', 'oauth', 'authentication', 'password', 'token', 'security'},
            'weight': 3
        },
        'student_evidence': {
            'keywords': {'student', 'university', 'college', 'assignment', 'final year', 'capstone', 'thesis', 'academic'},
            'weight': 2  # Must have but not as heavily weighted
        },
        'management_systems': {
            'keywords': {'management system', 'booking system', 'ecommerce', 'inventory', 'hospital', 'library'},
            'weight': 3
        },
        'low_priority': {
            'keywords': {'portfolio', 'resume', 'cv', 'blog', 'documentation', 'tutorial', 'template', 'demo'},
            'weight': -3  # Penalize these
        }
    }
    
    filtered_repos = []
    
    for repo in repos:
        risk_score = 0
        repo_text = f"{repo.get('name', '').lower()} {repo.get('description', '').lower()}"
        language = repo.get('language', '').lower() if repo.get('language') else ''
        
        # Language scoring
        if language in HIGH_RISK_LANGUAGES:
            risk_score += 3
        
        # Apply scoring categories
        student_found = False
        for category, config in SCORING_CATEGORIES.items():
            keyword_matches = sum(1 for keyword in config['keywords'] if keyword in repo_text)
            if keyword_matches > 0:
                risk_score += keyword_matches * config['weight']
                if category == 'student_evidence':
                    student_found = True
        
        # Penalty if no student evidence found
        if not student_found:
            risk_score -= 5
        
        # Size requirements (prioritize >3MB repos)
        size_kb = repo.get('size', 0)
        size_mb = size_kb / 1024
        
        if size_mb > 3:  # >3MB (high priority)
            risk_score += 5
        elif size_mb > 1:  # >1MB (medium priority)
            risk_score += 2
        elif size_kb > 100:  # >100KB (low priority)
            risk_score += 0
        else:  # Very small repos (exclude)
            risk_score -= 10
        
        # Activity indicators (more active = more likely to have real code)
        if repo.get('stargazers_count', 0) > 3:
            risk_score += 2
        if repo.get('forks_count', 0) > 1:
            risk_score += 2
        if repo.get('watchers_count', 0) > 2:
            risk_score += 1
        
        # Recent activity (updated in last year)
        try:
            from datetime import datetime, timedelta
            updated_at = repo.get('updated_at', '')
            if updated_at:
                update_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                if update_date > datetime.now().replace(tzinfo=update_date.tzinfo) - timedelta(days=365):
                    risk_score += 2
        except:
            pass
        
        # Only include repos with positive risk score
        if risk_score > 0:
            repo['risk_score'] = risk_score
            filtered_repos.append(repo)
    
    # Sort by risk score (highest first)
    filtered_repos.sort(key=lambda x: x['risk_score'], reverse=True)
    return filtered_repos

def fetch_repos(n=50):
    """Fetch repositories using multiple targeted queries to find repos likely to contain sensitive data"""
    all_repos = []
    seen_ids = set()
    
    # Start with reasonable per-query requests to get variety
    initial_per_query = max(5, n // len(SEARCH_QUERIES))
    
    print(f"Searching with {len(SEARCH_QUERIES)} targeted queries for student repositories...")
    
    for i, query in enumerate(SEARCH_QUERIES, 1):
        try:
            params = {"q": query, "per_page": initial_per_query, "sort": "updated"}
            r = requests.get(API_URL, headers=HEADERS, params=params)
            r.raise_for_status()
            repos = r.json()["items"]
            
            # Filter repos based on characteristics likely to contain sensitive data
            filtered_repos = filter_repos_by_risk(repos)
            
            # Add unique repos
            added_count = 0
            for repo in filtered_repos:
                if repo["id"] not in seen_ids and len(all_repos) < n:
                    seen_ids.add(repo["id"])
                    all_repos.append(repo)
                    added_count += 1
            
            print(f"[{i}/{len(SEARCH_QUERIES)}] Found {added_count} new repos from: {query[:45]}...")
            
            # Early exit if we have enough repos
            if len(all_repos) >= n:
                break
                
        except Exception as e:
            print(f"Error with query {query[:60]}...: {e}")
            continue
    
    # If we still don't have enough repos, try broader searches with higher per_page
    if len(all_repos) < n:
        print(f"Only found {len(all_repos)} repos, searching for more...")
        remaining = n - len(all_repos)
        
        # Use the last (broadest) query to fill remaining slots
        try:
            broad_query = SEARCH_QUERIES[-1]  # The fallback broad search
            params = {"q": broad_query, "per_page": min(100, remaining * 2), "sort": "updated"}
            r = requests.get(API_URL, headers=HEADERS, params=params)
            r.raise_for_status()
            repos = r.json()["items"]
            
            # Add any repos we haven't seen yet (with lower filtering threshold)
            for repo in repos:
                if repo["id"] not in seen_ids and len(all_repos) < n:
                    # Apply basic filtering but with lower threshold
                    repo_text = f"{repo.get('name', '').lower()} {repo.get('description', '').lower()}"
                    
                    # Skip obvious documentation/portfolio sites
                    skip_terms = ['portfolio', 'resume', 'cv', 'documentation', 'readme']
                    if any(term in repo_text for term in skip_terms):
                        continue
                        
                    # Add risk score for consistency
                    repo['risk_score'] = 1  # Low but positive risk score
                    seen_ids.add(repo["id"])
                    all_repos.append(repo)
            
            print(f"Added {len(all_repos) - (n - remaining)} more repos from broad search")
            
        except Exception as e:
            print(f"Error with broad search: {e}")
    
    return all_repos[:n]  # Return exactly n repos

def clone_repo(url, name):
    repo_path = os.path.join(OUT_DIR, name)
    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", "--depth", "1", url, repo_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to clone {name}: {e}")
            # Create empty directory to continue processing
            os.makedirs(repo_path, exist_ok=True)
    return repo_path

def run_gitleaks(repo_path, repo_name):
    out_file = os.path.join(REPORT_DIR, f"{repo_name}-gitleaks.json")
    cmd = [GITLEAKS_PATH, "detect", f"--source={repo_path}", f"--report-path={out_file}"]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(f"Warning: gitleaks not found at {GITLEAKS_PATH}. Skipping scan for {repo_name}")
        # Create empty file to avoid parse errors
        with open(out_file, "w") as f:
            json.dump([], f)
    return out_file

def run_trufflehog(repo_url, repo_name):
    out_file = os.path.join(REPORT_DIR, f"{repo_name}-truffle.json")
    cmd = [TRUFFLEHOG_PATH, "git", repo_url, "--json", "--no-update"]
    try:
        with open(out_file, "w") as f:
            subprocess.run(cmd, stdout=f, check=False)
    except FileNotFoundError:
        print(f"Warning: trufflehog not found at {TRUFFLEHOG_PATH}. Skipping scan for {repo_name}")
        # Create empty file to avoid parse errors
        with open(out_file, "w") as f:
            f.write("")
    return out_file

def parse_results(file):
    try:
        with open(file) as f:
            return json.load(f)
    except Exception:
        return []

def score_findings(findings, repo_info=None):
    """Score findings using 3 dimensions (0-2 each): Exploitability, Impact, Exposure"""
    
    if len(findings) == 0:
        return {"total": 0, "level": "Low", "exploitability": 0, "impact": 0, "exposure": 0}
    
    # Exploitability (0-2): How easily can secrets be exploited?
    exploitability = 0
    finding_text = json.dumps(findings).lower()
    
    # High exploitability patterns
    high_exploit_patterns = ['api_key', 'api-key', 'apikey', 'password', 'secret_key', 
                            'private_key', 'access_token', 'oauth', 'jwt', 'database_url',
                            'connection_string', 'aws_', 'google_', 'github_token']
    
    # Medium exploitability patterns  
    medium_exploit_patterns = ['config', 'env', 'credential', 'auth', 'token', 'key']
    
    if any(pattern in finding_text for pattern in high_exploit_patterns):
        exploitability = 2
    elif any(pattern in finding_text for pattern in medium_exploit_patterns):
        exploitability = 1
    
    # Impact (0-2): Potential damage if exploited
    impact = 0
    n = len(findings)
    
    if n >= 5:  # Many secrets = high impact
        impact = 2
    elif n >= 2:  # Multiple secrets = medium impact  
        impact = 1
    else:  # Single secret = low impact
        impact = 0
    
    # Bonus for database/backend systems (higher impact)
    if repo_info:
        repo_text = f"{repo_info.get('name', '').lower()} {repo_info.get('description', '').lower()}"
        if any(db in repo_text for db in ['database', 'mysql', 'postgresql', 'mongodb']):
            impact = min(2, impact + 1)
    
    # Exposure (0-2): How exposed are the secrets?
    exposure = 2  # Both gitleaks and trufflehog check git history = maximum exposure
    
    # Calculate total score (0-6)
    total = exploitability + impact + exposure
    
    # Map to risk levels
    if total >= 5:
        level = "High"
    elif total >= 3:
        level = "Medium"  
    else:
        level = "Low"
    
    return {
        "total": total,
        "level": level,
        "exploitability": exploitability,
        "impact": impact, 
        "exposure": exposure
    }

def main():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN environment variable not set")
        return
    
    # Note about optional statistical features
    if SCIPY_AVAILABLE:
        print("✓ scipy available - statistical tests will be performed")
    else:
        print("ℹ Install scipy (pip install scipy) for statistical tests")
    
    repos = fetch_repos()
    print(f"\nFound {len(repos)} targeted repositories to scan")
    summary = []
    all_findings_collected = []  # Collect all findings for secret type analysis
    
    for i, repo in enumerate(repos, 1):
        repo_id = repo["id"]
        lang = repo["language"]
        last_commit = repo["pushed_at"]
        size = repo["size"]
        owner_hash = anonymize_username(repo["owner"]["login"])
        name = repo["name"]

        url = repo["html_url"]
        print(f"\n[{i}/{len(repos)}] Processing: {name} (Risk: {repo.get('risk_score', 0)}, Lang: {lang})")
        repo_path = clone_repo(repo["clone_url"], name)

        gitleaks_file = run_gitleaks(repo_path, name)
        truffle_file = run_trufflehog(repo["clone_url"], name)

        gitleaks_findings = parse_results(gitleaks_file)
        truffle_findings = []
        try:
            with open(truffle_file, 'r') as f:
                truffle_findings = [json.loads(line) for line in f if line.strip()]
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        # Save raw findings to private directory (not for submission)
        save_raw_findings(name, gitleaks_findings, truffle_findings)
        
        # Anonymize findings for analysis
        all_findings = gitleaks_findings + truffle_findings
        anonymized_findings = redact_secrets(all_findings)
        
        # Collect findings for secret type analysis
        all_findings_collected.extend(all_findings)
        
        # Score using proper 3-dimensional approach
        score_result = score_findings(all_findings, repo)

        summary.append({
            "repo_id": repo_id,
            "repo_name": name,
            "repo_url": url,
            "language": lang,
            "last_commit": last_commit,
            "contributors": repo["forks_count"],
            "size_kb": size,
            "size_mb": round(size / 1024, 2),
            "owner_hash": anonymize_username(repo["owner"]["login"]),  # Anonymized username
            "selection_risk_score": repo.get('risk_score', 0),  # Risk score from filtering
            "gitleaks_hits": len(gitleaks_findings),
            "trufflehog_hits": len(truffle_findings),
            "total_findings": len(all_findings),
            "exploitability": score_result["exploitability"],
            "impact": score_result["impact"], 
            "exposure": score_result["exposure"],
            "secrets_risk_score": score_result["total"],  # 0-6 scale
            "secrets_risk_level": score_result["level"],  # High/Medium/Low
            "has_secrets": len(all_findings) > 0
        })


    # Save results and generate analysis
    if summary:
        # Save anonymized summary data
        with open("reports/summary.json", "w") as jf:
            json.dump(summary, jf, indent=2)    
        with open("reports/summary.csv", "w", newline="") as cf:
            writer = csv.DictWriter(cf, fieldnames=summary[0].keys())
            writer.writeheader()
            writer.writerows(summary)
        
        # Generate comprehensive statistical analysis
        analysis_report = generate_analysis_report(summary, all_findings_collected)
        with open("reports/statistical_analysis.json", "w") as af:
            json.dump(analysis_report, af, indent=2)
        
        # Print summary statistics
        print(f"\n=== ANALYSIS SUMMARY ===")
        print(f"Processed {len(summary)} repositories")
        print(f"Repositories with secrets: {analysis_report['summary_statistics']['repositories_with_secrets']}")
        print(f"Prevalence: {analysis_report['summary_statistics']['prevalence_percentage']}% "
              f"(95% CI: {analysis_report['summary_statistics']['confidence_interval_95'][0]:.1f}%-"
              f"{analysis_report['summary_statistics']['confidence_interval_95'][1]:.1f}%)")
        
        risk_dist = analysis_report['risk_distribution']
        print(f"Risk distribution - High: {risk_dist['high_risk']}, Medium: {risk_dist['medium_risk']}, Low: {risk_dist['low_risk']}")
        
        print(f"\nReports saved:")
        print(f"- Anonymized data: reports/summary.json, reports/summary.csv")
        print(f"- Statistical analysis: reports/statistical_analysis.json")
        print(f"- Raw data (private): reports/private/ (DO NOT SUBMIT)")
        
    else:
        print("No repositories found or processed")

if __name__ == "__main__":
    main()
