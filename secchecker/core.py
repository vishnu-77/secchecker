import re
import os
from pathlib import Path
from typing import Dict, List, Set
from .patterns import PATTERNS

# File extensions to skip for performance and accuracy
SKIP_EXTENSIONS = {
    '.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin', '.jpg', '.jpeg', 
    '.png', '.gif', '.bmp', '.ico', '.svg', '.pdf', '.zip', '.tar', '.gz', 
    '.rar', '.7z', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.woff', 
    '.woff2', '.ttf', '.eot', '.otf'
}

# Directories to skip
SKIP_DIRS = {
    '__pycache__', '.git', '.svn', '.hg', '.bzr', 'node_modules', '.venv', 
    'venv', 'env', '.env', 'build', 'dist', '.pytest_cache', '.tox', 
    '.coverage', '.mypy_cache', '.DS_Store', 'Thumbs.db'
}

def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped based on extension or size."""
    # Skip by extension
    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return True
    
    # Skip large files (>10MB)
    try:
        if filepath.stat().st_size > 10 * 1024 * 1024:
            return True
    except OSError:
        return True
    
    return False

def should_skip_directory(dirpath: Path) -> bool:
    """Check if directory should be skipped."""
    return dirpath.name in SKIP_DIRS

def scan_file(filepath: str) -> Dict[str, List[str]]:
    """
    Scan a single file for secret patterns.
    
    Args:
        filepath: Path to the file to scan
        
    Returns:
        Dictionary with pattern names as keys and matched strings as values
    """
    findings = {}
    path_obj = Path(filepath)
    
    if should_skip_file(path_obj):
        return findings
    
    try:
        # Try different encodings
        content = None
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(filepath, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            return findings
            
        # Scan for patterns
        for name, pattern in PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                if matches:
                    # Remove duplicates while preserving order
                    unique_matches = list(dict.fromkeys(matches))
                    findings[name] = unique_matches
            except re.error:
                # Skip invalid regex patterns
                continue
                
    except (OSError, IOError, PermissionError):
        # Skip files we can't read
        pass
    except Exception:
        # Catch any other unexpected errors
        pass
        
    return findings

def scan_directory(directory: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Scan a directory recursively for secret patterns.
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dictionary with file paths as keys and findings as values
    """
    results = {}
    directory_path = Path(directory)
    
    if not directory_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    
    if not directory_path.is_dir():
        # If it's a single file, scan just that file
        file_findings = scan_file(str(directory_path))
        if file_findings:
            results[str(directory_path)] = file_findings
        return results
    
    # Recursively scan directory
    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        
        # Skip certain directories
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]
        
        for file in files:
            file_path = root_path / file
            
            if should_skip_file(file_path):
                continue
                
            file_findings = scan_file(str(file_path))
            if file_findings:
                # Use relative path from scan root for cleaner output
                try:
                    rel_path = file_path.relative_to(directory_path)
                    results[str(rel_path)] = file_findings
                except ValueError:
                    # Fall back to absolute path if relative fails
                    results[str(file_path)] = file_findings
    
    return results

def get_scan_stats(results: Dict[str, Dict[str, List[str]]]) -> Dict[str, int]:
    """Get statistics about the scan results."""
    total_files = len(results)
    total_secrets = sum(len(findings) for findings in results.values())
    total_matches = sum(
        len(matches) for findings in results.values() 
        for matches in findings.values()
    )
    
    pattern_counts = {}
    for findings in results.values():
        for pattern_name, matches in findings.items():
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + len(matches)
    
    return {
        'total_files': total_files,
        'total_secret_types': total_secrets,
        'total_matches': total_matches,
        'pattern_breakdown': pattern_counts
    }
