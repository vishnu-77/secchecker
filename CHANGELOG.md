# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-12

### Added
- **Enhanced XML Report Generation**: Fully implemented XML report functionality with proper formatting, metadata, and severity levels
- **Comprehensive Secret Pattern Detection**: Added 40+ new patterns including:
  - Cloud provider secrets (AWS, Azure, Google Cloud)
  - Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
  - Authentication tokens (JWT, Bearer, Basic Auth)
  - Version control tokens (GitHub, GitLab)
  - Communication platform tokens (Slack, Discord, Telegram)
  - Cryptocurrency private keys
  - SSL/TLS certificates
  - Sensitive personal data (Credit cards, SSN)
- **Severity Classification**: Added CRITICAL, HIGH, MEDIUM, LOW severity levels for all patterns
- **Enhanced CLI Features**:
  - Verbose mode with detailed scanning information
  - Custom output file specification
  - Better error handling and user feedback
  - Environment variable configuration support
- **Improved Performance**:
  - Smart file filtering to skip binary files and common non-source directories
  - Better memory handling for large repositories
  - Multiple encoding support for international text files
- **Rich Report Formatting**:
  - Professional markdown reports with emojis and statistics
  - Structured XML reports with metadata and severity breakdown
  - Enhanced JSON reports with comprehensive metadata
- **False Positive Detection**: Added filtering for common false positive patterns
- **Comprehensive Test Suite**: Added 23 comprehensive tests covering all functionality

### Enhanced
- **Better Pattern Matching**: Improved regex patterns for more accurate detection
- **File Scanning Logic**: Enhanced to handle edge cases and different file encodings
- **Report Metadata**: Added timestamps, tool version, and scanning statistics
- **Documentation**: Improved inline documentation and type hints

### Fixed
- **XML Report Implementation**: Resolved "XML report functionality not yet implemented" error
- **Unicode Handling**: Fixed encoding issues in report generation
- **CLI Error Handling**: Better error messages and graceful failure handling

### Changed
- **Project Structure**: Reorganized for better maintainability
- **Version Bumped**: Updated from 0.1.3 to 0.2.0
- **Dependencies**: Removed click dependency, using only standard library
- **Report Format**: Enhanced all report formats with better structure and metadata

## [0.1.3] - 2025-10-01

### Added
- Basic XML report format option
- Environment variable configuration
- Initial CLI implementation

### Fixed
- Basic functionality issues

## [0.1.0] - 2025-10-01

### Added
- Initial release
- Basic secret scanning functionality
- JSON and Markdown report generation
- CLI interface
- Core pattern matching engine