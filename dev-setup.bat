@echo off
REM Development setup and testing script for secchecker (Windows)
echo 🔧 Setting up secchecker development environment...

REM Install in editable mode with development dependencies
echo 📦 Installing package in editable mode...
pip install -e ".[dev,test]"

REM Run tests with coverage
echo 🧪 Running test suite with coverage...
python -m pytest tests/ -v --cov=secchecker --cov-report=term-missing --cov-report=html

REM Test CLI functionality
echo 🔍 Testing CLI functionality...
python -m secchecker.cli --help
echo password='test123' > test_file.py
python -m secchecker.cli . --format json --verbose
del test_file.py secchecker_report.json 2>nul

echo ✅ All checks completed!
echo 📊 View detailed coverage report: htmlcov/index.html