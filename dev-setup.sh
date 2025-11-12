#!/bin/bash

# Development setup and testing script for secchecker
echo "🔧 Setting up secchecker development environment..."

# Install in editable mode with development dependencies
echo "📦 Installing package in editable mode..."
pip install -e ".[dev,test]"

# Run linting
echo "🧹 Running code formatting and linting..."
black secchecker/ tests/ --diff --color
flake8 secchecker/ tests/ --max-line-length=88

# Run tests with coverage
echo "🧪 Running test suite with coverage..."
pytest tests/ -v --cov=secchecker --cov-report=term-missing --cov-report=html

# Test CLI functionality
echo "🔍 Testing CLI functionality..."
python -m secchecker.cli --help
echo "password='test123'" > test_file.py
python -m secchecker.cli . --format json --verbose
rm -f test_file.py secchecker_report.json

echo "✅ All checks completed!"
echo "📊 View detailed coverage report: open htmlcov/index.html"