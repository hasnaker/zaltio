"""
HSD Auth Python SDK - Package Setup
Validates: Requirements 4.2, 4.6

Setup configuration for PyPI distribution.
"""

from setuptools import setup, find_packages
import os

# Read the README for long description
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="zalt-auth",
    version="0.1.0",
    author="HSD Team",
    author_email="dev@zaltcore.com",
    description="Python SDK for HSD Auth Platform - Authentication as a Service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zalt/zalt-auth-python-sdk",
    project_urls={
        "Documentation": "https://docs.auth.zaltcore.com/sdk/python",
        "Bug Tracker": "https://github.com/zalt/zalt-auth-python-sdk/issues",
        "Source Code": "https://github.com/zalt/zalt-auth-python-sdk",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "hypothesis>=6.0.0",
            "responses>=0.23.0",
            "mypy>=1.0.0",
            "black>=23.0.0",
            "isort>=5.0.0",
            "flake8>=6.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords="authentication, auth, zalt, sdk, api, jwt, oauth",
    package_data={
        "zalt_auth": ["py.typed"],
    },
    include_package_data=True,
    zip_safe=False,
)
