# Contributing to Crypto Tool

Thank you for considering contributing! Here's how to get started.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crypto-tool.git
   cd crypto-tool
   ```
3. **Install** in development mode:
   ```bash
   pip install -e ".[dev]"
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development

### Code Style

- Follow PEP 8
- Use type hints for all public functions
- Write docstrings (Google style preferred)
- Format with `black` and lint with `ruff`

```bash
black crypto_tool/ tests/
ruff check crypto_tool/
```

### Running Tests

```bash
pytest -v
pytest --cov=crypto_tool
```

Tests are required for all new features and bug fixes.

### Commit Messages

Use conventional commits:
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation
- `test:` — adding/updating tests
- `refactor:` — code restructuring
- `chore:` — maintenance

## Adding New Algorithms

1. Implement the algorithm in the appropriate module:
   - `cipher.py` for symmetric ciphers (AES, SM4-like)
   - `sm_cipher.py` for SM algorithms requiring `gmssl`
   - `hash_utils.py` for hash algorithms
2. Add CLI commands in `cli.py`
3. Add GUI controls in `gui.py`
4. Write comprehensive tests
5. Update `README.md`

## Pull Requests

1. Ensure all tests pass
2. Update documentation if needed
3. Describe what your change does and why
4. Reference any related issues

## Security

- **Never commit real cryptographic keys or secrets**
- Use test vectors for algorithm tests
- Report security issues privately
