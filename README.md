# AI Prompt Firewall

AI Prompt Firewall is a lightweight, FastAPI-based security gateway designed to intercept, analyze, and sanitize user prompts before they reach downstream Large Language Models (LLMs). It helps mitigate risks such as prompt injection, data exfiltration, and toxic inputs.

## 🚀 Features

* **Prompt Ingestion & Sanitization**: Inspects incoming text payloads against security schemas.
* **Security Services**: Built-in evaluation logic to flag or block malicious inputs.
* **Web UI Dashboard**: Includes a simple frontend template (`templates/index.html`) to test prompts and visualize firewall actions.
* **Automated Security Testing**: Integrated with `pytest` for robust security unit and integration tests.
* **CI/CD Ready**: Includes a GitHub Actions workflow to run security checks on every push.

---

## 📁 Project Structure

```text
ai-prompt-firewall-main/
├── .github/
│   └── workflows/
│       └── ci-security-tests.yml   # GitHub Actions CI pipeline
├── app/
│   ├── __init__.py
│   ├── schemas.py                  # Pydantic data models for validation
│   └── services.py                 # Core firewall evaluation & security logic
├── templates/
│   └── index.html                  # Web UI for interactive testing
├── tests/
│   ├── __init__.py
│   └── test_security_gateway.py    # Security test suites
├── main.py                         # FastAPI application entry point
├── pytest.ini                      # Pytest configuration
├── requirements.txt                # Python dependencies
└── .gitignore

```

---

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <link-to-this-repo>
cd ai-prompt-firewall-main

```

### 2. Set Up a Virtual Environment

```bash
# Create a virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

```

### 3. Install Dependencies

```bash
pip install -r requirements.txt

```

---

## 💻 Running the Application

Start the FastAPI local development server using `uvicorn`:

```bash
uvicorn main:app --reload

```

Once running, you can access:

* **Interactive Web UI**: `[http://127.0.0.1:8000/](http://127.0.0.1:8000/)`
* **API Documentation (Swagger UI)**: `[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)`

---

## 🧪 Running Tests

The project uses `pytest` to validate the firewall's detection mechanisms and API behavior.

To run the test suite locally:

```bash
pytest

```

---

## 🤖 CI/CD Integration

This repository includes a predefined GitHub Actions workflow located in `.github/workflows/ci-security-tests.yml`.

On every `push` or `pull_request` to the main branch, the pipeline will automatically:

1. Set up the Python environment.
2. Install the required packages.
3. Execute `pytest` to ensure no security regressions are introduced to the gateway logic.
