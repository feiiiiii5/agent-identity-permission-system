.PHONY: install run dev test lint clean demo demo-all verify

install:
	pip install -r requirements.txt

run:
	lsof -ti:8000 | xargs kill -9 2>/dev/null || true
	python main.py

dev:
	uvicorn main:app --reload --host 0.0.0.0 --port 8000

test:
	python -m pytest tests/ -v --tb=short

lint:
	python -m py_compile main.py
	python -m py_compile core/auth_server.py
	python -m py_compile core/token_manager.py
	python -m py_compile core/audit_logger.py
	python -m py_compile core/risk_scorer.py
	python -m py_compile core/injection_scanner.py
	python -m py_compile core/policy_engine.py
	python -m py_compile core/svid_manager.py
	python -m py_compile core/dpop_verifier.py
	python -m py_compile core/rate_limiter.py
	python -m py_compile core/circuit_breaker.py
	python -m py_compile core/nonce_manager.py
	python -m py_compile agents/*.py 2>/dev/null || true
	python -m py_compile feishu/*.py 2>/dev/null || true
	@echo "Syntax check passed"

clean:
	rm -f *.db
	rm -f data/*.db
	rm -f reports/*.html
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

demo:
	python cli/demo_cli.py run normal

demo-all:
	python cli/demo_cli.py run all

verify:
	python verify_chain.py
