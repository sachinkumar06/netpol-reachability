.PHONY: install test lint demo verify docker clean

install:
	pip install -e ".[dev]"

test:
	pytest --cov=netpol_reachability --cov-report=term-missing

lint:
	ruff check .

demo:
	netpol-reachability graph -f examples/demo-cluster --port 8080

verify:
	netpol-reachability verify -f examples/demo-cluster -i examples/intent.yaml

docker:
	docker build -t netpol-reachability:dev .

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ *.egg-info build dist
