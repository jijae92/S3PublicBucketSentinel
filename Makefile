ARTIFACTS_DIR ?= artifacts

.PHONY: deps test build deploy delete demo

deps:
	pip install -r requirements.txt

test:
	pytest -q --cov=backend --cov-report=term-missing

build:
	sam build

deploy:
	sam deploy --guided --stack-name s3-public-sentinel

delete:
	sam delete

demo:
	python -m backend.scanner.cli --mode report --out $(ARTIFACTS_DIR)/report.json --csv $(ARTIFACTS_DIR)/report.csv
