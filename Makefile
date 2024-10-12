flake:
	flake8 src

isort:
	isort .

black:
	black src

mypy:
	mypy .

pylint:
	pylint src

lint: flake isort black mypy pylint

cov:
	pytest --cov=src tests/
test:
	pytest tests/