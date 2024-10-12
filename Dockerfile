FROM python:3.12-slim

RUN pip install poetry  
RUN mkdir -p /app  
COPY . /app

WORKDIR /app

RUN poetry install

CMD ["poetry", "run", "python", "-m", "src.log_analyzer"]
