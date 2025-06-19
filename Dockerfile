FROM python:3.10-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
RUN python -c "from database.db import init_db; init_db()"

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
