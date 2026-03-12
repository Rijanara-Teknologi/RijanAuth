FROM python:3.9

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP run.py
ENV DEBUG True

# gunicorn tuning – override at runtime via docker run -e or docker-compose environment
ENV PORT=5085
ENV WORKERS=1
ENV THREADS=4
ENV TIMEOUT=600

# Directory used to persist the SQLite database across container rebuilds.
# Mount a Docker volume or a host bind-mount at this path so the data
# survives `docker-compose up --build` cycles.
ENV DB_PATH=/data/db.sqlite3
RUN mkdir -p /data

COPY requirements.txt .

# install python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY env.sample .env

COPY . .

# gunicorn
CMD ["gunicorn", "--config", "gunicorn-cfg.py", "run:app"]
