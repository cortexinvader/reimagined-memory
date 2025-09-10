FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir flask werkzeug
EXPOSE 5000
ENV FLASK_ENV=production
ENV DB_PATH=/app/mydata.sqlite
CMD ["python", "server.py"]
