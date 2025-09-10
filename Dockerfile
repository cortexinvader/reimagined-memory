FROM python:3.11-slim

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose Flask port
EXPOSE 5000

# Set environment
ENV FLASK_ENV=production
ENV DB_PATH=/app/mydata.sqlite

# Run with Gunicorn (production WSGI server)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server:app"]
