FROM python:3.11-slim

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files and ensure schema.sql is included
COPY . .
RUN ls -l /app/schema.sql && chmod 644 /app/schema.sql

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_ENV=production
ENV DB_PATH=/app/mydata.sqlite
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=securepassword123  # Change in production!

# Run with Gunicorn (production WSGI server)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers=2", "--threads=4", "server:app"]
