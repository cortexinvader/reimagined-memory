FROM python:3.11-slim

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_ENV=production
ENV DB_PATH=/app/mydata.sqlite
ENV ADMIN_USERNAME=Alpha
ENV ADMIN_PASSWORD=Cortex($₦)  

# Run with Gunicorn (production WSGI server)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers=2", "--threads=4", "server:app"]
