FROM python:3.11-slim

WORKDIR /app

# Copy application files
COPY checker.py depshield.py parsers.py registry_client.py reporter.py web_server.py /app/
# Copy static web assets
COPY web/ /app/web/
# Copy sample packages and test files
COPY test_depshield.py test_package.json test_requirements.txt lodash-4.17.21.tgz /app/

# Make depshield.py executable
RUN chmod +x /app/depshield.py

# Set the default entrypoint to the depshield executable
ENTRYPOINT ["python3", "/app/depshield.py"]
