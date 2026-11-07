FROM python:3.14.7

WORKDIR /app

# Install Tesseract OCR for Linux
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Existing team files
COPY ai_manager.py data_manager.py logic_manager.py phishing_guard_main.py ./

# Your updated I/O Manager folder
COPY io_manager/ ./io_manager/

# Python dependencies
RUN python -m pip install --no-cache-dir requests Pillow pytesseract

# Keep the team's main program unchanged
CMD ["python", "phishing_guard_main.py"]
