FROM python:3.14.7

WORKDIR /app

# Install Tesseract OCR for Linux
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Team files: these are folders now, so each one is copied separately
COPY ai_manager/ ./ai_manager/
COPY data_manager/ ./data_manager/
COPY logic_manager/ ./logic_manager/
COPY io_manager/ ./io_manager/
COPY phishing_guard_main.py phishguard_main_web_app.py ./

# Python dependencies (streamlit added)
RUN python -m pip install --no-cache-dir requests Pillow pytesseract streamlit

# Streamlit runs on port 8501
EXPOSE 8501

# Run the website
CMD ["streamlit", "run", "phishguard_main_web_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
