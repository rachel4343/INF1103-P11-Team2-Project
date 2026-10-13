FROM python:3.14.7

WORKDIR /app

COPY ai_manager.py data_manager.py io_manager.py logic_manager.py phishing_guard_main.py ./

RUN pip install --no-cache-dir requests

CMD ["python", "phishing_guard_main.py"]