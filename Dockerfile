FROM python:3

WORKDIR /app

COPY requirements.txt ./

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY resources/* ./resources/
COPY server_settings.ini ./
COPY oauth_settings.ini ./
COPY client_settings.ini ./
COPY ssl/* ./ssl/

CMD ["python", "-u", "./main.py"]