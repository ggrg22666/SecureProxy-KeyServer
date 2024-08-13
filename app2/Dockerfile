# Dockerfile для клиента API
FROM python:3.11

# Установка зависимостей
WORKDIR /app2
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Копирование исходного кода
COPY . .

# Команда для запуска приложения
CMD ["python", "app2.py"]

