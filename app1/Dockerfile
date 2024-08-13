# Dockerfile для сервера токенов
FROM python:3.11

# Установка зависимостей
WORKDIR /app1
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Копирование исходного кода
COPY . .

# Команда для запуска приложения
CMD ["python", "app1.py"]

