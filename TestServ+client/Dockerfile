# Используем образ Python
FROM python:3.11

# Устанавливаем рабочую директорию
WORKDIR /pythonProject5

# Копируем файлы в контейнер
COPY . /pythonProject5

RUN pip install flask

# Запускаем приложение
CMD ["python", "TestServ.py"]
