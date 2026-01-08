FROM python:3.9

RUN pip install flask

WORKDIR /app
COPY . .

USER root            #  root user
EXPOSE 80

CMD ["python", "app.py"]
