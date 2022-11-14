FROM ubuntu
RUN apt update
RUN apt install python3-pip -y
RUN pip3 install flask


COPY requeriments.txt ./
COPY client_secret.json ./


RUN pip install mysql-connector-python
RUN pip3 install -r requeriments.txt

WORKDIR /app
COPY . .

CMD ["python3","-m","flask","run","--host=0.0.0.0"]