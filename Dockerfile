FROM python:3.11-alpine

LABEL MAINTAINER="Pedro Nunes <pjn2work@google.com>"

EXPOSE 25050/tcp

WORKDIR /opt/capy/
COPY src .

RUN apk add gcc linux-headers musl-dev libffi-dev openssl-dev
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "capy.py"]
