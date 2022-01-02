FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN apk add build-base
RUN pip3 install --no-cache-dir -r requirements.txt

COPY token_extractor.py ./

CMD [ "python", "./token_extractor.py" ]
