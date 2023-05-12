# Common build stage
FROM --platform=linux/amd64 node:16

WORKDIR /app

COPY package*.json ./
COPY ./yarn.lock ./
RUN yarn


COPY . .
RUN yarn build

CMD yarn migrate && node dist/main
