FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json .
RUN npm install

COPY src src

FROM node:20-alpine

WORKDIR /app

EXPOSE 3000

CMD [ "node", "dist/server.js" ]
