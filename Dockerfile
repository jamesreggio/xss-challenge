FROM node:latest
ADD . /opt/xss-challenge
WORKDIR /opt/xss-challenge
RUN npm install --production
ENV VIRTUAL_HOST pets.web.hackfortress.net
EXPOSE 3000
CMD npm start
