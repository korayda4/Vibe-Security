# Test fixture — vulnerable Dockerfile

FROM node:latest

WORKDIR /app

# CI-003: no USER directive → runs as root
# CI-001: ADD with URL → MITM risk
ADD https://get.example.com/installer.sh /tmp/

COPY . .

RUN npm install

EXPOSE 3000
CMD ["npm", "start"]
