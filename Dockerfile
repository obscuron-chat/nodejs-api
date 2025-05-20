FROM node:lts
RUN apt-get update && \
    apt-get install -y texlive texlive-latex-extra texlive-fonts-extra && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json /app
RUN npm install
COPY . /app
CMD ["node","app/index.js"]