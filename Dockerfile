FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .

RUN mkdir -p /data /app/uploads/public/icons

# 安装 zsign 用于重签名（可选）
ARG INSTALL_ZSIGN=true
RUN if [ "$INSTALL_ZSIGN" = "true" ]; then \
      apk add --no-cache make cmake g++ && \
      git clone https://github.com/tihmstar/zsign.git /tmp/zsign && \
      cd /tmp/zsign && \
      make && cp zsign /usr/local/bin/; \
    fi

EXPOSE 8080

ENV NODE_ENV=production
ENV PORT=8080

CMD ["node", "server/index.js"]
