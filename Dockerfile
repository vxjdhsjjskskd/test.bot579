FROM node:18-alpine

# Установка рабочей директории
WORKDIR /app

# Копирование package.json и package-lock.json
COPY package*.json ./

# Установка зависимостей
RUN npm ci --only=production && npm cache clean --force

# Копирование исходного кода
COPY . .

# Создание директории для временных файлов
RUN mkdir -p temp

# Создание пользователя для запуска приложения
RUN addgroup -g 1001 -S nodejs
RUN adduser -S botuser -u 1001
RUN chown -R botuser:nodejs /app
USER botuser

# Экспорт порта
EXPOSE 3000

# Проверка здоровья
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Команда запуска
CMD ["npm", "start"]
