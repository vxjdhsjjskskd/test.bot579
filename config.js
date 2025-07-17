// Конфигурация приложения
const config = {
    // Основные настройки
    bot: {
        token: process.env.BOT_TOKEN,
        polling: {
            interval: 300,
            autoStart: true,
            params: {
                timeout: 10
            }
        }
    },
    
    // Настройки VirusTotal API
    virustotal: {
        apiKey: process.env.VIRUSTOTAL_API_KEY,
        baseUrl: 'https://www.virustotal.com/api/v3',
        limits: {
            maxFileSize: 32 * 1024 * 1024, // 32MB
            maxRequestsPerMinute: 4, // Лимит для бесплатного API
            analysisTimeout: 300000 // 5 минут максимум на анализ
        }
    },
    
    // Настройки сервера
    server: {
        port: process.env.PORT || 3000,
        host: '0.0.0.0'
    },
    
    // Настройки файлов
    files: {
        tempDir: './temp',
        allowedExtensions: [
            '.exe', '.dll', '.msi', '.deb', '.rpm', '.dmg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.js', '.html', '.css', '.php', '.py', '.java',
            '.apk', '.ipa', '.jar'
        ]
    },
    
    // Настройки таймаутов
    timeouts: {
        analysisCheck: 10000, // 10 секунд между проверками
        maxAnalysisTime: 300000, // 5 минут максимум
        httpRequest: 30000 // 30 секунд для HTTP запросов
    },
    
    // Сообщения
    messages: {
        welcome: `🤖 *Добро пожаловать в VirusTotal Bot!*

Я помогу вам проверить файлы, ссылки и IP-адреса на вирусы и угрозы.

*Что я умею:*
📁 Проверять файлы (до 32MB)
🔗 Сканировать URL-адреса
🌐 Анализировать IP-адреса

*Как использовать:*
• Отправьте файл для проверки
• Отправьте ссылку в сообщении
• Отправьте IP-адрес

*Команды:*
/start - Показать это сообщение
/help - Помощь по использованию
/status - Статус бота`,
        
        help: `ℹ️ *Помощь по использованию*

*Поддерживаемые форматы файлов:*
• Исполняемые файлы (.exe, .dll, .msi)
• Документы (.pdf, .doc, .docx)
• Архивы (.zip, .rar, .7z)
• Изображения (.jpg, .png, .gif)
• Мобильные приложения (.apk, .ipa)
• И многие другие

*Ограничения:*
• Максимальный размер файла: 32MB
• Бесплатный API имеет лимиты запросов
• Анализ может занять некоторое время

*Примеры использования:*
1. Отправьте файл как вложение
2. Отправьте: https://example.com
3. Отправьте: 8.8.8.8

*Безопасность:*
• Файлы удаляются после анализа
• Данные не сохраняются
• Используется официальный API VirusTotal`,
        
        unknownFormat: `❓ *Неизвестный формат данных*

Пожалуйста, отправьте:
• 📁 Файл для проверки
• 🔗 Валидный URL (например: https://example.com)
• 🌐 IP-адрес (например: 8.8.8.8)

Или используйте /help для получения справки.`
    }
};

// Проверка обязательных переменных
function validateConfig() {
    const required = ['BOT_TOKEN', 'VIRUSTOTAL_API_KEY'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error('❌ Отсутствуют обязательные переменные окружения:');
        missing.forEach(key => console.error(`   - ${key}`));
        process.exit(1);
    }
    
    console.log('✅ Конфигурация валидна');
}

module.exports = { config, validateConfig };
