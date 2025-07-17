const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Получаем переменные из настроек Pella
const BOT_TOKEN = process.env.BOT_TOKEN;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Создаем экземпляр бота
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// Базовые URL для VirusTotal API v3
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

// Функция для проверки файла
async function scanFile(filePath, fileName) {
    try {
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));
        
        const response = await axios.post(`${VT_BASE_URL}/files`, form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': VIRUSTOTAL_API_KEY
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Ошибка при сканировании файла:', error.message);
        throw error;
    }
}

// Функция для проверки URL
async function scanUrl(url) {
    try {
        const form = new FormData();
        form.append('url', url);
        
        const response = await axios.post(`${VT_BASE_URL}/urls`, form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': VIRUSTOTAL_API_KEY
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Ошибка при сканировании URL:', error.message);
        throw error;
    }
}

// Функция для проверки IP
async function getIpReport(ip) {
    try {
        const response = await axios.get(`${VT_BASE_URL}/ip_addresses/${ip}`, {
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Ошибка при получении отчета IP:', error.message);
        throw error;
    }
}

// Функция для получения результатов анализа
async function getAnalysisResult(analysisId) {
    try {
        const response = await axios.get(`${VT_BASE_URL}/analyses/${analysisId}`, {
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Ошибка при получении результатов анализа:', error.message);
        throw error;
    }
}

// Функция для форматирования отчета
function formatReport(data, type) {
    const stats = data.data.attributes.stats || {};
    const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
    
    let report = `🔍 *Отчет VirusTotal*\n\n`;
    report += `📊 *Результаты сканирования:*\n`;
    report += `✅ Безопасно: ${stats.harmless || 0}\n`;
    report += `❌ Вредоносно: ${stats.malicious || 0}\n`;
    report += `⚠️ Подозрительно: ${stats.suspicious || 0}\n`;
    report += `❓ Не обнаружено: ${stats.undetected || 0}\n`;
    report += `📈 Всего проверено: ${total}\n\n`;
    
    if (type === 'ip') {
        const attributes = data.data.attributes;
        report += `🌐 *IP информация:*\n`;
        report += `📍 Страна: ${attributes.country || 'Неизвестно'}\n`;
        report += `🏢 Владелец: ${attributes.as_owner || 'Неизвестно'}\n`;
        report += `🏷️ Репутация: ${attributes.reputation || 0}\n`;
    }
    
    // Добавляем информацию о наиболее опасных обнаружениях
    if (data.data.attributes.scans) {
        const maliciousScans = Object.entries(data.data.attributes.scans)
            .filter(([_, scan]) => scan.detected && scan.result)
            .slice(0, 5);
            
        if (maliciousScans.length > 0) {
            report += `\n🚨 *Обнаружения:*\n`;
            maliciousScans.forEach(([engine, scan]) => {
                report += `• ${engine}: ${scan.result}\n`;
            });
        }
    }
    
    return report;
}

// Проверка валидности IP
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

// Проверка валидности URL
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Обработчик команды /start
bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const welcomeMessage = `
🤖 *Добро пожаловать в VirusTotal Bot!*

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
    `;
    
    bot.sendMessage(chatId, welcomeMessage, { parse_mode: 'Markdown' });
});

// Обработчик команды /help
bot.onText(/\/help/, (msg) => {
    const chatId = msg.chat.id;
    const helpMessage = `
ℹ️ *Помощь по использованию*

*Поддерживаемые форматы файлов:*
• Исполняемые файлы (.exe, .dll, .msi)
• Документы (.pdf, .doc, .docx)
• Архивы (.zip, .rar, .7z)
• Изображения (.jpg, .png, .gif)
• И многие другие

*Ограничения:*
• Максимальный размер файла: 32MB
• Бесплатный API имеет лимиты запросов
• Анализ может занять некоторое время

*Примеры использования:*
1. Отправьте файл как вложение
2. Отправьте: https://example.com
3. Отправьте: 8.8.8.8
    `;
    
    bot.sendMessage(chatId, helpMessage, { parse_mode: 'Markdown' });
});

// Обработчик файлов
bot.on('document', async (msg) => {
    const chatId = msg.chat.id;
    const file = msg.document;
    
    // Проверяем размер файла (32MB лимит для бесплатного API)
    if (file.file_size > 32 * 1024 * 1024) {
        bot.sendMessage(chatId, '❌ Файл слишком большой! Максимальный размер: 32MB');
        return;
    }
    
    const processingMsg = await bot.sendMessage(chatId, '🔄 Загружаю файл для анализа...');
    
    try {
        // Получаем информацию о файле
        const fileInfo = await bot.getFile(file.file_id);
        const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${fileInfo.file_path}`;
        
        // Создаем временный файл
        const tempDir = path.join(__dirname, 'temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir);
        }
        
        const tempFilePath = path.join(tempDir, `${Date.now()}_${file.file_name}`);
        
        // Скачиваем файл
        const response = await axios({
            method: 'GET',
            url: fileUrl,
            responseType: 'stream'
        });
        
        const writer = fs.createWriteStream(tempFilePath);
        response.data.pipe(writer);
        
        await new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
        });
        
        // Отправляем на анализ
        await bot.editMessageText('📤 Отправляю файл в VirusTotal...', {
            chat_id: chatId,
            message_id: processingMsg.message_id
        });
        
        const scanResult = await scanFile(tempFilePath, file.file_name);
        const analysisId = scanResult.data.id;
        
        // Ждем результаты анализа
        await bot.editMessageText('⏳ Анализирую файл... Это может занять некоторое время.', {
            chat_id: chatId,
            message_id: processingMsg.message_id
        });
        
        let analysisComplete = false;
        let attempts = 0;
        const maxAttempts = 30; // 5 минут максимум
        
        while (!analysisComplete && attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 10000)); // Ждем 10 секунд
            
            try {
                const analysisResult = await getAnalysisResult(analysisId);
                
                if (analysisResult.data.attributes.status === 'completed') {
                    analysisComplete = true;
                    
                    // Удаляем сообщение о процессе
                    await bot.deleteMessage(chatId, processingMsg.message_id);
                    
                    // Отправляем отчет
                    const report = formatReport(analysisResult, 'file');
                    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
                    
                    // Отправляем ссылку на подробный отчет
                    const reportUrl = `https://www.virustotal.com/gui/file/${analysisResult.data.id}/detection`;
                    await bot.sendMessage(chatId, `🔗 [Подробный отчет на VirusTotal](${reportUrl})`, { parse_mode: 'Markdown' });
                }
            } catch (error) {
                console.error('Ошибка при получении результатов:', error);
            }
            
            attempts++;
        }
        
        if (!analysisComplete) {
            await bot.editMessageText('⏰ Анализ занимает больше времени чем ожидалось. Попробуйте позже.', {
                chat_id: chatId,
                message_id: processingMsg.message_id
            });
        }
        
        // Удаляем временный файл
        fs.unlinkSync(tempFilePath);
        
    } catch (error) {
        console.error('Ошибка при обработке файла:', error);
        await bot.editMessageText('❌ Произошла ошибка при анализе файла. Попробуйте позже.', {
            chat_id: chatId,
            message_id: processingMsg.message_id
        });
    }
});

// Обработчик текстовых сообщений (URL и IP)
bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text;
    
    // Игнорируем команды и сообщения с файлами
    if (!text || text.startsWith('/') || msg.document || msg.photo || msg.video) {
        return;
    }
    
    const trimmedText = text.trim();
    
    if (isValidURL(trimmedText)) {
        // Обрабатываем URL
        const processingMsg = await bot.sendMessage(chatId, '🔄 Анализирую URL...');
        
        try {
            const scanResult = await scanUrl(trimmedText);
            const analysisId = scanResult.data.id;
            
            // Ждем результаты
            await bot.editMessageText('⏳ Получаю результаты анализа...', {
                chat_id: chatId,
                message_id: processingMsg.message_id
            });
            
            let analysisComplete = false;
            let attempts = 0;
            const maxAttempts = 20;
            
            while (!analysisComplete && attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                try {
                    const analysisResult = await getAnalysisResult(analysisId);
                    
                    if (analysisResult.data.attributes.status === 'completed') {
                        analysisComplete = true;
                        
                        await bot.deleteMessage(chatId, processingMsg.message_id);
                        
                        const report = formatReport(analysisResult, 'url');
                        await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
                        
                        const reportUrl = `https://www.virustotal.com/gui/url/${analysisResult.data.id}/detection`;
                        await bot.sendMessage(chatId, `🔗 [Подробный отчет на VirusTotal](${reportUrl})`, { parse_mode: 'Markdown' });
                    }
                } catch (error) {
                    console.error('Ошибка при получении результатов URL:', error);
                }
                
                attempts++;
            }
            
            if (!analysisComplete) {
                await bot.editMessageText('⏰ Анализ занимает больше времени. Попробуйте позже.', {
                    chat_id: chatId,
                    message_id: processingMsg.message_id
                });
            }
            
        } catch (error) {
            console.error('Ошибка при анализе URL:', error);
            await bot.editMessageText('❌ Ошибка при анализе URL. Попробуйте позже.', {
                chat_id: chatId,
                message_id: processingMsg.message_id
            });
        }
        
    } else if (isValidIP(trimmedText)) {
        // Обрабатываем IP
        const processingMsg = await bot.sendMessage(chatId, '🔄 Анализирую IP-адрес...');
        
        try {
            const ipReport = await getIpReport(trimmedText);
            
            await bot.deleteMessage(chatId, processingMsg.message_id);
            
            const report = formatReport(ipReport, 'ip');
            await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
            
            const reportUrl = `https://www.virustotal.com/gui/ip-address/${trimmedText}/detection`;
            await bot.sendMessage(chatId, `🔗 [Подробный отчет на VirusTotal](${reportUrl})`, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Ошибка при анализе IP:', error);
            await bot.editMessageText('❌ Ошибка при анализе IP. Попробуйте позже.', {
                chat_id: chatId,
                message_id: processingMsg.message_id
            });
        }
        
    } else {
        // Неизвестный формат
        bot.sendMessage(chatId, `
❓ *Неизвестный формат данных*

Пожалуйста, отправьте:
• 📁 Файл для проверки
• 🔗 Валидный URL (например: https://example.com)
• 🌐 IP-адрес (например: 8.8.8.8)

Или используйте /help для получения справки.
        `, { parse_mode: 'Markdown' });
    }
});

// Обработка ошибок
bot.on('error', (error) => {
    console.error('Ошибка бота:', error);
});

// Обработка polling ошибок
bot.on('polling_error', (error) => {
    console.error('Polling error:', error);
});

console.log('🤖 VirusTotal Bot запущен!');
console.log('📡 Ожидаю сообщения...');
