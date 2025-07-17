const http = require('http');
const TelegramBot = require('node-telegram-bot-api');

// Простой HTTP сервер для health check
const server = http.createServer((req, res) => {
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            service: 'VirusTotal Telegram Bot'
        }));
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🏥 Health check server running on port ${PORT}`);
});

// Проверка подключения к Telegram API
function checkTelegramConnection() {
    const bot = new TelegramBot(process.env.BOT_TOKEN, { polling: false });
    
    return bot.getMe()
        .then(info => {
            console.log('✅ Telegram connection OK:', info.username);
            return true;
        })
        .catch(error => {
            console.error('❌ Telegram connection failed:', error.message);
            return false;
        });
}

// Проверка VirusTotal API
function checkVirusTotalConnection() {
    const axios = require('axios');
    
    return axios.get('https://www.virustotal.com/api/v3/users/me', {
        headers: {
            'x-apikey': process.env.VIRUSTOTAL_API_KEY
        }
    })
    .then(response => {
        console.log('✅ VirusTotal API connection OK');
        return true;
    })
    .catch(error => {
        console.error('❌ VirusTotal API connection failed:', error.response?.status || error.message);
        return false;
    });
}

// Запуск проверок при старте
setTimeout(async () => {
    console.log('🔍 Running health checks...');
    
    const telegramOK = await checkTelegramConnection();
    const virusTotalOK = await checkVirusTotalConnection();
    
    if (telegramOK && virusTotalOK) {
        console.log('✅ All systems operational');
    } else {
        console.log('⚠️ Some systems may have issues');
    }
}, 5000);

module.exports = server;
