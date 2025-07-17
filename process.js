// Graceful shutdown для корректного завершения работы бота
process.on('SIGTERM', () => {
    console.log('📴 Получен сигнал SIGTERM. Завершаю работу...');
    cleanup();
});

process.on('SIGINT', () => {
    console.log('📴 Получен сигнал SIGINT. Завершаю работу...');
    cleanup();
});

process.on('uncaughtException', (error) => {
    console.error('💥 Необработанная ошибка:', error);
    cleanup();
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Необработанный отказ промиса:', reason);
    console.error('В промисе:', promise);
    // Не завершаем процесс, просто логируем
});

function cleanup() {
    console.log('🧹 Очистка ресурсов...');
    
    // Очищаем временные файлы
    const tempDir = path.join(__dirname, 'temp');
    if (fs.existsSync(tempDir)) {
        try {
            const files = fs.readdirSync(tempDir);
            files.forEach(file => {
                const filePath = path.join(tempDir, file);
                fs.unlinkSync(filePath);
                console.log(`🗑️ Удален временный файл: ${file}`);
            });
        } catch (error) {
            console.error('Ошибка при очистке временных файлов:', error);
        }
    }
    
    console.log('✅ Очистка завершена');
    process.exit(0);
}

// Мониторинг памяти (для отладки)
setInterval(() => {
    const used = process.memoryUsage();
    const mb = (bytes) => Math.round(bytes / 1024 / 1024 * 100) / 100;
    
    console.log(`📊 Использование памяти: RSS: ${mb(used.rss)}MB, Heap: ${mb(used.heapUsed)}MB/${mb(used.heapTotal)}MB`);
}, 300000); // каждые 5 минут

module.exports = { cleanup };
