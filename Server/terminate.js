const { ClickHouse } = require('clickhouse');
const axios = require('axios');

const clickhouse = new ClickHouse({
    url: 'http://localhost',
    port: 8123,
    debug: false,
    basicAuth: {
        username: 'default',
        password: 'Welcome@Ganesh',
    },
    isUseGzip: false,
    format: 'json',
    config: {
        session_timeout: 60,
        output_format_json_quote_64bit_integers: 0,
        enable_http_compression: 0,
    },
});

async function fetchTerminateRules() {
    const query = "SELECT rule, action, action_time FROM rules WHERE action = 'terminate' AND action_time = 0";
    try {
        return await clickhouse.query(query).toPromise();
    } catch (err) {
        console.error('Error fetching terminate rules:', err);
        return [];
    }
}

async function logAction(action, sessionIds) {
    const timestamp = new Date().toISOString().replace('T', ' ').split('.')[0];
    const query = `INSERT INTO action_logs (action, timestamp, sessions) VALUES ('${action}', '${timestamp}', '${sessionIds.join(',')}')`;
    try {
        await clickhouse.query(query).toPromise();
        console.log(`Logged action: ${action} for sessions: ${sessionIds.join(', ')}`);
    } catch (err) {
        console.error(`Error logging action: ${action}`, err);
    }
}

async function performTerminateAction(rule) {
    const url = `http://13.201.62.72:8001/terminate-sessions?query1=${encodeURIComponent(rule.rule)}`;
    try {
        const response = await axios.get(url);
        if (response.status === 200) {
            console.log(`Successfully performed terminate action`);
            if (response.data && response.data.terminatedSessions) {
                await logAction(rule.action, response.data.terminatedSessions);
            } else {
                console.log('No sessions were terminated or data is missing');
            }
        } else {
            console.error(`Failed to perform terminate action. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error performing terminate action:`, error.message);
    }
}

async function main() {
    while (true) {
        try {
            const rules = await fetchTerminateRules();
            for (const rule of rules) {
                await performTerminateAction(rule);
            }
        } catch (error) {
            console.error('Error in main loop:', error.message);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

main().catch(console.error);
