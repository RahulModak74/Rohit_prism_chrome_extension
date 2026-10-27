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

async function fetchNudgeRules() {
    const query = "SELECT rule, action, action_time FROM rules WHERE action = 'nudge' AND action_time = 0";
    try {
        return await clickhouse.query(query).toPromise();
    } catch (err) {
        console.error('Error fetching nudge rules:', err);
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

async function checkActionLog(action, sessionId) {
    const query = `SELECT COUNT(*) AS count FROM action_logs WHERE action = '${action}' AND sessions LIKE '%${sessionId}%'`;
    try {
        const result = await clickhouse.query(query).toPromise();
        return result[0].count > 0;
    } catch (err) {
        console.error(`Error checking action log for ${action} on session ${sessionId}:`, err);
        return false;
    }
}

async function performNudgeAction(rule) {
    const sessions = await fetchSessions(rule.rule);
    const filteredSessions = [];
    
    for (const session of sessions) {
        const alreadyPerformed = await checkActionLog(rule.action, session.session_id);
        if (!alreadyPerformed) {
            filteredSessions.push(session.session_id);
        }
    }
    
    if (filteredSessions.length > 0) {
        const sessionsQuery = `SELECT session_id FROM tracking10 WHERE session_id IN ('${filteredSessions.join("','")}')`;
        const url = `http://13.201.62.72:8001/nudge-sessions?message=Your%20Custom%20Nudge%20Message&query1=${encodeURIComponent(sessionsQuery)}`;
        await performSingleAction(rule.action, url, filteredSessions);
    } else {
        console.log('No sessions to nudge after filtering already performed actions.');
    }
}

async function performSingleAction(action, url, sessionIds = null) {
    try {
        const response = await axios.get(url);
        if (response.status === 200) {
            console.log(`Successfully performed nudge action`);
            if (sessionIds) {
                await logAction(action, sessionIds);
            }
        } else {
            console.error(`Failed to perform nudge action. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error performing nudge action:`, error.message);
    }
}

async function fetchSessions(query) {
    try {
        return await clickhouse.query(query).toPromise();
    } catch (err) {
        console.error('Error fetching sessions:', err);
        return [];
    }
}

async function main() {
    while (true) {
        try {
            const rules = await fetchNudgeRules();
            for (const rule of rules) {
                await performNudgeAction(rule);
            }
        } catch (error) {
            console.error('Error in main loop:', error.message);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

main().catch(console.error);
