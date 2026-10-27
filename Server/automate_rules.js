
const { ClickHouse } = require('clickhouse');
const axios = require('axios');

const clickhouse = new ClickHouse({
    url: 'http://localhost',
    port: 8123,
    debug: false,
    basicAuth: {
        username: 'default',
        password: '',
    },
    isUseGzip: false,
    format: 'json', // 'json' or 'csv'
    config: {
        session_timeout: 60,
        output_format_json_quote_64bit_integers: 0,
        enable_http_compression: 0,
    },
});

async function fetchRules() {
    const query = "SELECT rule, action, action_time FROM rules WHERE action_time = 0";
    try {
        return await clickhouse.query(query).toPromise();
    } catch (err) {
        console.error('Error fetching rules:', err);
        return [];
    }
}


async function logAction(action, sessionIds) {
    if (!sessionIds || sessionIds.length === 0) {
        console.log(`No sessions to log for action: ${action}`);
        return;
    }
    
    // Format the timestamp to remove timezone information
    // const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 23); // Keep up to milliseconds, remove 'Z'
    const timestamp = new Date().toISOString().replace('T', ' ').split('.')[0]; // Excludes milliseconds

    
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
        return false; // Assume not performed in case of error
    }
}


async function performAction(rule) {
    let url;
    switch (rule.action) {
        case 'terminate':
            url = `http://64.227.151.232:8001/terminate-sessions?query1=${encodeURIComponent(rule.rule)}`;
            await performSingleAction(rule.action, url);
            break;
        case 'nudge':
        case 'captcha':
            // Fetch sessions from the query
            const sessions = await fetchSessions(rule.rule);
            const filteredSessions = [];
            for (const session of sessions) {
                const alreadyPerformed = await checkActionLog(rule.action, session.session_id);
                if (!alreadyPerformed) {
                    filteredSessions.push(session.session_id);
                } else {
                    console.log(`Skipping ${rule.action} for session: ${session.session_id} (already performed)`);
                }
            }
            
            if (filteredSessions.length > 0) {
                const sessionsQuery = `SELECT session_id FROM tracking10 WHERE session_id IN ('${filteredSessions.join("','")}')`;
                if (rule.action === 'nudge') {
                    url = `http://64.227.151.232:8001/nudge-sessions?message=Your%20Custom%20Nudge%20Message&query1=${encodeURIComponent(sessionsQuery)}`;
                } else if (rule.action === 'captcha') {
                    url = `http://64.227.151.232:8001/mass-captcha?message=Solve%20the%20CAPTCHA%20to%20continue.&query1=${encodeURIComponent(sessionsQuery)}`;
                }
                await performSingleAction(rule.action, url, filteredSessions);
            } else {
                console.log(`No sessions to perform ${rule.action} on after filtering already performed actions.`);
            }
            break;
        case 'block_page':
            url = `http://client-homepage.com?redirect_from=${encodeURIComponent(rule.rule)}`;
            console.log(`Redirecting based on rule: ${rule.rule}`);
            break;
        default:
            console.error(`Unknown action: ${rule.action}`);
    }
}

async function performSingleAction(action, url, sessionIds = null) {
    try {
        const response = await axios.get(url);
        if (response.status === 200) {
            console.log(`Successfully performed action: ${action}`);
            if (response.data && (response.data.terminatedSessions || sessionIds)) {
                const sessions = sessionIds || response.data.terminatedSessions;
                await logAction(action, sessions);
            } else {
                console.log('No sessions were affected or data is missing');
            }
        } else {
            console.error(`Failed to perform action: ${action}. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error performing action: ${action}`, error.message);
        if (error.response) {
            console.error('Error response:', error.response.data);
        }
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
            const rules = await fetchRules();
            for (const rule of rules) {
                await performAction(rule);
            }
        } catch (error) {
            console.error('Error in main loop:', error.message);
        }
        // Sleep for a short duration before checking again
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

main().catch(console.error);
