const { ClickHouse } = require('clickhouse');

const clickhouseConfig = {
    url: 'http://localhost',
    port: 8123, // Correct port for HTTP
    debug: false,
    basicAuth: {
        username: 'default',
        password: '',
    },
    isUseGzip: false,
    format: "json",
    raw: false,
    config: {
        database: 'default',
    }
};

const clickhouse = new ClickHouse(clickhouseConfig);

async function getMaxIdFromWebData() {
    try {
        // Ensure the query matches the structure of your database and data
        // const result = await clickhouse.query('SELECT MAX(id) AS max_id FROM web_data').toPromise();

        const result = await clickhouse.query('SELECT max(id) FROM webdata_10').toPromise();

        // const maxId = result.data[0].max_id; // Correctly parse based on the response structure
        const maxId = result[0]['max(id)'];
        console.log("Max ID from webdata_10:", maxId);
        return maxId || 0;
    } catch (error) {
        console.error('Error getting max ID from webdata_10:', error);
        return 0; // Default to 0 in case of any error.
    }
}

async function executeQueries() {
    try {
        const maxId = await getMaxIdFromWebData();
        console.log('Max ID from webdata_10:', maxId);

        // Query 1: Insert data from tracking7 into web_data
        await clickhouse.query(`
            INSERT INTO webdata_10
            SELECT *
            FROM tracking10
            WHERE id > ${maxId}
        `).toPromise();
        console.log("Updated webdata_10");

        // Query 2: Insert data into MOBILES2
        // await clickhouse.query(`DROP TABLE IF EXISTS MOBILES8`).toPromise();

        // await clickhouse.query(`CREATE TABLE MOBILES8
        // (
        //     ip_address String,
        //     timestamp DateTime64(3, 'UTC'),
        //     url String,
        //     session_id String,
        //     browser_id String,
        //     fingerprint_id String,
        //     mobile_numbers Array(String)
        // )
        // ENGINE = MergeTree
        // ORDER BY (session_id, ip_address)
        // SETTINGS index_granularity = 8192

        // `).toPromise();


        // remaining
        // await clickhouse.query(`
        // INSERT INTO MOBILES10
        // SELECT
        //     ip_address,
        //     timestamp,
        //     url,
        //     session_id,
        //     browser_id,
        //     fingerprint_id,
        //     extractAll(url, '\\\\b\\\\d{10}\\\\b') AS mobile_numbers 
        // FROM webdata_10
        // WHERE match(url, '\\\\b\\\\d{10}\\\\b') = 1 AND id > ${maxId}
        // `).toPromise();
        // console.log("Done updating MOBILES10");

        // await clickhouse.query(
        // `INSERT INTO MOBILES10 SELECT ip_address,timestamp,url,session_id,browser_id,fingerprint_id,mobile_numbers
        //  FROM (SELECT ip_address,timestamp,url,session_id,browser_id,fingerprint_id,extractAll(url,'\\b\\d{10}\\b') AS mobile_numbers,ROW_NUMBER() 
        //  OVER (PARTITION BY extractAll(url,'\\b\\d{10}\\b') ORDER BY timestamp) AS rn FROM webdata_10 WHERE match(url,'\\b\\d{10}\\b')=1 
        //  AND id>${maxId}) sub WHERE rn=1;`
        // ).toPromise();

        // await clickhouse.query(`
        // INSERT INTO MOBILES10 SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, mobile_numbers FROM
        // (SELECT ip_address, timestamp,url, session_id, browser_id,fingerprint_id, extractAll(url, '\\\\b\\\\d{10}\\\\b') 
        // AS mobile_numbers, ROW_NUMBER() OVER (PARTITION BY extractAll(url, '\\\\b\\\\d{10}\\\\b')
        // ORDER BY timestamp) AS rn,id FROM webdata_10 WHERE match(url, '\\\\b\\\\d{10}\\\\b') = 1 ) sub WHERE rn = 1;
        // `).toPromise();






        // old query 16 August 2024

        // await clickhouse.query(`
        // INSERT INTO MOBILES10 SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, mobile_numbers FROM
        // (SELECT ip_address, timestamp,url, session_id, browser_id,fingerprint_id, extractAll(url, '\\\\b\\\\d{10}\\\\b') 
        // AS mobile_numbers, ROW_NUMBER() OVER (PARTITION BY extractAll(url, '\\\\b\\\\d{10}\\\\b')
        // ORDER BY timestamp) AS rn,id FROM webdata_10 WHERE match(url, '\\\\b\\\\d{10}\\\\b') = 1 AND id >${maxId} ) sub WHERE rn = 1;
        // `).toPromise();


        // old query 16 August 2024 next version


        // await clickhouse.query(`
        //     INSERT INTO MOBILES10 
        //     SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, mobile_numbers 
        //     FROM (
        //         SELECT 
        //             ip_address, 
        //             timestamp, 
        //             url, 
        //             session_id, 
        //             browser_id, 
        //             fingerprint_id, 
        //             extractAll(url, '\\\\b[6789]\\\\d{9}\\\\b') AS mobile_numbers, 
        //             ROW_NUMBER() OVER (PARTITION BY extractAll(url, '\\\\b[6789]\\\\d{9}\\\\b') ORDER BY timestamp) AS rn, 
        //             id 
        //         FROM 
        //             webdata_10 
        //         WHERE 
        //             match(url, '\\\\b[6789]\\\\d{9}\\\\b') = 1 
        //             AND id > ${maxId}
        //     ) sub 
        //     WHERE rn = 1;
        // `).toPromise();

        await clickhouse.query(`
            INSERT INTO MOBILES10 
            SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, mobile_numbers 
            FROM (
                SELECT 
                    ip_address, 
                    timestamp, 
                    url, 
                    session_id, 
                    browser_id, 
                    fingerprint_id, 
                    extractAll(url, '\\\\b[6789]\\\\d{9}\\\\b') AS mobile_numbers, 
                    ROW_NUMBER() OVER (
                        PARTITION BY extractAll(url, '\\\\b[6789]\\\\d{9}\\\\b'), timestamp, session_id, browser_id 
                        ORDER BY timestamp
                    ) AS rn, 
                    id 
                FROM 
                    webdata_10 
                WHERE 
                    match(url, '\\\\b[6789]\\\\d{9}\\\\b') = 1 
                    AND id > ${maxId}
            ) sub 
            WHERE rn = 1;
        `).toPromise();





        console.log("Done updating MOBILES10");



        // // Query 3: Insert data into urls_with_mobile
        await clickhouse.query(`
        INSERT INTO urls_with_mobile10
        SELECT wd.*
        FROM webdata_10 AS wd
        INNER JOIN MOBILES10 AS m ON wd.session_id = m.session_id
        WHERE wd.id > ${maxId}
        `).toPromise();
        console.log("Done updating urls_with_mobile");


        // New Query 1: Insert data into EMAILS
        // await clickhouse.query(`
        //     INSERT INTO EMAILS9
        //     SELECT
        //         ip_address,
        //         timestamp,
        //         url,
        //         session_id,
        //         browser_id,
        //         fingerprint_id,
        //         extractAll(url, '[\\w\\.-]+@[\\w\\.-]+') AS email_addresses
        //     FROM web_data9
        //     WHERE match(url, '[\\w\\.-]+@[\\w\\.-]+') = 1 AND id > ${maxId}
        // `).toPromise();
        // console.log("Done updating EMAILS9");

        // INSERT INTO EMAILS9 SELECT ip_address, MIN(timestamp), url, session_id, browser_id, fingerprint_id, email_addresses FROM
        //  (SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, arrayDistinct(extractAll(url, '[\w\.-]+@[\w\.-]+'))
        //  AS email_addresses FROM web_data9 WHERE match(url, '[\w\.-]+@[\w\.-]+') = 1 AND ip_address != '') GROUP BY ip_address, url, session_id,
        //  browser_id, fingerprint_id, email_addresses;


        // working query 

        //         await clickhouse.query(`
        //     INSERT INTO EMAILS9 SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, extractAll(url, '[\\w\\.-]+@[\\w\\.-]+') 
        //     AS email_addresses FROM (SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, extractAll(url, '[\\w\\.-]+@[\\w\\.-]+')
        //     AS email_addresses, ROW_NUMBER() OVER (PARTITION BY extractAll(url, '[\\w\\.-]+@[\\w\\.-]+') ORDER BY timestamp) AS rn FROM web_data9 
        //     WHERE match(url, '[\\w\\.-]+@[\\w\\.-]+') = 1) sub WHERE rn = 1;
        // `).toPromise();

        // old query 16 August 2024


        //     await clickhouse.query(`
        //     INSERT INTO EMAILS10 
        //     SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, email_addresses
        //     FROM (
        //         SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, extractAll(url, '[\\w\\.-]+@[\\w\\.-]+') AS email_addresses, ROW_NUMBER() OVER (PARTITION BY extractAll(url, '[\\w\\.-]+@[\\w\\.-]+') ORDER BY timestamp) AS rn 
        //         FROM webdata_10 
        //         WHERE match(url, '[\\w\\.-]+@[\\w\\.-]+') = 1 AND id > ${maxId}
        //     ) sub 
        //     WHERE rn = 1;
        // `).toPromise();

        await clickhouse.query(`
            INSERT INTO EMAILS10 
            SELECT ip_address, timestamp, url, session_id, browser_id, fingerprint_id, email_addresses
            FROM (
                SELECT 
                    ip_address, 
                    timestamp, 
                    url, 
                    session_id, 
                    browser_id, 
                    fingerprint_id, 
                    extractAll(url, '\\\\b[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,6}\\\\b') AS email_addresses, 
                    ROW_NUMBER() OVER (
                        PARTITION BY extractAll(url, '\\\\b[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,6}\\\\b'), timestamp, session_id, browser_id 
                        ORDER BY timestamp
                    ) AS rn 
                FROM 
                    webdata_10 
                WHERE 
                    match(url, '\\\\b[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,6}\\\\b') = 1 
                    AND id > ${maxId}
            ) sub 
            WHERE rn = 1;
        `).toPromise();
        


        console.log("Done updating EMAILS10");

        // New Query 2: Insert data into urls_with_emails
        await clickhouse.query(`
            INSERT INTO urls_with_emails10
            SELECT wd.*
            FROM webdata_10 AS wd
            INNER JOIN EMAILS10 AS m ON wd.session_id = m.session_id
            WHERE wd.id > ${maxId}
        `).toPromise();
        console.log("Done updating urls_with_emails10");

    } catch (error) {
        console.error('Error executing queries:', error);
    }
}

// Main function
(async () => {
    await executeQueries();
})();


