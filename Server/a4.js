// require('dotenv').config(); // Load environment variables

// const express = require('express');
// const bodyParser = require('body-parser');
// const axios = require('axios');
// const { ClickHouse } = require('clickhouse');

// const app = express();
// app.use(bodyParser.json());

// const clickhouse = new ClickHouse({
//   url: 'http://0.0.0.0',  // Listen on all network interfaces
//   port: 8123,
//   debug: false,
//   basicAuth: null,
//   isUseGzip: false,
//   format: "json",
//   raw: false,
//   config: {
//     session_timeout: 60,
//     output_format_json_quote_64bit_integers: 0,
//     enable_http_compression: 0
//   }
// });

// app.get('/nudge-sessions', async (req, res) => {
//   const password = req.query.password;

//   // Uncomment the password check if needed
//   // if (password !== 'BRMBLUBT') {
//   //   return res.status(403).json({ success: false, message: 'Forbidden: Incorrect password.' });
//   // }

//   const query1 = req.query.query1; // Get the query parameter
//   const nudgeMessage = req.query.message || 'Default nudge message if none provided';

//   console.log('New Query received is:', query1);
//   console.log(`Query Parameters: ${JSON.stringify(req.query)}`); // Log all query parameters

//   try {
//     // Execute the custom query passed as a parameter
//     const result = await clickhouse.query(query1).toPromise();
//     console.log('Custom Query Executed'); // Log after query execution
//     console.log('Custom Query Result:', result); // Log the result of the custom query

//     // Remove duplicate session IDs
//     const uniqueSessions = [...new Set(result.map(row => row.session_id))];

//     console.log('Unique Sessions:', uniqueSessions); // Log unique session IDs

//     // Trigger nudges for all unique sessions
//     const nudgePromises = uniqueSessions.map(sessionId => {
//       return axios.post('http://0.0.0.0:8000/message', { sessionId, message: nudgeMessage })
//         .then(response => {
//           console.log(`Nudge sent to session ${sessionId}:`, response.data);
//           return sessionId; // Return sessionId for further logging
//         })
//         .catch(error => {
//           console.error(`Error sending nudge to session ${sessionId}:`, error);
//           return null; // Return null if there's an error
//         });
//     });

//     const nudgeResults = await Promise.all(nudgePromises);
//     const successfulNudges = nudgeResults.filter(sessionId => sessionId !== null);
//     console.log('Sessions that received a nudge:', successfulNudges);

//     res.json({ success: true, message: 'Nudges sent successfully.', nudgedSessions: successfulNudges });
//   } catch (error) {
//     console.error('Error in /nudge-sessions endpoint:', error);
//     res.status(500).send('Internal Server Error');
//   }
// });

// const PORT = process.env.PORT || 8001;
// app.listen(PORT, '0.0.0.0', () => {  // Listen on all network interfaces
//   console.log(`Server is running on port ${PORT}`);
// })

require('dotenv').config(); // Load environment variables

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { ClickHouse } = require('clickhouse');

const app = express();
app.use(bodyParser.json());

const clickhouse = new ClickHouse({
  url: 'http://0.0.0.0',  // Listen on all network interfaces
  port: 8123,
  debug: false,
  basicAuth: {
    username: 'default',
    password: '',
  },
  isUseGzip: false,
  format: "json",
  raw: false,
  config: {
    session_timeout: 60,
    output_format_json_quote_64bit_integers: 0,
    enable_http_compression: 0
  }
});

app.get('/nudge-sessions', async (req, res) => {
  const password = req.query.password;

  // Uncomment the password check if needed
  // if (password !== 'BRMBLUBT') {
  //   return res.status(403).json({ success: false, message: 'Forbidden: Incorrect password.' });
  // }

  const query1 = req.query.query1; // Get the query parameter
  const nudgeMessage = req.query.message || 'Default nudge message if none provided';

  console.log('New Query received is:', query1);
  console.log(`Query Parameters: ${JSON.stringify(req.query)}`); // Log all query parameters

  try {
    // Execute the custom query passed as a parameter
    const result = await clickhouse.query(query1).toPromise();
    console.log('Custom Query Executed'); // Log after query execution
    console.log('Custom Query Result:', result); // Log the result of the custom query

    // Remove duplicate session IDs
    const uniqueSessions = [...new Set(result.map(row => row.session_id))];

    console.log('Unique Sessions:', uniqueSessions); // Log unique session IDs

    // Trigger nudges for all unique sessions
    const nudgePromises = uniqueSessions.map(sessionId => {
      return axios.post('http://0.0.0.0:8000/message', { sessionId, message: nudgeMessage })
        .then(response => {
          console.log(`Nudge sent to session ${sessionId}:`, response.data);
          return sessionId; // Return sessionId for further logging
        })
        .catch(error => {
          console.error(`Error sending nudge to session ${sessionId}:`, error);
          return null; // Return null if there's an error
        });
    });

    const nudgeResults = await Promise.all(nudgePromises);
    const successfulNudges = nudgeResults.filter(sessionId => sessionId !== null);
    console.log('Sessions that received a nudge:', successfulNudges);

    res.json({ success: true, message: 'Nudges sent successfully.', nudgedSessions: successfulNudges });
  } catch (error) {
    console.error('Error in /nudge-sessions endpoint:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/terminate-sessions', async (req, res) => {
  const password = req.query.password;

  // Uncomment the password check if needed
  // if (password !== 'BRMBLUBT') {
  //   return res.status(403).json({ success: false, message: 'Forbidden: Incorrect password.' });
  // }

  const query1 = req.query.query1; // Get the query parameter

  console.log('New Query received is:', query1);
  console.log(`Query Parameters: ${JSON.stringify(req.query)}`); // Log all query parameters

  try {
    // Execute the custom query passed as a parameter
    const result = await clickhouse.query(query1).toPromise();
    console.log('Custom Query Executed'); // Log after query execution
    console.log('Custom Query Result:', result); // Log the result of the custom query

    // Remove duplicate session IDs
    const uniqueSessions = [...new Set(result.map(row => row.session_id))];

    console.log('Unique Sessions:', uniqueSessions); // Log unique session IDs

    // Terminate sessions for all unique session IDs
    const terminatePromises = uniqueSessions.map(sessionId => {
      return axios.post('http://0.0.0.0:8000/terminate-session', { sessionId })
        .then(response => {
          console.log(`Session terminated ${sessionId}:`, response.data);
          return sessionId; // Return sessionId for further logging
        })
        .catch(error => {
          console.error(`Error terminating session ${sessionId}:`, error);
          return null; // Return null if there's an error
        });
    });

    const terminateResults = await Promise.all(terminatePromises);
    const successfulTerminations = terminateResults.filter(sessionId => sessionId !== null);
    console.log('Sessions that were terminated:', successfulTerminations);

    res.json({ success: true, message: 'Sessions terminated successfully.', terminatedSessions: successfulTerminations });
  } catch (error) {
    console.error('Error in /terminate-sessions endpoint:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/mass-captcha', async (req, res) => {
  const query1 = req.query.query1; // Get the query parameter
  const captchaMessage = req.query.message || 'Solve the CAPTCHA to continue.'; // Custom message

  console.log('New Query received is:', query1);
  console.log('Query Parameters:', JSON.stringify(req.query)); // Log all query parameters

  try {
    // Execute the custom query passed as a parameter
    const result = await clickhouse.query(query1).toPromise();
    console.log('Custom Query Executed'); // Log after query execution
    console.log('Custom Query Result:', result); // Log the result of the custom query

    // Remove duplicate session IDs
    const uniqueSessions = [...new Set(result.map(row => row.session_id))];

    console.log('Unique Sessions:', uniqueSessions); // Log unique session IDs

    // Send CAPTCHA for all unique sessions
    const captchaPromises = uniqueSessions.map(sessionId => {
      return axios.post('http://0.0.0.0:8000/send-captcha', { sessionId })
        .then(response => {
          console.log(`CAPTCHA sent to session ${sessionId}:`, response.data);
          return sessionId; // Return sessionId for further logging
        })
        .catch(error => {
          console.error(`Error sending CAPTCHA to session ${sessionId}:`, error);
          return null; // Return null if there's an error
        });
    });

    const captchaResults = await Promise.all(captchaPromises);
    const successfulCaptchas = captchaResults.filter(sessionId => sessionId !== null);
    console.log('Sessions that received CAPTCHA:', successfulCaptchas);

    res.json({ success: true, message: 'CAPTCHA sent successfully.', captchaSessions: successfulCaptchas });
  } catch (error) {
    console.error('Error in /mass-captcha endpoint:', error);
    res.status(500).send('Internal Server Error');
  }
});


const PORT = process.env.PORT || 8001;
app.listen(PORT, '0.0.0.0', () => {  // Listen on all network interfaces
  console.log(`Server is running on port ${PORT}`);
});
