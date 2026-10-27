// utils/secureQuery.js or in your server file
const secureQuery = async (query, params = {}, options = {}) => {
  const defaults = {
    timeout: 10000,
    maxRows: 1000,
    paramValidation: true
  };
  
  const settings = { ...defaults, ...options };
  
  if (settings.paramValidation) {
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && value.length > 1000) {
        throw new Error(`Parameter ${key} exceeds maximum length`);
      }
    }
  }
  
  if (!query.includes('LIMIT') && settings.maxRows) {
    query += ` LIMIT ${settings.maxRows}`;
  }
  
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Query timeout'));
    }, settings.timeout);

    clickhouse.query(query, { params })
      .toPromise()
      .then(data => {
        clearTimeout(timeout);
        resolve(data);
      })
      .catch(err => {
        clearTimeout(timeout);
        reject(err);
      });
  });
};

module.exports = secureQuery;