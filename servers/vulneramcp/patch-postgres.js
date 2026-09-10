"use strict";
// Patched postgres.js — все функции обёрнуты в try/catch.
// PostgreSQL опционален: при отсутствии БД инструменты работают без сохранения.
Object.defineProperty(exports, "__esModule", { value: true });
exports.initPostgres = initPostgres;
exports.createTables = createTables;
exports.saveFinding = saveFinding;
exports.getFindings = getFindings;
exports.saveTestResult = saveTestResult;
exports.getTestResults = getTestResults;
exports.getTestStatistics = getTestStatistics;
exports.saveTrainingData = saveTrainingData;
exports.getTrainingData = getTrainingData;

let pool = null;

function initPostgres() {
    if (pool) return pool;
    try {
        const pg_1 = require("pg");
        pool = new pg_1.Pool({
            host: process.env.POSTGRES_HOST || 'localhost',
            port: parseInt(process.env.POSTGRES_PORT || '5433'),
            database: process.env.POSTGRES_DB || 'bugbounty',
            user: process.env.POSTGRES_USER || 'postgres',
            password: process.env.POSTGRES_PASSWORD ? String(process.env.POSTGRES_PASSWORD) : '',
            max: 5,
            idleTimeoutMillis: 10000,
            connectionTimeoutMillis: 2000,
        });
        pool.on('error', (err) => { /* silent */ });
        return pool;
    } catch (e) {
        return null;
    }
}

async function _query(fn) {
    try {
        const p = initPostgres();
        if (!p) return null;
        const client = await p.connect();
        try { return await fn(client); } finally { client.release(); }
    } catch (e) {
        console.error('PostgreSQL unavailable (optional):', e.message);
        return null;
    }
}

async function createTables() {
    return _query(async (client) => {
        await client.query(`
            CREATE TABLE IF NOT EXISTS findings (id SERIAL PRIMARY KEY, target VARCHAR(500), type VARCHAR(100), severity VARCHAR(20), description TEXT, payload TEXT, response TEXT, timestamp TIMESTAMP DEFAULT NOW(), score INTEGER, status VARCHAR(20) DEFAULT 'new', created_at TIMESTAMP DEFAULT NOW());
            CREATE TABLE IF NOT EXISTS test_results (id SERIAL PRIMARY KEY, target VARCHAR(500), test_type VARCHAR(100), success BOOLEAN, score INTEGER DEFAULT 0, result_data JSONB, error_message TEXT, payload TEXT, response_data TEXT, timestamp TIMESTAMP DEFAULT NOW());
            CREATE TABLE IF NOT EXISTS training_data (id SERIAL PRIMARY KEY, source VARCHAR(50), source_id VARCHAR(200), vulnerability_type VARCHAR(100), target_pattern TEXT, payload_pattern TEXT, success_pattern TEXT, failure_pattern TEXT, context_data JSONB, score INTEGER DEFAULT 0, learned_at TIMESTAMP DEFAULT NOW());
            CREATE TABLE IF NOT EXISTS graph_nodes (id VARCHAR(255) PRIMARY KEY, type VARCHAR(50), label VARCHAR(500), properties JSONB DEFAULT '{}', created_at TIMESTAMP DEFAULT NOW());
            CREATE TABLE IF NOT EXISTS graph_edges (id SERIAL PRIMARY KEY, source VARCHAR(255), target VARCHAR(255), type VARCHAR(50), weight DECIMAL(10,2) DEFAULT 1.0, properties JSONB DEFAULT '{}', created_at TIMESTAMP DEFAULT NOW());
        `);
    });
}

async function saveFinding(finding) {
    return _query(async (client) => {
        const r = await client.query(
            `INSERT INTO findings (target,type,severity,description,payload,response,score,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
            [finding.target, finding.type, finding.severity, finding.description,
             finding.payload||null, finding.response||null, finding.score||0, finding.timestamp]
        );
        return r.rows[0].id;
    });
}

async function getFindings(target, limit = 100) {
    return _query(async (client) => {
        const params = target ? [target, limit] : [limit];
        const where = target ? 'WHERE target=$1' : '';
        const pidx = target ? '$2' : '$1';
        const r = await client.query(`SELECT * FROM findings ${where} ORDER BY timestamp DESC LIMIT ${pidx}`, params);
        return r.rows;
    }) || [];
}

async function saveTestResult(target, testType, success, resultData, errorMessage, score, payload, responseData) {
    return _query(async (client) => {
        await client.query(
            `INSERT INTO test_results (target,test_type,success,result_data,error_message,score,payload,response_data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [target, testType, success, JSON.stringify(resultData||{}), errorMessage||null,
             score||(success?5:0), payload||null, responseData||null]
        );
    });
}

async function getTestResults(target, testType, success, limit = 100) {
    return _query(async (client) => {
        const conds = [], params = [];
        if (target)   { params.push(target);   conds.push(`target=$${params.length}`); }
        if (testType) { params.push(testType);  conds.push(`test_type=$${params.length}`); }
        if (success !== undefined) { params.push(success); conds.push(`success=$${params.length}`); }
        params.push(limit);
        const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
        const r = await client.query(`SELECT * FROM test_results ${where} ORDER BY timestamp DESC LIMIT $${params.length}`, params);
        return r.rows;
    }) || [];
}

async function getTestStatistics() {
    return _query(async (client) => {
        const r = await client.query(`SELECT test_type, COUNT(*) as count, COUNT(*) FILTER(WHERE success) as ok, AVG(score) as avg_score FROM test_results GROUP BY test_type ORDER BY count DESC`);
        return r.rows;
    }) || [];
}

async function saveTrainingData(source, sourceId, vulnerabilityType, targetPattern, payloadPattern, successPattern, failurePattern, contextData, score) {
    return _query(async (client) => {
        const r = await client.query(
            `INSERT INTO training_data (source,source_id,vulnerability_type,target_pattern,payload_pattern,success_pattern,failure_pattern,context_data,score) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
            [source, sourceId, vulnerabilityType, targetPattern, payloadPattern,
             successPattern, failurePattern, JSON.stringify(contextData||{}), score||0]
        );
        return r.rows[0].id;
    });
}

async function getTrainingData(vulnerabilityType, source, limit = 100) {
    return _query(async (client) => {
        const conds = [], params = [];
        if (vulnerabilityType) { params.push(vulnerabilityType); conds.push(`vulnerability_type=$${params.length}`); }
        if (source) { params.push(source); conds.push(`source=$${params.length}`); }
        params.push(limit);
        const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
        const r = await client.query(`SELECT * FROM training_data ${where} ORDER BY learned_at DESC LIMIT $${params.length}`, params);
        return r.rows;
    }) || [];
}
