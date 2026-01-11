const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

// Connect using the credentials from your .env file
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for NeonDB/AWS connections
});

async function updateHierarchy() {
    try {
        console.log('--- Starting Database Update ---');

        // 1. Add the rank column if it doesn't exist
        console.log('Adding hierarchy_rank column...');
        await pool.query(`
            ALTER TABLE users 
            ADD COLUMN IF NOTXSISTS hierarchy_rank INT DEFAULT 2;
        `);

        // 2. Set 'Dr. Muzafar Rasool' as Head of Department (Rank 1)
        console.log('Promoting Dr. Muzafar Rasool to HOD...');
        await pool.query(`
            UPDATE users 
            SET designation = 'Head of Department', hierarchy_rank = 1 
            WHERE email = 'm.rasool@i.com';
        `);

        // 3. Ensure everyone else is set to Rank 2 (Regular Faculty)
        console.log('Setting default rank for others...');
        await pool.query(`
            UPDATE users 
            SET hierarchy_rank = 2 
            WHERE hierarchy_rank IS NULL OR hierarchy_rank != 1;
        `);

        console.log('--- Success: Database updated for Hierarchy! ---');
    } catch (err) {
        console.error('Error updating database:', err.message);
    } finally {
        await pool.end();
    }
}

updateHierarchy();