const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

// Configuration from .env
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'iust_portal',
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
});

const SALT_ROUNDS = 10;

async function hashAllPasswords() {
    try {
        console.log('Fetching all users...');
        const usersResult = await pool.query('SELECT id, password, email FROM users');
        const users = usersResult.rows;

        if (users.length === 0) {
            console.log('No users found.');
            await pool.end();
            return;
        }

        for (const user of users) {
            // WARNING: This assumes all existing passwords are in plain text.
            // If some are already hashed, running this will double-hash them, which is wrong.
            // For a production system, you'd need a more robust check.
            console.log(`Hashing password for user: ${user.email}`);
            const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
            
            // Update the user's record with the new hash
            await pool.query(
                'UPDATE users SET password = $1 WHERE id = $2',
                [hashedPassword, user.id]
            );
            console.log(`Updated password hash for user ID: ${user.id}`);
        }

        console.log('\n--- All user passwords have been hashed successfully! ---');
    } catch (err) {
        console.error('\n--- CRITICAL ERROR during password hashing ---');
        console.error('Please ensure your database is running and credentials in .env are correct.');
        console.error('Error:', err.message);
    } finally {
        await pool.end();
    }
}

// To run this script: 
// 1. Ensure you have a .env file configured.
// 2. Run: node hash-generator.js
hashAllPasswords();