const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./data.sqlite');

db.run("ALTER TABLE users ADD COLUMN monthly_budget REAL DEFAULT 0;", (err) => {
    if (err) {
        console.log("❌ Error or column already exists:", err.message);
    } else {
        console.log("✅ monthly_budget column added successfully!");
    }
    db.close();
});
