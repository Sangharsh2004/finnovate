// test-api.js
// Run: node test-api.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3000';

const TEST_USER = {
    name: 'Sangharsh',
    email: 'sangharsh@example.com',
    password: '123456',
    role: 'user'
};

async function testSignup() {
    console.log('➡️ Signing up user...');
    const res = await fetch(`${API_BASE}/api/verify-signup-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...TEST_USER, otp: '1234' })
    });
    const data = await res.json();
    console.log('Signup Response:', data);
    return data;
}

async function testLogin() {
    console.log('➡️ Logging in user...');
    const res = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: TEST_USER.email, password: TEST_USER.password })
    });
    const data = await res.json();
    console.log('Login Response:', data);
    return data;
}

async function testAddTransaction(userId) {
    console.log('➡️ Adding transaction...');
    const res = await fetch(`${API_BASE}/api/transactions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            userId,
            type: 'income',
            category: 'Salary',
            amount: 50000,
            description: 'Monthly Salary'
        })
    });
    const data = await res.json();
    console.log('Add Transaction Response:', data);
    return data;
}

async function testDashboard(userId) {
    console.log('➡️ Fetching dashboard summary...');
    const res = await fetch(`${API_BASE}/api/dashboard/summary?userId=${userId}`);
    const data = await res.json();
    console.log('Dashboard Summary:', data);
    return data;
}

async function runTests() {
    try {
        // 1️⃣ Signup
        await testSignup();

        // 2️⃣ Login
        const loginData = await testLogin();
        const userId = loginData.userId;

        // 3️⃣ Add Transaction
        await testAddTransaction(userId);

        // 4️⃣ Fetch Dashboard
        await testDashboard(userId);

        console.log('✅ All API tests completed successfully!');
    } catch (err) {
        console.error('❌ Error during API tests:', err.message);
    }
}

runTests();
