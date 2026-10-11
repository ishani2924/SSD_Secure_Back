fetch('http://localhost:5000/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Test', email: 'test@test.com', password: 'test' })
}).then(res => res.text()).then(text => console.log('Response:', text)).catch(err => console.error('Error:', err));
