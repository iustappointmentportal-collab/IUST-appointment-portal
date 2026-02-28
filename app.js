document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const welcomeMessage = document.getElementById('welcome-message');
    const logoutButton = document.getElementById('logout-button');
    
    // --- NEW: Base URL for API calls ---
    const API_BASE_URL = 'http://localhost:3000/api';

    const getRole = () => document.getElementById('role') ? document.getElementById('role').value : 'student';

    // --- NEW: Calendar Loader Function ---
    async function loadCalendarEvents() {
        const token = localStorage.getItem('authToken');
        if (!token) return [];

        try {
            const response = await fetch(`${API_BASE_URL}/appointments`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!response.ok) throw new Error('Failed to fetch appointments');
            
            const appointments = await response.json();

            return appointments.map(app => ({
                title: app.purpose, 
                start: `${app.date}T${app.time}`, 
                backgroundColor: app.status === 'approved' ? '#4f46e5' : '#f59e0b', 
                allDay: false
            }));
        } catch (error) {
            console.error('Error loading calendar:', error);
            return [];
        }
    }

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const role = getRole();
        
        errorMessage.textContent = ''; 

        try {
            const response = await fetch(`${API_BASE_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, role }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `HTTP error! status: ${response.status}`);
            }

            // SUCCESS
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('currentUser', JSON.stringify(data.user));
            
            loginContainer.classList.add('hidden');
            dashboardContainer.classList.remove('hidden');
            welcomeMessage.textContent = `Welcome, ${data.user.name}! (Role: ${data.user.role})`;

            // --- TRIGGER CALENDAR LOAD ---
            const events = await loadCalendarEvents();
            console.log('Loaded Events:', events);
            // If using FullCalendar, you would call: calendar.addEventSource(events);

        } catch (error) {
            console.error('Login failed:', error);
            errorMessage.textContent = error.message;
        }
    });

    logoutButton.addEventListener('click', () => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        dashboardContainer.classList.add('hidden');
        loginContainer.classList.remove('hidden');
        welcomeMessage.textContent = '';
    });
    
    // Check if user is already logged in on page load
    const token = localStorage.getItem('authToken');
    const user = localStorage.getItem('currentUser');
    if (token && user) {
        loginContainer.classList.add('hidden');
        dashboardContainer.classList.remove('hidden');
        const userData = JSON.parse(user);
        welcomeMessage.textContent = `Welcome back, ${userData.name}! (Role: ${userData.role})`;
        
        // --- TRIGGER CALENDAR LOAD FOR RETURNING USER ---
        loadCalendarEvents().then(events => console.log('Restored Events:', events));
    }
});