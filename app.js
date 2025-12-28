document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const welcomeMessage = document.getElementById('welcome-message');
    const logoutButton = document.getElementById('logout-button');
    // Assume you have a role selection input (e.g., a dropdown or radio buttons)
    // For this example, let's assume a static role or a hidden input for testing.
    // NOTE: For a real app, the client shouldn't decide the role; the server should.
    // However, since the server mandates a role check, we must send one.

    // A simple way to get a role (e.g., from a dropdown with ID 'role')
    const getRole = () => document.getElementById('role') ? document.getElementById('role').value : 'student';

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent the form from reloading the page
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        // --- IMPROVEMENT: Include Role in Request ---
        const role = getRole();
        
        errorMessage.textContent = ''; // Clear previous errors

        try {
            const response = await fetch('http://localhost:3000/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password, role }), // Sending 'role'
            });

            const data = await response.json();

            if (!response.ok) {
                // Handle errors from the server (e.g., "Invalid password")
                throw new Error(data.message || `HTTP error! status: ${response.status}`);
            }

            // --- SUCCESS ---
            console.log('Login successful:', data);

            // Save the token and user to local storage
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('currentUser', JSON.stringify(data.user)); // Store user info
            
            // Show the dashboard and hide the login form
            loginContainer.classList.add('hidden');
            dashboardContainer.classList.remove('hidden');
            welcomeMessage.textContent = `Welcome, ${data.user.name}! (Role: ${data.user.role})`;

            // Optional: Fetch data now that we have a token (e.g., the faculty list)
            // loadFacultyData();

        } catch (error) {
            console.error('Login failed:', error);
            errorMessage.textContent = error.message;
        }
    });

    logoutButton.addEventListener('click', () => {
        // Clear the token and user data
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
    }
    
    // Example function to call protected API (requires an element with ID 'faculty-list')
    /*
    async function loadFacultyData() {
        const token = localStorage.getItem('authToken');
        if (!token) return;
        
        try {
            const response = await fetch('http://localhost:3000/api/faculty', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}` // Sending the token
                }
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'Failed to fetch faculty data.');
            }
            console.log('Faculty Data:', data);
            // Display data in the dashboard (e.g., in a div with id="faculty-list")
        } catch (error) {
            console.error('Fetch error:', error);
            alert('Error fetching protected data: ' + error.message);
        }
    }
    */
});