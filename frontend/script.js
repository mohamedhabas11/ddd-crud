// --- Existing DOM Element selections ---
const loginForm = document.getElementById('loginForm');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const messageDiv = document.getElementById('message');
const userInfoDiv = document.getElementById('userInfo');
const userIdSpan = document.getElementById('userId');
const userNameSpan = document.getElementById('userName');
const userEmailSpan = document.getElementById('userEmail');
const userRoleSpan = document.getElementById('userRole');
const logoutButton = document.getElementById('logoutButton');

// --- NEW DOM Element selections ---
const showChangePasswordFormButton = document.getElementById('showChangePasswordFormButton');
const changePasswordSection = document.getElementById('changePasswordSection');
const changePasswordForm = document.getElementById('changePasswordForm');
const oldPasswordInput = document.getElementById('oldPasswordInput');
const newPasswordInput = document.getElementById('newPasswordInput');
const confirmNewPasswordInput = document.getElementById('confirmNewPasswordInput');
const changePasswordMessageDiv = document.getElementById('changePasswordMessage');


// --- Configuration ---
const API_BASE_URL = 'http://localhost:8080';
const LOGIN_ENDPOINT = `${API_BASE_URL}/api/v1/users/login`;
// NEW: Define endpoint structure (user ID will be added later)
const CHANGE_PASSWORD_ENDPOINT_BASE = `${API_BASE_URL}/api/v1/users`;

// --- Helper Functions ---

function showMessage(message, isError = false, targetDiv = messageDiv) {
    targetDiv.textContent = message;
    targetDiv.className = isError ? 'error' : 'success';
}

function displayUserInfo(user) {
    userIdSpan.textContent = user.id;
    userNameSpan.textContent = user.name;
    userEmailSpan.textContent = user.email;
    userRoleSpan.textContent = user.role;
    userInfoDiv.style.display = 'block';
    loginForm.style.display = 'none';
    messageDiv.textContent = '';
    messageDiv.className = '';
    // Reset change password form state when user info is displayed
    changePasswordSection.style.display = 'none';
    changePasswordMessageDiv.textContent = '';
    changePasswordMessageDiv.className = '';
    changePasswordForm.reset(); // Clear form fields
}

function handleLogout() {
    localStorage.removeItem('jwtToken');
    localStorage.removeItem('userInfo');
    userInfoDiv.style.display = 'none';
    loginForm.style.display = 'block';
    emailInput.value = '';
    passwordInput.value = '';
    // Also hide change password section on logout
    changePasswordSection.style.display = 'none';
    showMessage('You have been logged out.', false);
    console.log('Logged out');
}

// --- Login Handler (No changes needed here) ---
async function handleLogin(event) {
    event.preventDefault();
    const email = emailInput.value;
    const password = passwordInput.value;
    showMessage('Logging in...', false);

    try {
        const response = await fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || `Login failed with status: ${response.status}`);
        }
        console.log('Login successful:', data);
        localStorage.setItem('jwtToken', data.token);
        localStorage.setItem('userInfo', JSON.stringify(data.user));
        showMessage('Login successful!', false);
        displayUserInfo(data.user);
    } catch (error) {
        console.error('Login error:', error);
        showMessage(error.message || 'An unexpected error occurred.', true);
        userInfoDiv.style.display = 'none';
        loginForm.style.display = 'block';
    }
}

// --- NEW: Change Password Handler ---
async function handleChangePassword(event) {
    event.preventDefault();
    showMessage('', false, changePasswordMessageDiv); // Clear previous message

    const oldPassword = oldPasswordInput.value;
    const newPassword = newPasswordInput.value;
    const confirmNewPassword = confirmNewPasswordInput.value;

    // Basic Client-side validation
    if (newPassword !== confirmNewPassword) {
        showMessage('New passwords do not match.', true, changePasswordMessageDiv);
        return;
    }
    if (newPassword.length < 8) {
        // HTML5 minlength should catch this, but double-check
        showMessage('New password must be at least 8 characters long.', true, changePasswordMessageDiv);
        return;
    }

    // Get User ID and Token from localStorage
    const storedUserInfo = localStorage.getItem('userInfo');
    const storedToken = localStorage.getItem('jwtToken');

    if (!storedUserInfo || !storedToken) {
        showMessage('Error: Not logged in or user data missing.', true, changePasswordMessageDiv);
        handleLogout(); // Log out if data is inconsistent
        return;
    }

    let userId;
    try {
        userId = JSON.parse(storedUserInfo).id;
        if (!userId) throw new Error("User ID missing");
    } catch (e) {
        showMessage('Error: Could not retrieve user ID.', true, changePasswordMessageDiv);
        handleLogout();
        return;
    }

    const changePasswordUrl = `${CHANGE_PASSWORD_ENDPOINT_BASE}/${userId}/password`;
    const requestBody = {
        old_password: oldPassword,
        new_password: newPassword,
    };

    showMessage('Updating password...', false, changePasswordMessageDiv);

    try {
        const response = await fetch(changePasswordUrl, {
            method: 'PATCH', // Use PATCH as defined in the backend router
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${storedToken}`, // Send the JWT token
            },
            body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
            let errorMsg = `Password update failed with status: ${response.status}`;
            try {
                // Try to get specific error from backend response body
                const errorData = await response.json();
                if (errorData && errorData.error) {
                    errorMsg = errorData.error;
                }
            } catch (jsonError) {
                // Ignore if response body wasn't JSON or empty
                console.warn("Could not parse error response JSON:", jsonError);
            }
             // Handle specific common errors
            if (response.status === 400) {
                 // Could be incorrect old password or invalid new password format
                 errorMsg = `Update failed: ${errorMsg}`; // Prepend context
            } else if (response.status === 401 || response.status === 403) {
                 errorMsg = "Authentication error. Please log out and log back in.";
                 // Consider forcing logout here: handleLogout();
            }
            throw new Error(errorMsg);
        }

        // --- Password Change Successful (Status 204 No Content expected) ---
        console.log('Password updated successfully');
        showMessage('Password updated successfully!', false, changePasswordMessageDiv);
        changePasswordForm.reset(); // Clear the form
        changePasswordSection.style.display = 'none'; // Hide the form again
        showChangePasswordFormButton.style.display = 'inline-block'; // Show the button again

    } catch (error) {
        console.error('Change password error:', error);
        showMessage(error.message || 'An unexpected error occurred while changing password.', true, changePasswordMessageDiv);
    }
}

// --- NEW: Toggle Change Password Form Visibility ---
function toggleChangePasswordForm() {
    if (changePasswordSection.style.display === 'none') {
        changePasswordSection.style.display = 'block';
        showChangePasswordFormButton.style.display = 'none'; // Hide button when form is shown
        changePasswordMessageDiv.textContent = ''; // Clear message when showing
        changePasswordMessageDiv.className = '';
    } else {
        changePasswordSection.style.display = 'none';
        showChangePasswordFormButton.style.display = 'inline-block'; // Show button again
    }
}


// --- Event Listeners ---
loginForm.addEventListener('submit', handleLogin);
logoutButton.addEventListener('click', handleLogout);
// NEW Listeners
showChangePasswordFormButton.addEventListener('click', toggleChangePasswordForm);
changePasswordForm.addEventListener('submit', handleChangePassword);


// --- Initial Check on Load ---
const storedToken = localStorage.getItem('jwtToken');
const storedUserInfo = localStorage.getItem('userInfo');

if (storedToken && storedUserInfo) {
    console.log('User already logged in from previous session.');
    try {
        const user = JSON.parse(storedUserInfo);
        displayUserInfo(user);
    } catch (e) {
        console.error("Failed to parse stored user info", e);
        localStorage.removeItem('jwtToken');
        localStorage.removeItem('userInfo');
    }
}
