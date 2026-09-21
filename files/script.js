// ============ PAGE NAVIGATION ============

function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    document.getElementById(pageName).classList.add('active');
    
    // Update nav auth buttons based on page
    if (pageName === 'dashboard') {
        document.getElementById('navAuth').innerHTML = `
            <div style="display: flex; align-items: center; gap: 15px;">
                <span style="font-weight: 600;" id="userGreeting">Welcome!</span>
                <button class="btn btn-secondary" onclick="logout()">Logout</button>
            </div>
        `;
    } else {
        document.getElementById('navAuth').innerHTML = `
            <button class="btn btn-secondary" onclick="showPage('login')">Login</button>
            <button class="btn btn-primary" onclick="showPage('signup')">Sign Up</button>
        `;
    }

    window.scrollTo(0, 0);
}

function scrollToFeatures() {
    document.getElementById('featuresSection').scrollIntoView({ behavior: 'smooth' });
}

// ============ DASHBOARD TAB NAVIGATION ============

function showDashboardTab(tabName) {
    document.querySelectorAll('.dashboard-tab').forEach(tab => {
        tab.style.display = 'none';
    });
    document.getElementById(tabName + 'Tab').style.display = 'block';

    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.classList.add('active');
}

// ============ ALERT FUNCTIONS ============

function showAlert(elementId, message, type) {
    const alert = document.getElementById(elementId);
    alert.textContent = message;
    alert.className = `alert show alert-${type}`;
}

// ============ AUTHENTICATION FUNCTIONS ============

function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    if (password.length < 6) {
        showAlert('loginAlert', 'Password must be at least 6 characters', 'error');
        return;
    }

    showAlert('loginAlert', 'Signing you in...', 'success');
    
    setTimeout(() => {
        localStorage.setItem('userEmail', email);
        localStorage.setItem('userName', email.split('@')[0]);
        showPage('dashboard');
        updateUserProfile(email);
    }, 1500);
}

function handleSignup(e) {
    e.preventDefault();
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const password2 = document.getElementById('signupPassword2').value;

    if (password !== password2) {
        showAlert('signupAlert', 'Passwords do not match', 'error');
        return;
    }

    if (password.length < 8) {
        showAlert('signupAlert', 'Password must be at least 8 characters', 'error');
        return;
    }

    showAlert('signupAlert', 'Creating your account...', 'success');
    
    setTimeout(() => {
        localStorage.setItem('userEmail', email);
        localStorage.setItem('userName', name);
        showPage('dashboard');
        updateUserProfile(email);
    }, 1500);
}

function updateUserProfile(email) {
    const name = localStorage.getItem('userName') || email.split('@')[0];
    document.getElementById('profileName').textContent = name;
    document.getElementById('profileEmail').textContent = email;
    document.getElementById('userGreeting').textContent = `Welcome, ${name}!`;
    
    // Create avatar from initials
    const initials = name.split(' ').map(n => n[0]).join('').toUpperCase();
    document.getElementById('profileAvatar').textContent = initials;
}

function logout() {
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userName');
    showPage('home');
}

function socialLogin(provider) {
    alert(`${provider} login would redirect to OAuth in a real application`);
}

// ============ INITIALIZATION ============

window.addEventListener('load', () => {
    if (localStorage.getItem('userEmail')) {
        updateUserProfile(localStorage.getItem('userEmail'));
    }
});
