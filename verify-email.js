// verify-email.js
async function verifyEmail() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const email = urlParams.get('email');
  
    if (!token || !email) {
      alert('Missing token or email.');
      return;
    }
  
    try {
      const response = await fetch('http://93.127.172.167:5001/verify-email1', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token, email }),
      });
      const data = await response.json();
  
      if (response.ok) {
        alert(data.message);
        //window.location.href = data.redirectUrl;
         window.location.href = '/login'; // Redirect to login page
      } else {
        alert(data.message);
      }
    } catch (error) {
      alert('An error occurred. Please try again later.');
      console.error('Error:', error);
    }
  }
  
  // Call verifyEmail function when the page loads
  //document.addEventListener('DOMContentLoaded', verifyEmail);
  