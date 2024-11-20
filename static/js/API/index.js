function save(event) {
    event.preventDefault(); // Prevent the form from submitting the traditional way

    const apiUrl = 'https://' + window.location.host;
    const postData = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
    };

    const requestOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(postData)
    };

    fetch(apiUrl, requestOptions)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.message) {
                window.location.href = "/home"; // Redirect to home page
            } else {
                alert("Login failed");
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("Login failed");
        });
}