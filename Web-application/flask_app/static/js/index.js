async function authenticate(event) {
    event.preventDefault();

    const formData = new FormData(document.getElementById("login-form"));
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    });

    const challengeResponse = await fetch("http://localhost:5000/challenge", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(contents)
    });

    if (!challengeResponse.ok) {
        console.log("Error");
        return;
    }
    const challenge = await challengeResponse.json();

    const signatureResponse = await fetch("http://localhost:8081/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: challenge.challenge
    });
    if (!signatureResponse.ok)
    {
        const statusMsg = document.querySelector(".status-msg");
        statusMsg.innerHTML = String("Error communicating with the Tkey");
        console.error('Error:', 'Error communicating with the Tkey');
        return;
    }
    const pSignature = await signatureResponse.json();
    const responseDict = {
        "session_id": challenge.session_id,
        "signature": pSignature.signature
    };

    const verifyResponse = await fetch("http://localhost:5000/verify", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(responseDict)
    });
    
    const responseData = await verifyResponse.json();

    if (verifyResponse.ok && responseData.success) {
        window.location.href = responseData.redirect_url;
    } else {
        const statusMsg = document.querySelector(".status-msg");
        statusMsg.innerHTML = String(responseData.error);
        console.error('Error:', responseData.error);
    }
}

async function register(event) {
    event.preventDefault();

    const formData = new FormData(document.getElementById("registration-form"));
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    });

    const challengeResponse = await fetch("http://localhost:5000/challenge", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(contents)
    });

    if (!challengeResponse.ok) {
        console.log("error");
        return;
    }

    const challenge = await challengeResponse.json();
    console.log(challenge.challenge);

    const signatureResponse = await fetch("http://localhost:8081/registration", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: challenge.challenge
    });
    if (!signatureResponse.ok)
        {
            const statusMsg = document.querySelector(".status-msg");
            statusMsg.innerHTML = String("Error communicating with the Tkey");
            console.error('Error:', 'Error communicating with the Tkey');
            return;
        }
    const pSignature = await signatureResponse.json();
    const responseDict = {
        "session_id": challenge.session_id,
        "signature": pSignature.signature,
        "publicKey": pSignature.publicKey
    };

    const verifyResponse = await fetch("http://localhost:5000/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(responseDict)
    });
    
    const responseData = await verifyResponse.json();

    if (verifyResponse.ok && responseData.success) {
        window.location.href = responseData.redirect_url;
    } else {
        const statusMsg = document.querySelector(".status-msg");
        statusMsg.innerHTML = String(responseData.error);
        console.error('Error:', responseData.error);
    }
}