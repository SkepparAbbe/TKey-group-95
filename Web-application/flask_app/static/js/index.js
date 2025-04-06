const ContentType = {
    URLENCODED: "application/x-www-form-urlencoded",
    JSON: "application/json"
};

const statusMsg = document.querySelector(".status-msg");

async function HandleAuthentication(event, formID, responseGenerator, signatureURL, responseUrlSuffix) {
    event.preventDefault();
    const current_url = window.location.origin;

    const formData = new FormData(document.getElementById(formID));
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    });

    const challenge = await requestData(
        contents,
        current_url + "/challenge",
        ContentType.JSON,
        contents.csrf_token
    );

    if (!challenge.ok) {
        statusMsg.innerHTML = String("Error communicating with the Server");
        return;
    }

    const signature = await requestData(
        challenge.data.challenge,
        signatureURL,
        ContentType.URLENCODED
    );

    if (!signature.ok) {
        statusMsg.innerHTML = signature.data.error;
        return;
    }

    const responseDict = responseGenerator(signature.data);

    const response = await requestData(
        responseDict, 
        current_url + responseUrlSuffix, 
        ContentType.JSON,
        contents.csrf_token
    );

    if (response.ok && response.data.success) {
        if(response.data.redirect_url){
            window.location.href = response.data.redirect_url;
        }
        if(response.data.qr_code){        
            showQRCode(response.data.qr_code);
        }

    } else {
        statusMsg.innerHTML = String(response.data.error);
    }
}

async function authenticate(event) {
    HandleAuthentication(
        event,
        "login-form",
        authResponseBuilder,
        "http://localhost:8081/login",
        "/verify"
    );
}

async function register(event) {
    HandleAuthentication(
        event,
        "registration-form",
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/register"
    );
}

function goToStage(currentStage, route) {
    const form = document.getElementById(`stage-${currentStage}-form`);
    let bodyData = null;
    let csrfToken = null;

    if (form) {
        const formData = new FormData(form);
        bodyData = JSON.stringify(Object.fromEntries(formData.entries()));
        csrfToken = formData.get('csrf_token');
    }

    fetch(route, {
        method: 'POST',
        body: bodyData,
        headers: {
            'Content-Type': 'application/json',
            ... (csrfToken && {'X-CSRFToken': csrfToken})
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            const errorElem = document.getElementById(`stage-${currentStage}-error`);
            if (errorElem) {
                errorElem.innerText = data.error;
            }
        } else {
            // Göm nuvarande steg
            const currentStageElem = document.getElementById(`stage-${currentStage}`);
            if (currentStageElem) {
                currentStageElem.style.display = 'none';
            }

            // Visa nästa steg
            const nextStageElem = document.getElementById(`stage-${currentStage + 1}`);
            if (nextStageElem) {
                nextStageElem.style.display = 'block';
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        const errorElem = document.getElementById(`stage-${currentStage}-error`);
        if (errorElem) {
            errorElem.innerText = "Something went wrong. Please try again.";
        }
    });
}

function authResponseBuilder(challengeData, signatureData) {
    const totp = document.getElementById("totp").value;
    return {
        signature: signatureData.signature,
        totp: totp
    };
}

function registerResponseBuilder(signatureData) {
    return {
        signature: signatureData.signature,
        publicKey: signatureData.publicKey
    };
}

async function requestData(message, url, contentType, csrf) {
	try {
        const headers = {
            "Content-Type": contentType,
            ... (csrf && {'X-CSRFToken': csrf})
        };
        console.log(headers)
		const response = await fetch(url, {
			method: "POST",
            headers: headers,
			body: contentType == ContentType.JSON ? JSON.stringify(message) : message
		});
        const data = await response.json();
        return { ok: response.ok, data: data };
    } catch (e) {
        // Assume error in proxy server
        return { ok: false, data: { error: "Error communicating with the Tkey" } };
    }
}