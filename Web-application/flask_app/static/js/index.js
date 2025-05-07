const ContentType = {
    URLENCODED: "application/x-www-form-urlencoded",
    JSON: "application/json"
};

//const statusMsg = document.querySelector(".status-msg");

async function HandleAuthentication(event, formID, responseGenerator, signatureURL, responseUrlSuffix, url_extension, statusMsg, flagbool) {
    event.preventDefault();
    const current_url = window.location.origin;

    if (flagbool==true) {
        statusMsg = document.querySelector(statusMsg);

    } else {
        statusMsg = document.getElementById(statusMsg);

    }

    const formData = new FormData(document.getElementById(formID));
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    });

    const challenge = await requestData(
        contents,
        current_url + url_extension,
        ContentType.JSON,
        contents.csrf_token
    );
    console.log(challenge);

    if (!challenge.ok) {
        statusMsg.innerHTML = String("Error communicating with the Server");
        return;
    }

    const signature = await requestData(
        challenge.data.challenge,
        signatureURL,
        ContentType.URLENCODED
    );
    console.log(signature);

    if (!signature.ok) {
        statusMsg.innerHTML = signature.data.error;
        return;
    }

    const responseDict = responseGenerator(challenge.data, signature.data);

    const response = await requestData(
        responseDict, 
        current_url + responseUrlSuffix, 
        ContentType.JSON,
        contents.csrf_token
    );

    console.log(response);
    if (response.ok && response.data.success) {
        if (!flagbool) {
            statusMsg.innerHTML = String("Success!");
            statusMsg.classList.add("success-green");
            setTimeout(() => {
                window.location.href = current_url + "/login";
            }, 3000);
        }
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
        "/verify",
        "/challenge",
        ".status-msg",
        true
    );
}

async function register(event) {
    HandleAuthentication(
        event,
        "registration-form",
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/register",
        "/challenge",
        ".status-msg",
        true
    );
}

async function recover(event) {
    const response = await HandleAuthentication(
        event,
        "recover-form",
        recoverResponseBuilder,
        "http://localhost:8081/registration",
        "/recover-challenge",
        "/challenge",
        'stage-3-error',
        false
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
            ...(csrfToken ? { 'X-CSRFToken': csrfToken } : {})
        }
    })
    .then(response => response.json())
    .then(data => {
        const errorElem = document.getElementById(`stage-${currentStage}-error`);
        
        if (data.error) {
            if (errorElem) {
                errorElem.innerText = data.error;
            }
            return;
        }

        // Hide current stage
        const currentStageElem = document.getElementById(`stage-${currentStage}`);
        if (currentStageElem) {
            currentStageElem.classList.remove('active');
        }

        // Show next stage
        const nextStageElem = document.getElementById(`stage-${currentStage + 1}`);
        if (nextStageElem) {
            nextStageElem.classList.add('active');
        }

        // Clear previous errors
        if (errorElem) {
            errorElem.innerText = '';
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
        session_id: challengeData.session_id,
        signature: signatureData.signature,
        totp: totp
    };
}

function registerResponseBuilder(challengeData, signatureData) {
    return {
        session_id: challengeData.session_id,
        signature: signatureData.signature,
        publicKey: signatureData.publicKey
    };
}

function recoverResponseBuilder(challengeData,signatureData){
    return {
        session_id: challengeData.session_id,
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
		const response = await fetch(url, {
			method: "POST",
            headers: headers,
			body: contentType == ContentType.JSON ? JSON.stringify(message) : message
		});
        const data = await response.json();
        return { ok: response.ok, data: data };
    } catch (e) {
        // Assume error in proxy server
        return { ok: false, data: { error: "Error communicating with the TKey" } };
    }
}