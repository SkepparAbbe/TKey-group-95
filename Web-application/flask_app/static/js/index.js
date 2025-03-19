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
        ContentType.JSON
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

    const responseDict = responseGenerator(challenge.data, signature.data);

    const response = await requestData(
        responseDict, 
        current_url + responseUrlSuffix, 
        ContentType.JSON
    );

    if (response.ok && response.data.success) {
        window.location.href = response.data.redirect_url;
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

function authResponseBuilder(challengeData, signatureData) {
    return {
        session_id: challengeData.session_id,
        signature: signatureData.signature
    };
}

function registerResponseBuilder(challengeData, signatureData) {
    return {
        session_id: challengeData.session_id,
        signature: signatureData.signature,
        publicKey: signatureData.publicKey
    };
}

async function requestData(message, url, contentType) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": contentType
        },
        body: contentType == ContentType.JSON ? JSON.stringify(message) : message
    });
    try {
        const data = await response.json();
        return { ok: response.ok, data: data };
    } catch (e) {
        // Assume error in proxy server
        return { ok: false, data: { error: "Error communicating with the Tkey" } };
    }
}