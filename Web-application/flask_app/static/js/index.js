const ContentType = {
    URLENCODED: "application/x-www-form-urlencoded",
    JSON: "application/json"
};

const statusMsg = document.querySelector(".status-msg");

function extractFormData(form) {
    const formData = new FormData(form);
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    })
    return contents;
}

async function HandleAuthentication(event, responseGenerator, signatureURL, responseUrlSuffix, url_extension, responseHandler) {
    event.preventDefault();
    const current_url = window.location.origin;

    const contents = extractFormData(event.target);

    const challenge = await requestData(
        { username: contents['challenge'] },
        current_url + url_extension,
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

    const responseDict = responseGenerator(contents, signature.data);

    const response = await requestData(
        responseDict, 
        current_url + responseUrlSuffix, 
        ContentType.JSON,
        contents.csrf_token
    );

    responseHandler(response);
}

async function authenticate(event) {
    HandleAuthentication(
        event,
        authResponseBuilder,
        "http://localhost:8081/login",
        "/verify",
        "/challenge",
        (response) => {
            if (response.ok) {
                window.location.href = response.data.redirect_url;
            } else {
                statusMsg.innerHTML = String(response.data.error);
            }
        }
    );
}

async function register(event) {
    HandleAuthentication(
        event,
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/register",
        "/challenge",   
        (response) => {
            if (response.ok) {
                window.location.href = response.data.redirect_url;
            } else {
                statusMsg.innerHTML = String(response.data.error);
            }
        }
    );
}

async function recover(event) {
    HandleAuthentication(
        event,
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/recover/challenge",
        "/challenge",
        (response) => {
            if (response.ok) {
                statusMsg.innerHTML = String("Success!");
                statusMsg.classList.add("success-green");
                setTimeout(() => {
                    window.location.href = response.data.redirect_url;
                }, 3000);
            } else {
                statusMsg.innerHTML = String(response.data.error);
            }
        }
    );
}

async function handleFormSubmit(event, urlSuffix) {
    event.preventDefault();

    const contents = extractFormData(event.target);

	const response = await requestData(
		contents,
		window.location.origin + urlSuffix,
		ContentType.JSON,
		formData.get('csrf_token')
	);

	if (response.ok) {
		window.location.href = response.data.redirect_url;
	} else {
		statusMsg.innerHTML = response.data.error;
	}
}

async function submitUser(event) {
    handleFormSubmit(event, "/recover");
}

async function submitMnemonic(event) {
    handleFormSubmit(event, "/recover/mnemonic");
}

function authResponseBuilder(formData, signatureData) {
    return {
        username: formData.username,
        totp: formData.totp,
        signature: signatureData.signature
    };
}

function registerResponseBuilder(formData, signatureData) {
    return {
        username: formData.username,
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
        return { ok: false, data: { error: "Communication error" } };
    }
}