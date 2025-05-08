const ContentType = {
    URLENCODED: "application/x-www-form-urlencoded",
    JSON: "application/json"
};

const statusMsg = document.querySelector(".status-msg");

async function HandleAuthentication(event, responseGenerator, signatureURL, responseUrlSuffix, url_extension, flagbool) {
    event.preventDefault();
    const current_url = window.location.origin;

    const formData = new FormData(event.target);
    const contents = {};
    formData.forEach((value, key) => {
        contents[key] = value;
    });

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
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/register",
        "/challenge",   
        true
    );
}

async function recover(event) {
    HandleAuthentication(
        event,
        registerResponseBuilder,
        "http://localhost:8081/registration",
        "/recover/challenge",
        "/challenge",
        false
    );
}



async function fetchUser(event) {
    event.preventDefault();

  	const formData = new FormData(event.target);
	const contents = {};
	formData.forEach((value, key) => {
		contents[key] = value;
	});

	const response = await requestData(
		contents,
		window.location.origin + "/recover",
		ContentType.JSON,
		formData.get('csrf_token')
	);

	console.log(response);

	if (response.ok) {
		window.location.href = response.data.redirect_url;
	} else {
		statusMsg.innerHTML = response.data.error;
	}
}

async function submitMnemonic(event) {
    const statusMsg = document.querySelector(".status-msg");
    event.preventDefault();

  	const formData = new FormData(event.target);
	const contents = {};
	formData.forEach((value, key) => {
		contents[key] = value;
	});

    const response = await requestData(
        contents,
        window.location.origin + "/recover/mnemonic",
		ContentType.JSON,
		formData.get('csrf_token')
    )

    if (response.ok) {
		window.location.href = response.data.redirect_url;
	} else {
		statusMsg.innerHTML = response.data.error;
	}
}

function authResponseBuilder(formData, signatureData) {
    const totp = document.getElementById("totp").value;
    return {
        username: formData.username,
        signature: signatureData.signature,
        totp: totp
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