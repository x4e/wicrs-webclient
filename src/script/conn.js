const httpReq = (url, data = {}) => {
	return fetch(
		url,
		data
	);
};

const apiReq = async (state, path, data = {}) => {	
	let boundary;
	
	let url = state.hostname + "/" + path;
	
	let resp = await httpReq(url, data)
		.then(response => {
			let type = response.headers.get("content-type");
			if (!type) throw "No content-type in response";
			let typeParts = type.split(";").map(a => a.trim());
			
			if (typeParts[0] != "multipart/encrypted") {
				throw new Error("Non encrypted response");
			}
			if (typeParts[1] != "protocol=\"application/pgp-encrypted\"") {
				throw new Error("Non pgp encrypted response");
			}
			boundary = typeParts.find(a => a.startsWith("boundary="));
			if (!boundary) {
				throw new Error("No boundary given");
			}
			boundary = boundary.substring("boundary=".length);
			
 			return response.text();
		})
		.then(data => {
			let parts = [];
			
			while (data.length > 0) {
				let i = data.indexOf(`--${boundary}`);
				if (i == -1) i = data.length-1;
				
				var part = data.substring(0,i).trim();
				if (part.length > 0) {
					parts.push(part);
				}
				
				data = data.substring(i + `--${boundary}`.length);
				if (data.startsWith("--")) {
					break;
				}
			}
			
			if (parts.length != 2) {
				throw new Error("Invalid API response, wrong num parts");
			}
			
			if (parts[0] != "Content-Type: application/pgp-encrypted\r\nVersion: 1") {
				throw new Error("Invalid API response, unknown content type");
			}
			
			let streamType = "Content-Type: application/octet-stream\r\n";
			if (!parts[1].startsWith(streamType)) {
				throw new Error("Invalid API response, unknown encrypted content");
			}
			
			return parts[1].substring(streamType.length);
		})
		.catch(error => { throw error; });
	
	let message = await openpgp.readMessage({
		armoredMessage: resp
	});
	
	// Need to verify
	if (state.serverKey) {
		message = await openpgp.verify({
			message: message,
			publicKeys: state.serverKey
		});
	}
	
	let text = await openpgp.stream.readToEnd(message.getText());
	
	return JSON.parse(text);
};

const connect = async (hostname, publicKey, privateKey) => {	
	const state = {
		hostname: hostname,
		publicKey: publicKey,
		privateKey: privateKey,
		serverKey: undefined, // known and trusted server key
		keyServer: undefined, // key server hostname
	};
	
	let info = await apiReq(state, "v3/info");
	console.log("Connected to wicrs server " + info.version);
	
	state.keyServer = info.key_server;
	let fingerprint = info.public_key_fingerprint;
	
	for (i in fingerprint) {
		const c = fingerprint.charAt(i);
		if (c < '0' || c > 'Z') {
			throw new Error("Invalid key fingerprint");
		}
	}
	
	let serverArmor = await (
		await httpReq(`${state.keyServer}/pks/lookup?op=get&options=mr&search=${fingerprint}`)
	).text();
	state.serverKey = await openpgp.readKey({ armoredKey: serverArmor });
};
