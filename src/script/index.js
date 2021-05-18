window.onclick = function(event) {
	const classList = event.target.classList;
	if (classList.contains("modal") && classList.contains("modal-closable")) {
		classList.remove("modal-open");
	}
} 

const showErr = (err) => {
	console.error(err);
	
	const errModal = document.getElementById("modal-error");
	const text  = document.getElementById("modal-error-text");
	
	var msg = "";
	if (err.name) {
		msg += err.name + ": ";
	}
	if (err.message) {
		msg += err.message;
	}
	if (msg.trim().length === 0) {
		msg = err.toString();
	}
	if (err.stack) {
		err.stack.split("\n").forEach((line) => {
			msg += "\n\t" + line;
		});
	}
	text.innerText = msg;
	errModal.classList.add("modal-open");
};

window.wicrsConnect = async () => {
	try {
		const connModal = document.getElementById("connect-modal");
		connModal.classList.remove("modal-open");
		
		let hostname = document.getElementById("connect-hostname-inp")
			.value
			.trim();
		
		if (!hostname.startsWith("http")) {
			hostname = "http://" + hostname;
		}
		
		const pgpPass = document.getElementById("pgp-passphrase-inp")
			.value;
		
		const pgpArmor = document.getElementById("connect-pgp-inp")
			.value
			.trim();
		
		let privateKey = await openpgp.readKey({ armoredKey: pgpArmor });
		
		if (!privateKey.isDecrypted()) {
			privateKey = await openpgp.decryptKey({
				privateKey: privateKey,
				pgpPass
			});
		}
		
		if (!privateKey.isPrivate()) {
			throw new Error("Private key must be provided");
		}
		
		let publicKey = privateKey.toPublic();
		
		var resp = await connect(hostname, publicKey, privateKey);
		console.log(resp);
	} catch (e) {
		showErr(e);
	}
};

window.pgpGenerate = async () => {
	try {
		const name = document.getElementById("pgp-name-inp")
			.value
			.trim();
		const email = document.getElementById("pgp-email-inp")
			.value
			.trim();
		const pass = document.getElementById("pgp-passphrase-inp")
			.value;
		
		const textField = document.getElementById("connect-pgp-inp");
		
		const btn = document.getElementById("generate-btn");
		const prevBtn = btn.innerText;
		btn.innerText = "Generating...";
		
		const key = await openpgp.generateKey({
			type: 'rsa',
			rsaBits: 4096,
			userIDs: [{ name: name, email: email }],
			passphrase: pass
		});
		
		btn.innerText = prevBtn;
		
		textField.value = key.privateKeyArmored;
	} catch (e) {
		showErr(e);
	}
};
