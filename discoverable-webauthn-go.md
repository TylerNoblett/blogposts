# Discoverable WebAuthn with Go and Typescript
In this post, I'm going to explain how to enable discoverable webauthn credentials in Go. 

The code snippets are taken from [ASHIRT](https://github.com/ashirt-ops/ashirt-server), an open source tool used for documenting and reporting evidence for red teams that I've been working on occasionally for the past year. If you'd like more context for these code snippets, I've included the file name and function name that the snippet came from at the top of each code block.

Additionally, the team behind the [Go WebAuthn library](https://github.com/go-webauthn/webauthn) has provided an [example repo](https://github.com/go-webauthn/example) that might be helpful; I used this example repo, the library code and a few other repos on Github to figure out how to set up discoverable login, as the WebAuthn library doesn't explicity explain how to set it up. I'm assuming that you already have username based WebAuthn setup, or at least have an understanding of how it works from the repo's readme.

## Registration (Attestation)
When registering a user, both username and discoverable auth flows use the `BeginRegistration` function, but you'll want to include `protocol.ResidentKeyRequirementRequired` for the `ResidentKey` field in your `AuthenticatorSelection` as a registration option. By setting `ResidentKey` to `protocol.ResidentKeyRequirementRequired`, we are telling the WebAuthn library to issue an error if the device cannot be registered as a resident credential (which is another name for discoverable credential). This is essential, because discoverable login can only 'discover' resident keys. 

Note that `FinishRegistration` is handled the same way as you would with a username, so I haven't included a code snippet for it.
```go
// https://github.com/ashirt-ops/ashirt-server/blob/main/backend/authschemes/webauthn/webauthn.go
// beginRegistration
if discoverable {
    selection = protocol.AuthenticatorSelection{
        ResidentKey: protocol.ResidentKeyRequirementRequired,
    }
}

registrationOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
    credCreationOpts.AuthenticatorSelection = selection
    // Any other options you might want
}

credOptions, sessionData, err := a.Web.BeginRegistration(&user, auth.WithAuthenticatorSelection(selection), registrationOptions)
```

## Login (Assertion)
The login process is where we see major differences between username and discoverable processes. With a username, you retrieve the user, and pass them along to BeginLogin.
```go
// https://github.com/ashirt-ops/ashirt-server/blob/main/backend/authschemes/webauthn/webauthn.go
// beginLogin
options, sessionData, err := a.Web.BeginLogin(&webauthnUser)
```

However, for discoverable login, we aren't given a username, so we only pass along our login options (if desired, but not essential) or nothing at all. In return, we'll receieve session data, which we'll need to save for the second part of the login process.
```go
// https://github.com/ashirt-ops/ashirt-server/blob/main/backend/authschemes/webauthn/webauthn.go
// beginLogin
// These options are not required, given as an example
var opts = []auth.LoginOption{
	auth.WithUserVerification(protocol.VerificationPreferred),
}
options, sessionData, err = a.Web.BeginDiscoverableLogin(opts...)
```

### Finish Login

In the traditional login process, you're basically home free at this point. You pass the user along with the session data you received in the beginning of the login process, which will verify the idenity of the user.
```go
// https://github.com/ashirt-ops/ashirt-server/blob/main/backend/authschemes/webauthn/webauthn.go
// remux.Route(r, "POST", "/login/finish", ...
cred, err = a.Web.FinishLogin(user, *data.WebAuthNSessionData, r)
```
However, it gets substantially trickier for validating the discoverable login. 
1. The first step is parsing the credential request. Most of the other functions we've used (FinishRegistration, BeginLogin, FinishLogin) have handled parsing for us, but here we need to parse it ourselves.
2. We then create a `userHandler` which we will allow us to get the User from our database using either the `rawID` or the `userHandle`, both of which are byte slices
3. Pass the handle, session data, and parsed response to `ValidateDiscoverableLogin`.
```go
// https://github.com/ashirt-ops/ashirt-server/blob/main/backend/authschemes/webauthn/webauthn.go
// remux.Route(r, "POST", "/login/finish", ...
// #1 parse the response
parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
// handle the error ...

// #2 create the user handler
userHandler := func(rawID byte[], userHandle []byte) (user auth.User, err error) {
	// call your DB to get the user using the userHandle or rawID, 
	webauthnUser := someOperationToGetUser(userHandle, rawID)
	return &webauthnUser, nil
}
// #3 Validate
cred, err = a.Web.ValidateDiscoverableLogin(userHandler, *data.WebAuthNSessionData, parsedResponse)
```

When I was working on setting up discoverable auth for ASHIRT, I could not find almost any resources on this topic, so I hope this post saves you some time and makes your life a little easier!













## Excess Stuff - could include if making a full blown webauthn post
// TODO TN clean this up
*, 
This is not somethig we had to worry about with FinishLogin, because FinishLogin is a wrapper for ValidateLogin,  an extra step for parsing:
```go
// FinishLogin takes the response from the client and validate it against the user credentials and stored session data.
func (webauthn *WebAuthn) FinishLogin(user User, session SessionData, response *http.Request) (*Credential, error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
	if err != nil {
		return nil, err
	}

	return webauthn.ValidateLogin(user, session, parsedResponse)
}
```


// TODO TN should I include this?
# What is WebAuthn
WebAuthn (short for Web Authentication) is a web standard that has been designed as a replacement for password based authentication. It does this by using either a hardware token (ie a yubikey or smart card) or biometrics (fingerprint or facial recogntion) that you might find on a laptop or smartphone. The benefit is that, in order to log in, an attacker must steal your physical device. 

In a standard WebAuthn setup, a user provides a username, which pulls the user info from the database, and then determines the validity of the user by checking the saved public key against the devices' private key.

However, there exist another method, called discoverable login, where the hardware key is saved (how exactly to put this) to the client device. In this setup, a user can simply click a login button (without a username!), and a list of resident devices will appear. Aftering attaching their device (ie inserting their usb key, etc), the user will be logged in. (include video example?)

While there are some disadvantages (share them?), this provides an incredibly simple user experience.

// TODO - explain why I left other code in
// or maybe I should remove it, and give file names for context



// TODO TN - do I even need to include this? This isn't discoverable specific 
// TODO TN explain that resident means discoverable?
On the front end, you'll want to 
1. take the credOptions created on the backend by `BeginRegistration`, which will need to be CredentialCreationOptions object
2. Register the credential as a resident credential
3. Send to the backend, like ou would wtih 
```ts
// https://github.com/ashirt-ops/ashirt-server/blob/main/frontend/src/authschemes/webauthn/login/index.tsx
// RegisterModal
// #1
const reg = await beginRegistration({
	firstName: firstNameField.value,
	lastName: lastNameField.value,
	email: emailField.value,
	username: usernameField.value,
	credentialName: keyNameField.value,
}, props.isDiscoverable)
const credOptions = convertToCredentialCreationOptions(reg)

// #2
const signed = await navigator.credentials.create(credOptions)

if (signed == null || signed.type != 'public-key') {
	throw new Error("WebAuthn is not supported")
}
const pubKeyCred = signed as PublicKeyCredential
const pubKeyResponse = pubKeyCred.response as AuthenticatorAttestationResponse

// for helper functions such as encodeAsB64, see https://github.com/ashirt-ops/ashirt-server/blob/main/frontend/src/authschemes/webauthn/helpers.ts
await finishRegistration({
	type: 'public-key',
	id: pubKeyCred.id,
	rawId: encodeAsB64(pubKeyCred.rawId),
	response: {
		attestationObject: encodeAsB64(pubKeyResponse.attestationObject),
		clientDataJSON: encodeAsB64(pubKeyResponse.clientDataJSON),
	},
})
```



link to file where this is located
```ts
// These two lines calls the backend and transforms the data we receive
// All that really matters is that your credoptions is a PublicKeyCredentialRequestOptions object
const protoOptions = await beginLogin({ username: usernameField.value }, isDiscoverable)
const credOptions = convertToPublicKeyCredentialRequestOptions(protoOptions)

// This line creates the UI to let a user choose their credential
const cred = await navigator.credentials.get({
	publicKey: credOptions
})
if (cred == null || cred.type != 'public-key') {
	throw new Error("WebAuthn is not supported")
}
const pubKeyCred = cred as PublicKeyCredential
const pubKeyResponse = pubKeyCred.response as AuthenticatorAssertionResponse

// for helper functions such as encodeAsB64, see https://github.com/ashirt-ops/ashirt-server/blob/main/frontend/src/authschemes/webauthn/helpers.ts
await finishLogin({
	id: pubKeyCred.id,
	rawId: encodeAsB64(pubKeyCred.rawId),
	type: pubKeyCred.type,
	response: {
		authenticatorData: encodeAsB64(pubKeyResponse.authenticatorData),
		clientDataJSON: encodeAsB64(pubKeyResponse.clientDataJSON),
		signature: encodeAsB64(pubKeyResponse.signature),
		userHandle: pubKeyResponse.userHandle == null ? "" : encodeAsB64(pubKeyResponse.userHandle),
	}
}, isDiscoverable)
```
