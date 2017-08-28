import { OAuthService } from "angular-oauth2-oidc";
import { Injectable } from "@angular/core";

declare var OktaAuth: any;

@Injectable()
export class OktaAuthWrapper {

    private authClient: any;

    constructor(private oauthService: OAuthService) {
        this.authClient = new OktaAuth({
            url: this.oauthService.issuer
        });
    }

    login(username: string, password: string): Promise<any> {

        return this.oauthService.createAndSaveNonce().then(nonce => {
            return this.authClient.signIn({
                username: username,
                password: password
            }).then((response) => {
                if (response.status === 'SUCCESS') {

                    return this.authClient.token.getWithoutPrompt({
                        clientId: this.oauthService.clientId,
                        responseType: ['id_token', 'token'],
                        scopes: ['openid', 'profile', 'email'],
                        sessionToken: response.sessionToken,
                        nonce: nonce,
                        redirectUri: window.location.origin
                    })
                    .then((tokens) => {

                        let idToken = tokens[0].idToken;
                        let accessToken = tokens[1].accessToken;

                        // We need to plant the tokens received by the
                        // okta api into the OAuthService.
                        // For this, we are using a key/value pair, the
                        // service would normally get out of the hash 
                        // fragment. Perhaps we should create an other
                        // options for this.
                        let keyValuePair = `#id_token=${encodeURIComponent(idToken)}&access_token=${encodeURIComponent(accessToken)}`;

                        return this.oauthService.tryLogin({
                            customHashFragment: keyValuePair,
                            disableOAuth2StateCheck: true
                        });

                    });
                } else {
                    return Promise.reject('We cannot handle the ' + response.status + ' status');
                }
            });
        });

    }

}