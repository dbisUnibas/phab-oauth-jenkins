/**
 The MIT License

Copyright (c) 2011 Michael O'Cleirigh
Copyright (c) 2016 Jean-Baptiste Aubort

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.



 */
package org.jenkinsci.plugins;

import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import jenkins.model.Jenkins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

public class PhabricatorAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;
	private final String accessToken;

	private final String userName;
	private PhabricatorSecurityRealm myRealm = null;

	private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

	public PhabricatorAuthenticationToken(String accessToken)
			throws IOException {
		super(new GrantedAuthority[] {});

		this.accessToken = accessToken;
		this.userName = "";

		// Authenticate using token

		setAuthenticated(true);

		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
		if (Jenkins.getInstance().getSecurityRealm() instanceof PhabricatorSecurityRealm) {
			if (myRealm == null) {
				myRealm = (PhabricatorSecurityRealm) Jenkins.getInstance()
						.getSecurityRealm();
			}
		}
	}

	public String getAccessToken() {
		return accessToken;
	}

	public Object getCredentials() {
		return ""; // do not expose the credential
	}

	public String getPrincipal() {
		return this.userName;
	}

	private static final Logger LOGGER = Logger
			.getLogger(PhabricatorAuthenticationToken.class.getName());

}
