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

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

public class PhabricatorSecurityRealm extends SecurityRealm {

	private static final String OAUTH_SCOPES = "whoami";
	private static final String PHAB_OAUTH = "oauthserver/";
	private static final String PHAB_API = "api/user.whoami";
	private static final String REFERER_ATTRIBUTE = PhabricatorSecurityRealm.class
			.getName() + ".referer";
	private static final Logger LOGGER = Logger
			.getLogger(PhabricatorSecurityRealm.class.getName());

	private String clientID;
	private String clientSecret;
	private String serverURL;
	private boolean trustAllCert;

	@DataBoundConstructor
	public PhabricatorSecurityRealm(String serverURL, String clientID,
			String clientSecret, boolean trustAllCert) {
		super();
		this.serverURL = Util.fixEmptyAndTrim(serverURL);
		this.clientID = Util.fixEmptyAndTrim(clientID);
		this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
		this.trustAllCert = trustAllCert;
	}

	public PhabricatorSecurityRealm() {
		super();
		LOGGER.log(Level.FINE, "PhabricatorSecurityRealm()");
	}

	public String getClientID() {
		return clientID;
	}

	public void setClientID(String clientID) {
		this.clientID = clientID;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getServerURL() {
		return serverURL;
	}

	public void setServerURL(String serverURL) {
		this.serverURL = serverURL;
	}

	@Override
	public String getLoginUrl() {
		return "securityRealm/commenceLogin";
	}

	public HttpResponse doCommenceLogin(StaplerRequest request,
			@Header("Referer") final String referer) throws IOException {
		LOGGER.log(Level.WARNING, "doCommenceLogin");
		request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
		return new HttpRedirect(serverURL + PHAB_OAUTH + "/auth/?client_id="
				+ clientID + "&response_type=code&scope=" + OAUTH_SCOPES);
	}

	public HttpResponse doFinishLogin(StaplerRequest request)
			throws IOException {
		String code = request.getParameter("code");

		if (code == null || code.trim().length() == 0) {
			Log.info("doFinishLogin: missing code.");
			return HttpResponses.redirectToContextRoot();
		}

		String rootUrl = Jenkins.getInstance().getRootUrl()
				+ "securityRealm/finishLogin";

		String authUrl = serverURL + PHAB_OAUTH + "/token/?client_id="
				+ clientID + "&client_secret=" + clientSecret + "&code=" + code
				+ "&grant_type=authorization_code&redirect_uri=" + rootUrl;

		if (trustAllCert) {
			LOGGER.log(Level.WARNING, "Trust all certificates");
			Protocol easyhttps = new Protocol("https",
					new EasySSLProtocolSocketFactory(), 443);
			Protocol.registerProtocol("https", easyhttps);
		}

		HttpGet httpGet = new HttpGet(authUrl);
		DefaultHttpClient httpclient = new DefaultHttpClient();
		org.apache.http.HttpResponse response = httpclient.execute(httpGet);
		HttpEntity entity = response.getEntity();
		String content = EntityUtils.toString(entity);
		httpclient.getConnectionManager().shutdown();

		String accessToken;
		try {
			JSONObject jsonObject = new JSONObject(content);
			accessToken = jsonObject.getString("access_token");
			LOGGER.log(Level.WARNING, "accessToken FOUND=" + accessToken);
		} catch (JSONException e) {
			LOGGER.log(Level.WARNING, "accessToken not found=" + e.getMessage());
			accessToken = null;
		}

		if (accessToken != null && accessToken.trim().length() > 0) {
			PhabricatorAuthenticationToken auth = new PhabricatorAuthenticationToken(
					accessToken);
			SecurityContextHolder.getContext().setAuthentication(auth);
			// User u = User.current();
		} else {
			Log.info("Phabricator did not return an access token.");
		}

		String referer = (String) request.getSession().getAttribute(
				REFERER_ATTRIBUTE);
		if (referer != null)
			return HttpResponses.redirectTo(referer);

		return HttpResponses.redirectToContextRoot();
	}

	@Override
	public boolean allowsSignup() {
		return false;
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents(new AuthenticationManager() {

			public Authentication authenticate(Authentication authentication)
					throws AuthenticationException {
				if (authentication instanceof PhabricatorAuthenticationToken)
					return authentication;
				if (authentication instanceof UsernamePasswordAuthenticationToken)
					try {
						UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
						PhabricatorAuthenticationToken auth = new PhabricatorAuthenticationToken(
								token.getCredentials().toString());
						SecurityContextHolder.getContext().setAuthentication(
								auth);
						return auth;
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				throw new BadCredentialsException(
						"Unexpected authentication type: " + authentication);
			}
		}, new UserDetailsService() {
			public UserDetails loadUserByUsername(String username)
					throws UsernameNotFoundException, DataAccessException {
				return PhabricatorSecurityRealm.this
						.loadUserByUsername(username);
			}
		});
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		// TODO: load by username
		return new PhabricatorOAuthUserDetails(username);
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

		@Override
		public String getHelpFile() {
			return "/plugin/phab-oauth/help/help-security-realm.html";
		}

		@Override
		public String getDisplayName() {
			return "Phabricator OAuth Plugin";
		}

		public DescriptorImpl() {
			super();
		}

		public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
			super(clazz);
		}
	}

}
