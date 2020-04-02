/**
 * The MIT License
 *
 * Copyright (c) 2011 Michael O'Cleirigh
 * Copyright (c) 2016 Jean-Baptiste Aubort
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins;


import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
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

    private static final String OAUTH_SCOPES = "";
    private static final String PHAB_OAUTH = "/oauthserver";
    protected static final String PHAB_API_USER_WHOAMI = "/api/user.whoami";
    private static final String REFERER_ATTRIBUTE = PhabricatorSecurityRealm.class.getName() + ".referer";
    private static final Logger LOGGER = Logger.getLogger( PhabricatorSecurityRealm.class.getName() );

    private String clientID;
    private String clientSecret;
    private String serverURL; // no slash at the end


    @DataBoundConstructor
    public PhabricatorSecurityRealm( String serverURL, String clientID, String clientSecret ) {
        super();
        this.serverURL = fixServerUrl( Util.fixEmptyAndTrim( serverURL ) );
        this.clientID = Util.fixEmptyAndTrim( clientID );
        this.clientSecret = Util.fixEmptyAndTrim( clientSecret );
    }


    private String fixServerUrl( String serverUrl ) {
        if ( serverUrl == null ) {
            return "";
        }

        while ( serverUrl.endsWith( "/" ) ) {
            serverUrl = serverUrl.substring( 0, serverUrl.length() - 1 );
        }
        return serverUrl;
    }


    public PhabricatorSecurityRealm() {
        super();
        LOGGER.log( Level.FINE, "PhabricatorSecurityRealm()" );
    }


    public String getClientID() {
        return clientID;
    }


    public void setClientID( String clientID ) {
        this.clientID = clientID;
    }


    public String getClientSecret() {
        return clientSecret;
    }


    public void setClientSecret( String clientSecret ) {
        this.clientSecret = clientSecret;
    }


    public String getServerURL() {
        return serverURL;
    }


    public void setServerURL( String serverURL ) {
        this.serverURL = fixServerUrl( serverURL );
    }


    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }


    public HttpResponse doCommenceLogin( StaplerRequest request, @Header("Referer") final String referer ) throws IOException {
        LOGGER.log( Level.WARNING, "doCommenceLogin" );

        request.getSession().setAttribute( REFERER_ATTRIBUTE, referer );

        return new HttpRedirect( getServerURL() + PHAB_OAUTH + "/auth/?client_id=" + clientID + "&response_type=code&scope=" + OAUTH_SCOPES );
    }


    public HttpResponse doFinishLogin( StaplerRequest request ) throws IOException {
        String code = request.getParameter( "code" );

        if ( code == null || code.trim().length() == 0 ) {
            Log.info( "doFinishLogin: missing code." );
            return HttpResponses.redirectToContextRoot();
        }

        String rootUrl = Jenkins.getInstance().getRootUrl();
        rootUrl += (rootUrl.endsWith( "/" ) ? "" : "/") + "securityRealm/finishLogin";

        String authUrl = getServerURL() + PHAB_OAUTH + "/token/?client_id=" + clientID + "&client_secret=" + clientSecret + "&code=" + code + "&grant_type=authorization_code&redirect_uri=" + rootUrl;

        String content = getUrlContent( authUrl );
        String accessToken;
        try {
            JSONObject jsonObject = new JSONObject( content );
            accessToken = jsonObject.getString( "access_token" );
            LOGGER.log( Level.WARNING, "accessToken FOUND=" + accessToken );
        } catch ( JSONException e ) {
            LOGGER.log( Level.WARNING, "accessToken not found=" + e.getMessage() );
            accessToken = null;
        }

        if ( accessToken != null && accessToken.trim().length() > 0 ) {
            PhabricatorAuthenticationToken auth = new PhabricatorAuthenticationToken( accessToken );
            SecurityContextHolder.getContext().setAuthentication( auth );
            PhabricatorUser phabricatorUser = auth.getUser();

            User jenkinsUser = User.current();
            jenkinsUser.setFullName( phabricatorUser.getRealname() );
            jenkinsUser.addProperty( new Mailer.UserProperty( phabricatorUser.getEmail() ) );
            // TODO: What is it for the jenkinsUser object ?
        } else {
            Log.info( "Phabricator did not return an access token." );
        }

        String referer = (String) request.getSession().getAttribute( REFERER_ATTRIBUTE );
        if ( referer != null ) {
            return HttpResponses.redirectTo( referer );
        }

        return HttpResponses.redirectToContextRoot();
    }


    protected String getUrlContent( String url ) throws IOException {
        HttpGet httpGet = new HttpGet( url );
        DefaultHttpClient httpclient = new DefaultHttpClient();
        org.apache.http.HttpResponse response = httpclient.execute( httpGet );
        HttpEntity entity = response.getEntity();
        String content = EntityUtils.toString( entity );
        httpclient.getConnectionManager().shutdown();
        return content;
    }


    @Override
    public boolean allowsSignup() {
        return false;
    }


    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents( new AuthenticationManager() {

            public Authentication authenticate( Authentication authentication )
                    throws AuthenticationException {
                if ( authentication instanceof PhabricatorAuthenticationToken ) {
                    return authentication;
                }
                if ( authentication instanceof UsernamePasswordAuthenticationToken ) {
                    try {
                        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
                        PhabricatorAuthenticationToken auth = new PhabricatorAuthenticationToken( token.getCredentials().toString() );
                        SecurityContextHolder.getContext().setAuthentication( auth );
                        return auth;
                    } catch ( IOException e ) {
                        throw new RuntimeException( e );
                    }
                }
                throw new BadCredentialsException( "Unexpected authentication type: " + authentication );
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername( String username )
                    throws UsernameNotFoundException, DataAccessException {
                return PhabricatorSecurityRealm.this.loadUserByUsername( username );
            }
        } );
    }


    @Override
    public UserDetails loadUserByUsername( String username ) {
        Authentication authToken = SecurityContextHolder.getContext().getAuthentication();
        if ( authToken == null ) {
            throw new UsernameNotFoundException( "Could not get auth token." );
        }

        if ( username == null || username.isEmpty() ) {
            throw new UsernameNotFoundException( "Could not get username." );
        }

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add( SecurityRealm.AUTHENTICATED_AUTHORITY );

        PhabricatorOAuthUserDetails userDetails = new PhabricatorOAuthUserDetails( username, authorities.toArray( new GrantedAuthority[authorities.size()] ) );

        return userDetails;
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


        public DescriptorImpl( Class<? extends SecurityRealm> clazz ) {
            super( clazz );
        }
    }

}
