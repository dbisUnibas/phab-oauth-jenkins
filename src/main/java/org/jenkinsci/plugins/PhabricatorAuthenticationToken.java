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


import hudson.security.SecurityRealm;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.http.client.methods.HttpGet;
import org.json.JSONException;
import org.json.JSONObject;


public class PhabricatorAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final String accessToken;

    private PhabricatorUser user;
    private final String userName;

    private final List<GrantedAuthority> authorities = new ArrayList<>();


    public PhabricatorAuthenticationToken( String accessToken ) throws IOException {
        super( new GrantedAuthority[]{} );

        this.accessToken = accessToken;

        authorities.add( SecurityRealm.AUTHENTICATED_AUTHORITY );

        user = authUsingToken();
        if ( user == null ) {
            throw new BadCredentialsException( "Unexpected authentication type" );
        }

        userName = user.getUsername();
        setAuthenticated( true );
    }


    protected PhabricatorUser getUser() {
        if ( user == null && accessToken != null ) {
            try {
                user = authUsingToken();
            } catch ( IOException e ) {
                LOGGER.log( Level.WARNING, e.getMessage() );
            }
        }
        return user;
    }


    protected PhabricatorUser authUsingToken() throws IOException {
        LOGGER.log( Level.WARNING, "Login using token" );

        final Jenkins jenkins = Jenkins.getInstance();
        final PhabricatorSecurityRealm phabricator;
        if ( jenkins.getSecurityRealm() instanceof PhabricatorSecurityRealm ) {
            phabricator = (PhabricatorSecurityRealm) jenkins.getSecurityRealm();
        } else {
            throw new IllegalStateException( "jenkins.getSecurityRealm() is not PhabricatorSecurityRealm" );
        }
        final String result = phabricator.getUrlContent( new HttpGet( phabricator.getServerURL() + PhabricatorSecurityRealm.PHAB_API_USER_WHOAMI + "?access_token=" + accessToken ) );

        PhabricatorUser user = null;
        try {
            JSONObject jsonObject = new JSONObject( result );
            JSONObject jsonResult = jsonObject.getJSONObject( "result" );

            String userName = jsonResult.getString( "userName" );
            String realName = jsonResult.getString( "realName" );
            String primaryEmail = jsonResult.getString( "primaryEmail" );
            String image = jsonResult.getString( "image" );

            if ( primaryEmail != null && userName != null ) {
                user = new PhabricatorUser( userName, realName, primaryEmail, image );
            }
        } catch ( JSONException e ) {
            LOGGER.log( Level.WARNING, e.getMessage() );
        }
        return user;
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


    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities.toArray( new GrantedAuthority[authorities.size()] );
    }


    private static final Logger LOGGER = Logger.getLogger( PhabricatorAuthenticationToken.class.getName() );

}
