/*
 * Copyright (c) 2018 Databases and Information Systems Research Group, University of Basel, Switzerland
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.jenkinsci.plugins;


import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import com.google.inject.Inject;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.ManagementLink;
import hudson.model.ModelObject;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.security.ACL;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.AccessControlled;
import hudson.security.AuthorizationStrategy;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.security.GroupDetails;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.HudsonPrivateSecurityRealm.Details;
import hudson.security.HudsonPrivateSecurityRealm.SignupInfo;
import hudson.security.Permission;
import hudson.security.PermissionAdder;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.tasks.Mailer;
import hudson.util.PluginServletFilter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.Symbol;
import org.jfree.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


/**
 * {@link hudson.security.SecurityRealm} that performs authentication by looking up {@link hudson.model.User} locally or by using Phabricator's OAuth Service.
 *
 * <p>
 * This implementation contains methods of {@link hudson.security.HudsonPrivateSecurityRealm}.
 *
 * @see hudson.security.HudsonPrivateSecurityRealm
 */
public class PhabricatorSecurityRealm extends AbstractPasswordBasedSecurityRealm implements AccessControlled, ModelObject {

    private static final String REFERER_ATTRIBUTE = PhabricatorSecurityRealm.class.getName() + ".referer";
    private static final String OAUTH_SCOPES = "";
    private static final String PHAB_OAUTH = "/oauthserver";
    protected static final String PHAB_API_USER_WHOAMI = "/api/user.whoami";

    private String clientID;
    private String clientSecret;
    private String serverURL; // no slash at the end


    public PhabricatorSecurityRealm() {
        if ( !allowsSignup() && !hasSomeUser() ) {
            // if Hudson is newly set up with the security realm and there's no user account created yet,
            // insert a filter that asks the user to create one
            try {
                PluginServletFilter.addFilter( CREATE_FIRST_USER_FILTER );
            } catch ( ServletException e ) {
                throw new AssertionError( e ); // never happen because our Filter.init is no-op
            }
        }
    }


    @DataBoundConstructor
    public PhabricatorSecurityRealm( String serverURL, String clientID, String clientSecret ) {
        this();
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
    public boolean allowsSignup() {
        return false;
    }


    @Restricted(NoExternalUse.class)
    public boolean getAllowsSignup() {
        return allowsSignup();
    }


    private static boolean hasSomeUser() {
        for ( User u : User.getAll() ) {
            if ( u.getProperty( Details.class ) != null ) {
                return true;
            }
        }
        return false;
    }


    @Restricted(NoExternalUse.class)
    public Details loadUser( String username ) throws UsernameNotFoundException {
        User user = User.getById( username, false );
        return user != null ? user.getProperty( Details.class ) : null;
    }


    @Override
    public UserDetails loadUserByUsername2( String username ) throws UsernameNotFoundException {
        Details userProperties = loadUser( username );
        if ( userProperties != null ) {
            // Username:Password was successful
            return new PhabricatorOAuthUserDetails( userProperties );
        }

        // No username:password found
        // Try phabricator oauth

        Authentication authToken = SecurityContextHolder.getContext().getAuthentication();
        if ( authToken == null ) {
            throw new UserMayOrMayNotExistException2( "Could not get auth token." );
        }

        if ( username == null || username.isEmpty() ) {
            throw new UsernameNotFoundException( "Could not get username." );
        }

        return new PhabricatorOAuthUserDetails( username, Collections.singletonList( SecurityRealm.AUTHENTICATED_AUTHORITY2 ) );
    }


    /**
     * This implementation doesn't support groups.
     */
    @Override
    public GroupDetails loadGroupByGroupname2( String groupname, boolean fetchMembers ) throws UsernameNotFoundException {
        throw new UsernameNotFoundException( groupname );
    }


    @Override
    protected UserDetails authenticate2( String username, String password ) throws AuthenticationException {
        Details userProperties = loadUser( username );

        if ( !userProperties.isPasswordCorrect( password ) ) {
            String message;
            try {
                message = ResourceBundle.getBundle( "org.acegisecurity.messages" ).getString( "AbstractUserDetailsAuthenticationProvider.badCredentials" );
            } catch ( MissingResourceException x ) {
                message = "Bad credentials";
            }
            throw new BadCredentialsException( message );
        }
        return new PhabricatorOAuthUserDetails( userProperties );
    }


    /**
     * Lets the current user silently login as the given user and report back accordingly.
     */
    @SuppressWarnings("ACL.impersonate")
    private void loginAndTakeBack( StaplerRequest req, StaplerResponse rsp, User u ) throws ServletException, IOException {
        // ... and let him login
        Authentication a = new UsernamePasswordAuthenticationToken( u.getId(), req.getParameter( "password1" ) );
        a = this.getSecurityComponents().manager2.authenticate( a );
        SecurityContextHolder.getContext().setAuthentication( a );

        SecurityListener.fireLoggedIn( u.getId() );

        // then back to top
        req.getView( this, "success.jelly" ).forward( req, rsp );
    }


    /**
     * Creates a user account. Used by admins.
     *
     * This version behaves differently from {@link hudson.security.HudsonPrivateSecurityRealm#doCreateAccount(StaplerRequest, StaplerResponse)} in that
     * this is someone creating another user.
     */
    @RequirePOST
    public void doCreateAccountByAdmin( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
        createAccountByAdmin( req, rsp, "addUser.jelly", "." ); // send the user back to the listing page on success
    }


    /**
     * Creates a user account. Requires {@link Jenkins#ADMINISTER}
     */
    @Restricted(NoExternalUse.class)
    public User createAccountByAdmin( StaplerRequest req, StaplerResponse rsp, String addUserView, String successView ) throws IOException, ServletException {
        checkPermission( Jenkins.ADMINISTER );
        User u = createAccount( req, rsp, false, addUserView );
        if ( u != null && successView != null ) {
            rsp.sendRedirect( successView );
        }
        return u;
    }


    private String getErrorMessages( SignupInfo si ) {
        StringBuilder messages = new StringBuilder();
        for ( String message : si.errors.values() ) {
            messages.append( message ).append( " | " );
        }
        return messages.toString();
    }


    /**
     * Creates a first admin user account.
     *
     * <p>
     * This can be run by anyone, but only to create the very first user account.
     */
    @RequirePOST
    public void doCreateFirstAccount( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
        if ( hasSomeUser() ) {
            rsp.sendError( SC_UNAUTHORIZED, "First user was already created" );
            return;
        }
        User u = createAccount( req, rsp, false, "firstUser.jelly" );
        if ( u != null ) {
            tryToMakeAdmin( u );
            loginAndTakeBack( req, rsp, u );
        }
    }


    /**
     * Try to make this user a super-user
     */
    private void tryToMakeAdmin( User u ) {
        AuthorizationStrategy as = Jenkins.get().getAuthorizationStrategy();
        for ( PermissionAdder adder : ExtensionList.lookup( PermissionAdder.class ) ) {
            if ( adder.add( as, u, Jenkins.ADMINISTER ) ) {
                return;
            }
        }
    }


    /**
     * @param req the request to get the form data from (is also used for redirection)
     * @param rsp the response to use for forwarding if the creation fails
     * @param validateCaptcha whether to attempt to validate a captcha in the request
     * @param formView the view to redirect to if creation fails
     * @return null if failed. The browser is already redirected to retry by the time this method returns.
     * a valid {@link User} object if the user creation was successful.
     */
    private User createAccount( StaplerRequest req, StaplerResponse rsp, boolean validateCaptcha, String formView ) throws ServletException, IOException {
        SignupInfo si = validateAccountCreationForm( req, validateCaptcha );

        if ( !si.errors.isEmpty() ) {
            // failed. ask the user to try again.
            req.getView( this, formView ).forward( req, rsp );
            return null;
        }

        return createAccount( si );
    }


    /**
     * @param req the request to process
     * @param validateCaptcha whether to attempt to validate a captcha in the request
     * @return a {@link SignupInfo#SignupInfo(StaplerRequest) SignupInfo from given request}, with {@link
     * SignupInfo#errors} containing errors (keyed by field name), if any of the supported fields are invalid
     */
    private SignupInfo validateAccountCreationForm( StaplerRequest req, boolean validateCaptcha ) {
        // form field validation
        // this pattern needs to be generalized and moved to stapler
        SignupInfo si = new SignupInfo( req );

        if ( validateCaptcha && !validateCaptcha( si.captcha ) ) {
            si.errorMessage = "Text didn't match the word shown in the image";
        }

        if ( si.username == null || si.username.length() == 0 ) {
            si.errorMessage = "User name is required";
        } else {
            // do not create the user - we just want to check if the user already exists but is not a "login" user.
            User user = User.getById( si.username, false );
            if ( null != user )
            // Allow sign up. SCM people has no such property.
            {
                if ( user.getProperty( Details.class ) != null ) {
                    si.errorMessage = "User name is already taken";
                }
            }
        }

        if ( si.password1 != null && !si.password1.equals( si.password2 ) ) {
            si.errorMessage = "Password didn't match";
        }

        if ( !(si.password1 != null && si.password1.length() != 0) ) {
            si.errorMessage = "Password is required";
        }

        if ( si.fullname == null || si.fullname.length() == 0 ) {
            si.fullname = si.username;
        }

        if ( isMailerPluginPresent() && (si.email == null || !si.email.contains( "@" )) ) {
            si.errorMessage = "Invalid e-mail address";
        }

        if ( !User.isIdOrFullnameAllowed( si.username ) ) {
            si.errorMessage = "\"" + si.username + "\" is prohibited as a username for security reasons.";
        }

        if ( !User.isIdOrFullnameAllowed( si.fullname ) ) {
            si.errorMessage = "\"" + si.fullname + "\" is prohibited as a full name for security reasons.";
        }

        req.setAttribute( "data", si ); // for error messages in the view
        return si;
    }


    /**
     * Creates a new account from a valid signup info. A signup info is valid if its {@link SignupInfo#errors}
     * field is empty.
     *
     * @param si the valid signup info to create an account from
     * @return a valid {@link User} object created from given signup info
     * @throws IllegalArgumentException if an invalid signup info is passed
     */
    private User createAccount( SignupInfo si ) throws IOException {
        if ( !si.errors.isEmpty() ) {
            String messages = getErrorMessages( si );
            throw new IllegalArgumentException( "invalid signup info passed to createAccount(si): " + messages );
        }

        // register the user
        User user = createAccount( si.username, si.password1 );
        user.setFullName( si.fullname );
        if ( isMailerPluginPresent() ) {
            try {
                // legacy hack. mail support has moved out to a separate plugin
                Class<?> up = Jenkins.get().pluginManager.uberClassLoader.loadClass( "hudson.tasks.Mailer$UserProperty" );
                Constructor<?> c = up.getDeclaredConstructor( String.class );
                user.addProperty( (UserProperty) c.newInstance( si.email ) );
            } catch ( ReflectiveOperationException e ) {
                throw new RuntimeException( e );
            }
        }
        user.save();
        return user;
    }


    @Restricted(NoExternalUse.class)
    public boolean isMailerPluginPresent() {
        try {
            // mail support has moved to a separate plugin
            return null != Jenkins.get().pluginManager.uberClassLoader.loadClass( "hudson.tasks.Mailer$UserProperty" );
        } catch ( ClassNotFoundException e ) {
            LOGGER.finer( "Mailer plugin not present" );
        }
        return false;
    }


    /**
     * Creates a new user account by registering a password to the user.
     */
    public User createAccount( String userName, String password ) throws IOException {
        User user = User.getById( userName, true );
        try {
            Method Details_fromPlainPassword = Details.class.getDeclaredMethod( "fromPlainPassword", String.class );
            if ( !Details_fromPlainPassword.isAccessible() ) {
                Details_fromPlainPassword.setAccessible( true ); //if security settings allow this
            }
            Details details = (Details) Details_fromPlainPassword.invoke( null, password ); //use null if the method is static
            user.addProperty( /*Details.fromPlainPassword( password )*/ details );
        } catch ( NoSuchMethodException | IllegalAccessException | InvocationTargetException e ) {
            throw new IOException( e );
        }
        return user;
    }


    @Override
    public String getDisplayName() {
        return "Manage Local Users";
    }


    @Nonnull
    @Override
    public ACL getACL() {
        return Jenkins.get().getACL();
    }


    @Override
    public void checkPermission( @NonNull Permission permission ) throws AccessDeniedException {
        Jenkins.get().checkPermission( permission );
    }


    @Override
    public boolean hasPermission( @NonNull Permission permission ) {
        return Jenkins.get().hasPermission( permission );
    }


    /**
     * All users who can login to the system.
     */
    public List<User> getAllUsers() {
        List<User> r = new ArrayList<User>();
        for ( User u : User.getAll() ) {
            if ( u.getProperty( Details.class ) != null ) {
                r.add( u );
            }
        }
        Collections.sort( r );
        return r;
    }


    @Restricted(NoExternalUse.class)
    public User getUser( String id ) {
        return User.getById( id, true );
    }


    /**
     *
     */
    public HttpResponse doCommenceLogin( StaplerRequest request, @Header("Referer") String referer ) throws IOException, URISyntaxException {
        LOGGER.log( Level.FINE, "doCommenceLogin" );

        if ( LOGGER.isLoggable( Level.FINE ) ) {
            LOGGER.log( Level.FINE, "doCommenceLogin-OriginalReferer=" + referer );
        }

        final URI originalRefererUri = URI.create( referer );
        final List<NameValuePair> originalQueryParameters = URLEncodedUtils.parse( originalRefererUri, StandardCharsets.UTF_8.toString() );
        final List<NameValuePair> newQueryParameters = new LinkedList<>();

        String path = originalRefererUri.getPath();
        for ( NameValuePair queryParameter : originalQueryParameters ) {
            if ( queryParameter.getName().equals( "from" ) ) {
                path = StringEscapeUtils.unescapeHtml( queryParameter.getValue() );
            } else {
                newQueryParameters.add( queryParameter );
            }
        }

        referer = new URI( originalRefererUri.getScheme(), originalRefererUri.getAuthority(), path, newQueryParameters.isEmpty() ? null : URLEncodedUtils.format( newQueryParameters, StandardCharsets.UTF_8.toString() ), originalRefererUri.getFragment() ).toASCIIString();
        if ( LOGGER.isLoggable( Level.FINE ) ) {
            LOGGER.log( Level.FINE, "doCommenceLogin-New Referer=" + referer );
        }

        request.getSession().setAttribute( REFERER_ATTRIBUTE, referer );

        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add( new BasicNameValuePair( "response_type", "code" ) );
        parameters.add( new BasicNameValuePair( "client_id", clientID ) );
        parameters.add( new BasicNameValuePair( "scope", OAUTH_SCOPES ) );

        // getServerURL() + PHAB_OAUTH + "/auth/?client_id=" + clientID + "&response_type=code&scope=" + OAUTH_SCOPES
        return new HttpRedirect( getServerURL() + PHAB_OAUTH + "/auth/?" + URLEncodedUtils.format( parameters, StandardCharsets.UTF_8.toString() ) );
    }


    /**
     *
     */
    public HttpResponse doFinishLogin( StaplerRequest request ) throws IOException {
        String code = request.getParameter( "code" );

        if ( code == null || code.trim().length() == 0 ) {
            Log.warn( "doFinishLogin: missing code." );
            return HttpResponses.redirectToContextRoot();
        }

        String redirectUrl = Jenkins.get().getRootUrl();
        redirectUrl += (redirectUrl.endsWith( "/" ) ? "" : "/") + "securityRealm/finishLogin";

        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add( new BasicNameValuePair( "client_id", clientID ) );
        parameters.add( new BasicNameValuePair( "client_secret", clientSecret ) );
        parameters.add( new BasicNameValuePair( "code", code ) );
        parameters.add( new BasicNameValuePair( "grant_type", "authorization_code" ) );
        parameters.add( new BasicNameValuePair( "redirect_uri", redirectUrl ) );

        final String content = getUrlContent( new HttpGet( getServerURL() + PHAB_OAUTH + "/token/?" + URLEncodedUtils.format( parameters, StandardCharsets.UTF_8.name() ) ) );
        String accessToken;
        try {
            JSONObject jsonObject = new JSONObject( content );
            accessToken = jsonObject.getString( "access_token" );
        } catch ( JSONException e ) {
            LOGGER.log( Level.WARNING, "accessToken not found=" + e.getMessage() );
            LOGGER.log( Level.WARNING, "Request was: " + getServerURL() + PHAB_OAUTH + "/token/?" + URLEncodedUtils.format( parameters, StandardCharsets.UTF_8.name() ) );
            LOGGER.log( Level.WARNING, "Response was: " + content );
            accessToken = null;
        }

        if ( accessToken != null && accessToken.trim().length() > 0 ) {
            final PhabricatorAuthenticationToken auth = new PhabricatorAuthenticationToken( accessToken );
            SecurityContextHolder.getContext().setAuthentication( auth ); // This sets the Jenkins User ID to the username used in Phabricator
            PhabricatorUser phabricatorUser = auth.getUser();

            // prevent session fixation attack
            Stapler.getCurrentRequest().getSession().invalidate();
            Stapler.getCurrentRequest().getSession();

            User jenkinsUser = User.current(); // == User.get( phabricatorUser.getUsername() ) since the username has already been set according to the one of Phabricator
            if ( jenkinsUser == null ) {
                // This should never happen. We got a username from Phabricator and if this user did not already exist in Jenkins it was created by invoking `User.current()`. It can be `null` if and only if no `Authentication` is set in the `SecurityContextHolder`.
                throw new IllegalStateException( "jenkinsUser == null" );
            }
            jenkinsUser.setFullName( phabricatorUser.getRealname() );
            jenkinsUser.addProperty( new Mailer.UserProperty( phabricatorUser.getEmail() ) );

            SecurityListener.fireLoggedIn( jenkinsUser.getId() );
        } else {
            Log.warn( "Phabricator did not return an access token." );
        }

        String referer = (String) request.getSession().getAttribute( REFERER_ATTRIBUTE );
        if ( referer != null ) {
            return HttpResponses.redirectTo( referer );
        }

        return HttpResponses.redirectToContextRoot();
    }


    protected String getUrlContent( final HttpUriRequest request ) throws IOException {
        DefaultHttpClient httpClient = null;
        try {
            httpClient = new DefaultHttpClient();
            return EntityUtils.toString( httpClient.execute( request ).getEntity() );
        } finally {
            if ( httpClient != null ) {
                httpClient.getConnectionManager().shutdown();
            }
        }
    }


    @Override
    public SecurityComponents createSecurityComponents() {
        final SecurityComponents securityComponents = super.createSecurityComponents();

        return new SecurityComponents( authentication -> {
            if ( authentication instanceof PhabricatorAuthenticationToken ) {
                return authentication;
            }
            return securityComponents.manager2.authenticate( authentication );
        }, securityComponents.userDetails2 );
    }


    @Extension
    public static class PhabricatorLoginService extends FederatedLoginService {

        @Inject
        private transient Jenkins jenkins;


        public PhabricatorLoginService() {
            super();
        }


        public boolean isDisabled() {
            return !(jenkins.getSecurityRealm() instanceof PhabricatorSecurityRealm);
        }


        @Override
        public String getUrlName() {
            return "phabricator";
        }


        @Override
        public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
            return PhabricatorLoginServiceUserProperty.class;
        }
    }


    public class PhabricatorLoginServiceUserProperty extends FederatedLoginServiceUserProperty {

        protected PhabricatorLoginServiceUserProperty( Collection<String> identifiers ) {
            super( identifiers );
        }
    }


    /**
     * Displays "manage users" link in the system config if {@link HudsonPrivateSecurityRealm}
     * is in effect.
     */
    @Extension
    @Symbol("localUsers")
    public static class ManageUserLinks extends ManagementLink {

        @Inject
        private transient Jenkins jenkins;


        public String getIconFileName() {
            if ( jenkins.getSecurityRealm() instanceof PhabricatorSecurityRealm ) {
                return "user.png";
            } else {
                return null;    // not applicable now
            }
        }


        public String getUrlName() {
            return "securityRealm/";
        }


        public String getDisplayName() {
            return "Manage Users";
        }


        @Override
        public String getDescription() {
            return "Create/delete/modify users that can log in to this Jenkins";
        }
    }


    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {

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


    private static final Filter CREATE_FIRST_USER_FILTER = new Filter() {
        public void init( FilterConfig config ) throws ServletException {
        }


        public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException, ServletException {
            HttpServletRequest req = (HttpServletRequest) request;

            /* allow signup from the Jenkins home page, or /manage, which is where a /configureSecurity form redirects to */
            if ( req.getRequestURI().equals( req.getContextPath() + "/" ) || req.getRequestURI().equals( req.getContextPath() + "/manage" ) ) {
                if ( needsToCreateFirstUser() ) {
                    ((HttpServletResponse) response).sendRedirect( "securityRealm/firstUser" );
                } else {// the first user already created. the role of this filter is over.
                    PluginServletFilter.removeFilter( this );
                    chain.doFilter( request, response );
                }
            } else {
                chain.doFilter( request, response );
            }
        }


        private boolean needsToCreateFirstUser() {
            return !hasSomeUser() && Jenkins.get().getSecurityRealm() instanceof HudsonPrivateSecurityRealm;
        }


        public void destroy() {
        }
    };


    private static final Logger LOGGER = Logger.getLogger( PhabricatorSecurityRealm.class.getName() );
}
