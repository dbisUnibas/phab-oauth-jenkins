
package org.jenkinsci.plugins;


import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import java.io.IOException;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;


/**
 * @author Kohsuke Kawaguchi, jenkins-openid-plugin
 */
@Extension
public class StaticResourceServer implements UnprotectedRootAction {

    public String getIconFileName() {
        return null;
    }


    public String getDisplayName() {
        return null;
    }


    public String getUrlName() {
        return "phabricator-assets";
    }


    // serve static resources
    public void doDynamic( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
        Jenkins.getActiveInstance().getPlugin( "phab-oauth" ).doDynamic( req, rsp );
    }
}
