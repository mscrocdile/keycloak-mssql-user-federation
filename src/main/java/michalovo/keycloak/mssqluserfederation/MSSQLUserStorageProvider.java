/*
   Copyright 2020 Kyriakos Chatzidimitriou

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package michalovo.keycloak.mssqluserfederation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

public class MSSQLUserStorageProvider
        implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, CredentialInputUpdater, UserQueryProvider {



    protected KeycloakSession session;
    protected Connection conn;
    protected ComponentModel config;

    private static final Logger logger = Logger.getLogger(MSSQLUserStorageProvider.class);

    public MSSQLUserStorageProvider(KeycloakSession session, ComponentModel config, Connection conn) {
        this.session = session;
        this.config = config;
        this.conn = conn;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        System.out.println("HIW: starting getUserByUsername " + username);
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UserModel adapter = null;
        try {
            String query = "SELECT  " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();
            String pword = null;
            if (rs.next()) {
                pword = rs.getString(this.config.getConfig().getFirst("passwordcol"));
                System.out.println("HIW: A3 " + pword);
            }
            if (pword != null) {
                adapter = createAdapter(realm, username);
                System.out.println("HIW: "+adapter.getId()+" user succesfully returned");
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }
        return adapter;
    }

    protected UserModel createAdapter(RealmModel realm, String username) {
        return new AbstractUserAdapter(session, realm, config) {
            @Override
            public String getUsername() {
                return username;
            }

            @Override
            protected Set<RoleModel> getRoleMappingsInternal() {
                List<RoleModel> roles = new ArrayList<RoleModel>();
                if (username.toLowerCase().trim().equals("xyz")) {
                    roles.add(new UserRoleModel("adminuser", realm));
                    System.out.println("hiw: nastavuju role pro super uzivatele " + username);
                } else {
                    System.out.println("hiw: role pro uzivatele " +  username.toLowerCase().trim());
                }
                roles.add(new UserRoleModel("normaluser", realm));
                return new HashSet<RoleModel>(roles);
            }
        };
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        System.out.println("hiw: getUserById "+ id);
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(username, realm);
    }



    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        System.out.println("hiw: getUserByEmail(null) ...");
        return null;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        System.out.println("hiw: isConfiguredFor ...");
        System.out.println(user.getUsername() + "'s credtype " + credentialType);
        String password = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            String query = "SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, user.getUsername());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }
        return credentialType.equals(CredentialModel.PASSWORD) && password != null;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(CredentialModel.PASSWORD);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()))
            return false;
        String password = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            String query = "SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, user.getUsername());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }

        if (password == null)
            return false;

        String hex = null;
        if (this.config.getConfig().getFirst("hash").equalsIgnoreCase("SHA1")) {
            hex = DigestUtils.sha1Hex(input.getChallengeResponse());
        } else {
            hex = DigestUtils.md5Hex(input.getChallengeResponse());
        }

        boolean res = password.trim().equalsIgnoreCase(hex.trim());
        if (res)
            System.out.println("hiw: HESLO je validni!");
        else {
            System.out.println("HIW: heslo neni stejne");
            System.out.println(password);
            System.out.println(hex);
        }
        return res;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        System.out.println("Try to update credentials type "+input.getType()+" for user " + user.getId());
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        System.out.println("hiw: updateCredential ...");
        if (input.getType().equals(CredentialModel.PASSWORD))
            System.out.println("heslo je stejny.. coze?");
            //throw new ReadOnlyException("user is read only for this update");

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        System.out.println("hiw:disableCred ...");
    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }

    @Override
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException sqlEx) {
                logger.error(sqlEx.getMessage());
            } // ignore
            conn = null;
        }
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        System.out.println("hiw:getUsersCount");
        return 0;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        System.out.println("hiw:getUsers");
        return null;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        System.out.println("hiw:getUsersA");
        return null;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        System.out.println("hiw:searchForUser " + search);
        return null;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        System.out.println("hiw:searchForUser " + search);
        return null;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        System.out.println("hiw:searchForUserB");
        return null;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        System.out.println("hiw:searchForUserA " + params.toString());
        List<UserModel> result = new ArrayList<UserModel>();
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UserModel adapter = null;
        try {
            String query = "SELECT  " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table");
            pstmt = conn.prepareStatement(query);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                String un = rs.getString(this.config.getConfig().getFirst("usernamecol"));
                adapter = createAdapter(realm, un);
                result.add(adapter);
                System.out.println("HIW: " + adapter.getId() + "(" + un + ")" + " user succesfully found :)");
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }
        return result;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        System.out.println("hiw:getGroupMembers");
        return null;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        System.out.println("hiw:getGroupMembers");
        return null;
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        System.out.println("hiw:searchForUserByUserAttr");
        return null;
    }


}
