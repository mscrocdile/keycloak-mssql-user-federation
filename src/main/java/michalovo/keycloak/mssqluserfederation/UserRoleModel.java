package michalovo.keycloak.mssqluserfederation;

import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.ReadOnlyException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public class UserRoleModel implements RoleModel {
    private final String name;
    private final RealmModel realm;

    public UserRoleModel(String name, RealmModel realm) {
        this.name = name;
        this.realm = realm;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void setDescription(String s) {
        throw new ReadOnlyException("role is read only1");
    }

    @Override
    public String getId() {
        return name;
    }

    @Override
    public void setName(String s) {
        throw new ReadOnlyException("role is read only2");
    }

    @Override
    public boolean isComposite() {
        return false;
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        throw new ReadOnlyException("role is read only3");
    }

    @Override
    public void removeCompositeRole(RoleModel roleModel) {
        throw new ReadOnlyException("role is read only4");
    }

    @Override
    public Set<RoleModel> getComposites() {
        return null;
    }

    @Override
    public boolean isClientRole() {
        return false;
    }

    @Override
    public String getContainerId() {
        return realm.getId();
    }

    @Override
    public RoleContainerModel getContainer() {
        return realm;
    }

    @Override
    public boolean hasRole(RoleModel roleModel) {
        return this.equals(roleModel) || this.name.equals(roleModel.getName());
    }

    @Override
    public void setSingleAttribute(String s, String s1) {
        throw new ReadOnlyException("role is read only5");
    }

    @Override
    public void setAttribute(String name, Collection<String> values) {

    }

    @Override
    public void removeAttribute(String s) {
        throw new ReadOnlyException("role is read only6");
    }

    @Override
    public String getFirstAttribute(String name) {
        return null;
    }

    @Override
    public List<String> getAttribute(String name) {
        return null;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return Map.of();
    }
}



