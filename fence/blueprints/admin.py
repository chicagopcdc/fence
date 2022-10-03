"""
Blueprints for administation of the userdatamodel database and the storage
solutions. Operations here assume the underlying operations in the interface
will maintain coherence between both systems.
"""

import functools

from flask import request, jsonify, Blueprint, current_app
from flask_sqlalchemy_session import current_session

from gen3authz.client.arborist.client import ArboristClient
from cdislogging import get_logger

from fence.auth import admin_login_required
from fence.authz.errors import ArboristError
from fence.authz.auth import remove_permission
from fence.resources import admin
from fence.scripting.fence_create import sync_users
from fence.config import config
from fence.models import User, DocumentSchema
from fence.errors import UserError, NotFound, InternalError




logger = get_logger(__name__)


blueprint = Blueprint("admin", __name__)


def debug_log(function):
    """Output debug information to the logger for a function call."""
    argument_names = list(function.__code__.co_varnames)

    @functools.wraps(function)
    def write_log(*args, **kwargs):
        argument_values = (
            "{} = {}".format(arg, value)
            for arg, value in list(zip(argument_names, args)) + list(kwargs.items())
        )
        msg = function.__name__ + "\n\t" + "\n\t".join(argument_values)
        logger.debug(msg)
        return function(*args, **kwargs)

    return write_log


#### USERS ####


@blueprint.route("/users/<username>", methods=["GET"])
@blueprint.route("/user/<username>", methods=["GET"])
@admin_login_required
@debug_log
def get_user(username):
    """
    Get the information of a user from our userdatamodel database

    Returns a json object
    """
    return jsonify(admin.get_user_info(current_session, username))


@blueprint.route("/users", methods=["GET"])
@blueprint.route("/user", methods=["GET"])
@admin_login_required
@debug_log
def get_all_users():
    """
    Get the information of all users from our userdatamodel database

    Returns a json object.
    """
    return jsonify(admin.get_all_users(current_session))


@blueprint.route("/users/selected", methods=["POST"])
@blueprint.route("/user/selected", methods=["POST"])
@admin_login_required
@debug_log
def get_users():
    """
    Get the information about each user included in the submitted username list from our 
    userdatamodel database

    Returns a json object of one or more user records
    """
    usernames = request.get_json().get('usernames', None)
    ids = request.get_json().get('ids', None)
    
    if (ids and usernames):
        raise UserError("Wrong params, only one among `ids` and `usernames` should be set.")

    if usernames:
        users = admin.get_users(current_session, usernames)
    elif ids:
        users = admin.get_users_by_id(current_session, ids)
    else:
        raise UserError("Wrong params, at least one among `ids` and `usernames` should be set.")
        
    return jsonify(users)


@blueprint.route("/users", methods=["POST"])
@blueprint.route("/user", methods=["POST"])
@admin_login_required
@debug_log
def create_user():
    """
    Create a user on the userdatamodel database

    Returns a json object
    """
    username = request.get_json().get("name", None)
    role = request.get_json().get("role", None)
    email = request.get_json().get("email", None)
    return jsonify(admin.create_user(current_session, username, role, email))


@blueprint.route("/users/<username>", methods=["PUT"])
@blueprint.route("/user/<username>", methods=["PUT"])
@admin_login_required
@debug_log
def update_user(username):
    """
    Create a user on the userdatamodel database

    Returns a json object
    """
    name = request.get_json().get("name", None)
    role = request.get_json().get("role", None)
    email = request.get_json().get("email", None)
    return jsonify(admin.update_user(current_session, username, role, email, name))


@blueprint.route("/users/<username>", methods=["DELETE"])
@blueprint.route("/user/<username>", methods=["DELETE"])
@admin_login_required
@debug_log
def delete_user(username):
    """
    Remove the user from the userdatamodel database and all associated storage
    solutions.

    Returns json object
    """
    response = jsonify(admin.delete_user(current_session, username))
    return response


@blueprint.route("/users/<username>/groups", methods=["GET"])
@blueprint.route("/user/<username>/groups", methods=["GET"])
@admin_login_required
@debug_log
def get_user_groups(username):
    """
    Get the information of a user from our userdatamodel database.

    Returns a json object
    """
    return jsonify(admin.get_user_groups(current_session, username))


@blueprint.route("/users/<username>/groups", methods=["PUT"])
@blueprint.route("/user/<username>/groups", methods=["PUT"])
@admin_login_required
@debug_log
def add_user_to_groups(username):
    """
    Create a user to group relationship in the database

    Returns a json object
    """
    groups = request.get_json().get("groups", [])
    return jsonify(admin.add_user_to_groups(current_session, username, groups=groups))


@blueprint.route("/users/<username>/groups", methods=["DELETE"])
@blueprint.route("/user/<username>/groups", methods=["DELETE"])
@admin_login_required
@debug_log
def remove_user_from_groups(username):
    """
    Create a user to group relationship in the database

    Returns a json object
    """
    groups = request.get_json().get("groups", [])
    return jsonify(
        admin.remove_user_from_groups(current_session, username, groups=groups)
    )


@blueprint.route("/users/<username>/projects", methods=["DELETE"])
@blueprint.route("/user/<username>/projects", methods=["DELETE"])
@admin_login_required
@debug_log
def remove_user_from_projects(username):
    """
    Create a user to group relationship in the database

    Returns a json object
    """
    projects = request.get_json().get("projects", [])
    return jsonify(admin.remove_user_from_projects(current_session, username, projects))


@blueprint.route("/users/<username>/projects", methods=["PUT"])
@blueprint.route("/user/<username>/projects", methods=["PUT"])
@admin_login_required
@debug_log
def add_user_to_projects(username):
    """
    Create a user to project relationship on the database and add the access to
    the the object store associated with it

    Returns a json object
    """
    projects = request.get_json().get("projects", [])
    return jsonify(
        admin.add_user_to_projects(current_session, username, projects=projects)
    )

@blueprint.route("/toggle_admin", methods=["POST"])
@admin_login_required
@debug_log
def toggle_admin():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_resource`

    payload:
    `{
        "parent_path": "/services/",
        "name": "amanuensis",
        "description": "Amanuensis admin resource"
    }`
    """
    body = request.get_json()
    user_id = body.get('user_id', None)

    if user_id is None:
        raise UserError("There are some missing parameters in the payload.")

    res = admin.toggle_admin(current_session, user_id)
    if res is None or len(res) < 1:
        raise InternalError(
            "Resource {} has not been created.".format(
                user_id
            )
        )
    else:
        logger.info("Updated resource")

    return jsonify(res)

@blueprint.route("/update_user_authz", methods=["POST"])
@admin_login_required
@debug_log
def update_user_authz():
    """
    run user sync to update fence anf arborist DB

    Receive a JSON object with the list of resources, policies, roles, and user auth

    Returns a json object
    """

    logger.warning("IN UPDATE")
    logger.warning(request.get_json())

    sync_users(
            dbGaP=[{'info': {'host': '', 'username': '', 'password': '', 'port': 22, 'proxy': '', 'proxy_user': ''}, 'protocol': 'sftp', 'decrypt_key': '', 'parse_consent_code': True}], # dbGap
            STORAGE_CREDENTIALS={}, # storage_credential
            DB=config["DB"], # flask.current_app.db, # postgresql://fence_user:fence_pass@postgres:5432/fence_db DB
            projects=None, #project_mapping
            is_sync_from_dbgap_server=False,
            sync_from_local_csv_dir=None,
            sync_from_local_yaml_file=None, #'user.yaml',
            json_from_api=request.get_json(),
            arborist=flask.current_app.arborist,
            folder=None,
        )

    # username = request.get_json().get("name", None)
    # role = request.get_json().get("role", None)
    # email = request.get_json().get("email", None)
    # return jsonify(admin.create_user(current_session, username, role, email))
    return jsonify("test")


@blueprint.route("/add_resource", methods=["POST"])
@admin_login_required
@debug_log
def add_resource():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_resource`

    payload:
    `{
        "parent_path": "/services/",
        "name": "amanuensis",
        "description": "Amanuensis admin resource"
    }`
    """
    body = request.get_json()

    parent_path = body.get('parent_path', None)
    name = body.get('name', None)
    description = body.get('description', None)

    if name is None:
        raise UserError("There are some missing parameters in the payload.")

    resource_json = {}
    resource_json["name"] = name
    resource_json["description"] = description
    res = current_app.arborist.create_resource(parent_path, resource_json)
    if res is None:
        raise ArboristError(
            "Resource {} has not been created.".format(
                resource_json
            )
        )
    else:
        logger.info("Created resource {}".format(resource_json))

    return jsonify(res)


@blueprint.route("/add_role", methods=["POST"])
@admin_login_required
@debug_log
def add_role():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_role`

    payload:
    `{
        "id": "amanuensis_admin",
        "description": "can do admin work on project/data request",
        "permissions": [
            {
                "id": "amanuensis_admin_action", 
                "action": {
                    "service": "amanuensis", 
                    "method": "*"
                }
            }
        ]
    }`
    """
    body = request.get_json()

    id = body.get('id', None)
    description = body.get('description', None)
    permissions = body.get('permissions', None)

    if id is None or permissions is None:
        raise UserError("There are some missing parameters in the payload.")

    role_json = {}
    role_json["id"] = id
    role_json["description"] = description
    role_json["permissions"] = permissions
    res = current_app.arborist.create_role(role_json)
    if res is None:
        raise ArboristError(
            "Role {} has not been created.".format(
                role_json
            )
        )
    else:
        logger.info("Created role {}".format(role_json))

    return jsonify(res)


@blueprint.route("/add_policy", methods=["POST"])
@admin_login_required
@debug_log
def add_policy():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_policy`

    payload:
    `{
        "id": "services.amanuensis-admin",
        "description": "admin access to amanunsis",
        "resource_paths": [
            "/services/amanuensis"
        ],
        "role_ids": [
            "amanuensis_admin"
        ]   
    }`
    """
    body = request.get_json()

    policy_id = body.get('id', None)
    description = body.get('description', None)
    resource_paths = body.get('resource_paths', None)
    role_ids = body.get('role_ids', None)

    if policy_id is None or resource_paths is None or role_ids is None:
        raise UserError("There are some missing parameters in the payload.")

    # Check if resource exists
    for path in resource_paths:
        resource = current_app.arborist.get_resource(path)
        if resource is None:
            raise NotFound("Resource {} not found".format(path))

    # Check if role exists
    # TODO gen3authz 1.4.2 doens't support get_role, create a PR or see if future versions support that.
    roles = current_app.arborist.list_roles()
    arborist_role_ids = [role["id"] for role in roles.json["roles"]]
    for id in role_ids:
        if id not in arborist_role_ids:
            raise NotFound("Role {} not found.".format(id))

    policy_json = {}
    policy_json["id"] = policy_id
    policy_json["description"] = description
    policy_json["resource_paths"] = resource_paths
    policy_json["role_ids"] = role_ids
    res = current_app.arborist.create_policy(policy_json)
    if res is None:
        raise ArboristError(
            "Policy {} has not been created.".format(
                policy_json
            )
        )
    else:
        logger.info("Created policy {}".format(policy_json))

    return jsonify(res)


@blueprint.route("/add_policy_to_user", methods=["POST"])
@admin_login_required
@debug_log
def add_policy_to_user():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_policy_to_user`

    payload:
    `{
       "policy_name" = "services.amanuensis-admin",
       "username" = "graglia01@gmail.com"
    }`
    """
    body = request.get_json()

    policy_name = body.get('policy_name', None)
    username = body.get('username', None)

    if username is None or policy_name is None:
        raise UserError("There are some missing parameters in the payload.")

    # Check if username is present in the DB and is a registered user
    users = admin.get_users(current_session, [username])
    users = users["users"]
    if len(users) == 0:
        raise NotFound("User {} not found!".format(username))
    elif len(users) > 1:
        raise InternalError("Too many user with the same username: {}. check the DB".format(username))

    # Check if policy is present in the DB
    policy = current_app.arborist.get_policy(policy_name)
    if policy is None:
        raise NotFound('Policy {} not found.'.format(policy_name))

    res = current_app.arborist.grant_user_policy(username, policy_name)
    if res is None:
        raise ArboristError(
            "Policy {} has not been assigned.".format(
                policy_name
            )
        )

    return jsonify(res)


@blueprint.route("/add_authz_all", methods=["POST"])
@admin_login_required
@debug_log
def add_authz_all():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_authz_all`

    payload:
    `{
       "resource": {
          parent_path = '/services/',
          "name" = "amanuensis",
          "description" = "Amanuensis admin resource"
       },
       "role": {
          "id" = "amanuensis_admin"
          "description" = "can do admin work on project/data request"
          "permissions" = [
              {
                 "id": "amanuensis_admin_action", 
                 "action": {
                     "service": "amanuensis", 
                     "method": "*"}
                }
          ] 
       },
       "policy": {
          "id" = "services.amanuensis-admin",
          "description" = "admin access to amanunsis",
          "resource_paths" = [
            '/services/amanuensis'
          ],
          "role_ids" = [
            'amanuensis_admin'
          ]
       },
       "username" = "graglia01@gmail.com"
    
    }`
    """
    body = request.get_json()

    resource = body.get('resource', None)
    role = body.get('role', None)
    policy = body.get('policy', None)
    username = body.get('username', None)

    if resource is None or role is None or policy is None or username is None:
        raise UserError("There are some missing parameters in the payload.")


    # Check if username is present in the DB and is a registered user
    users = admin.get_users(current_session, [username])
    if len(users) == 0:
        raise NotFound("User {} not found!".format(username))
    elif len(users) > 1:
        raise InternalError("Too many user with the same username: {}. check the DB".format(username))


    # parent_path = '/services/'
    parent_path = resource["parent_path"]
    resource_json = {}
    resource_json["name"] = resource["name"]
    resource_json["description"] = resource["description"]
    res = current_app.arborist.create_resource(parent_path, resource_json)
    if res is None:
        raise ArboristError(
            "Resource {} has not been created.".format(
                resource_json
            )
        )
    else:
        logger.info("Created resource {}".format(resource_json))


    role_json = {}
    role_json["id"] = role["id"]
    role_json["description"] = role["description"]
    role_json["permissions"] = role["permissions"]
    res = current_app.arborist.create_role(role_json)
    if res is None:
        raise ArboristError(
            "Role {} has not been created.".format(
                role_json
            )
        )
    else:
        logger.info("Created role {}".format(role_json))


    policy_json = {}
    policy_json["id"] = policy["id"]
    policy_json["description"] = policy["description"]
    policy_json["resource_paths"] = policy["resource_paths"]
    policy_json["role_ids"] = policy["role_ids"]
    res = current_app.arborist.create_policy(policy_json)
    if res is None:
        raise ArboristError(
            "Policy {} has not been createsd.".format(
                policy_json
            )
        )
    else:
        logger.info("Created role {}".format(policy_json))


    policy_name = policy["id"]
    res = current_app.arborist.grant_user_policy(username, policy_name)
    if res is None:
        raise ArboristError(
            "Policy {} has not been assigned.".format(
                policy_name
            )
        )

    return jsonify(res)


@blueprint.route("/add_document", methods=["POST"])
@admin_login_required
@debug_log
def add_document():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_document`

    payload:
    `{
        "type": "privacy-policy",
        "version": 2,
        "name": "Privacy Policy",
        "raw": "https://github.com/chicagopcdc/Documents/blob/fda4a7c914173e29d13ab6249ded7bc9adea5674/governance/privacy_policy/privacy_notice.md",
        "formatted": "https://github.com/chicagopcdc/Documents/blob/81d60130308b6961c38097b6686a21f8be729a2c/governance/privacy_policy/PCDC-Privacy-Notice.pdf",
        "required": true
    }`
    """
    document_json = request.get_json()

    if document_json["type"] not in config["DOCUMENT_TYPES"]:
        raise UserError("Type {} not supported. Please talk with the developer team.".format(document_json["type"]))

    # TODO check input is in correct format

    document_schema = DocumentSchema()
    return jsonify(document_schema.dump(admin.add_document(current_session, document_json)))


@blueprint.route("/revoke_permission", methods=["POST"])
@admin_login_required
@debug_log
def revoke_permission():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_document`

    payload:
    `{
        "policy_name": ""
    }`
    """
    # body = request.get_json()

    return jsonify(remove_permission())




#### PROJECTS ####
@blueprint.route("/projects/<projectname>", methods=["GET"])
@admin_login_required
@debug_log
def get_project(projectname):
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    return jsonify(admin.get_project_info(current_session, projectname))


@blueprint.route("/projects", methods=["GET"])
@admin_login_required
@debug_log
def get_all_projects():
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    return jsonify(admin.get_all_projects(current_session))


@blueprint.route("/projects/<projectname>", methods=["POST"])
@admin_login_required
@debug_log
def create_project(projectname):
    """
    Create a new project on the specified storage
    Returns a json object
    """
    auth_id = request.get_json().get("auth_id")
    storage_accesses = request.get_json().get("storage_accesses", [])
    response = jsonify(
        admin.create_project(current_session, projectname, auth_id, storage_accesses)
    )
    return response


@blueprint.route("/projects/<projectname>", methods=["DELETE"])
@admin_login_required
@debug_log
def delete_project(projectname):
    """
    Remove project. No Buckets should be associated with it.
    Returns a json object.
    """
    response = jsonify(admin.delete_project(current_session, projectname))
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["DELETE"])
@admin_login_required
@debug_log
def remove_projects_from_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get("projects", [])
    return jsonify(
        admin.remove_projects_from_group(current_session, groupname, projects)
    )


@blueprint.route("/projects/<projectname>/groups", methods=["PUT"])
@admin_login_required
def add_project_to_groups(projectname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get("groups", [])
    return jsonify(
        admin.add_project_to_groups(current_session, username, groups=groups)
    )


@blueprint.route("/projects/<projectname>/bucket/<bucketname>", methods=["POST"])
@admin_login_required
def create_bucket_in_project(projectname, bucketname):
    """
    Create a bucket in the selected project.
    Returns a json object.
    """
    providername = request.get_json().get("provider")
    response = jsonify(
        admin.create_bucket_on_project(
            current_session, projectname, bucketname, providername
        )
    )
    return response


@blueprint.route("/projects/<projectname>/bucket/<bucketname>", methods=["DELETE"])
@admin_login_required
def delete_bucket_from_project(projectname, bucketname):
    """
    Delete a bucket from the selected project, both
    in the userdatamodel database and in the storage client
    associated with that bucket.
    Returns a json object.
    """
    return jsonify(
        admin.delete_bucket_on_project(current_session, projectname, bucketname)
    )


@blueprint.route("/projects/<projectname>/bucket", methods=["GET"])
@admin_login_required
def list_buckets_from_project(projectname):
    """
    Retrieve the information regarding the buckets created within a project.

    Returns a json object.
    """
    response = jsonify(
        admin.list_buckets_on_project_by_name(current_session, projectname)
    )
    return response


#### GROUPS ####


@blueprint.route("/groups/<groupname>", methods=["GET"])
@admin_login_required
def get_group_info(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(admin.get_group_info(current_session, groupname))


@blueprint.route("/groups", methods=["GET"])
@admin_login_required
def get_all_groups():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(admin.get_all_groups(current_session))


@blueprint.route("/groups/<groupname>/users", methods=["GET"])
@admin_login_required
def get_group_users(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(admin.get_group_users(current_session, groupname))


@blueprint.route("/groups", methods=["POST"])
@admin_login_required
def create_group():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    groupname = request.get_json().get("name")
    description = request.get_json().get("description")
    grp = admin.create_group(current_session, groupname, description)
    if grp:
        response = admin.get_group_info(current_session, groupname)
    else:
        response = {"result": "group creation failed"}
    response = jsonify(response)
    return response


@blueprint.route("/groups/<groupname>", methods=["PUT"])
@admin_login_required
def update_group(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    name = request.get_json().get("name", None)
    description = request.get_json().get("description", None)
    response = jsonify(
        admin.update_group(current_session, groupname, description, name)
    )
    return response


@blueprint.route("/groups/<groupname>", methods=["DELETE"])
@admin_login_required
def delete_group(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    response = jsonify(admin.delete_group(current_session, groupname))
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["PUT"])
@admin_login_required
def add_projects_to_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get("projects", [])
    response = jsonify(
        admin.add_projects_to_group(current_session, groupname, projects)
    )
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["GET"])
@admin_login_required
def get_group_projects(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    values = admin.get_group_projects(current_session, groupname)
    return jsonify({"projects": values})


#### CLOUD PROVIDER ####


@blueprint.route("/cloud_providers/<providername>", methods=["GET"])
@blueprint.route("/cloud_provider/<providername>", methods=["GET"])
@admin_login_required
def get_cloud_provider(providername):
    """
    Retriev the information related to a cloud provider
    Returns a json object.
    """
    return jsonify(admin.get_provider(current_session, providername))


@blueprint.route("/cloud_providers/<providername>", methods=["POST"])
@blueprint.route("/cloud_provider/<providername>", methods=["POST"])
@admin_login_required
def create_cloud_provider(providername):
    """
    Create a cloud provider.
    Returns a json object
    """
    backend_name = request.get_json().get("backend")
    service_name = request.get_json().get("service")
    response = jsonify(
        admin.create_provider(
            current_session, providername, backend=backend_name, service=service_name
        )
    )
    return response


@blueprint.route("/cloud_providers/<providername>", methods=["DELETE"])
@blueprint.route("/cloud_provider/<providername>", methods=["DELETE"])
@admin_login_required
def delete_cloud_provider(providername):
    """
    Deletes a cloud provider from the userdatamodel
    All projects associated with it should be deassociated
    or removed.
    Returns a json object.
    """
    response = jsonify(admin.delete_provider(current_session, providername))
    return response


@blueprint.route("/register", methods=["GET"])
@admin_login_required
def get_registered_users():
    """
    - List registration info for every user for which there exists registration info.
    - Endpoint accessible to admins only.
    - Response json structure is provisional.
    """
    registered_users = (
        current_session.query(User)
        .filter(User.additional_info["registration_info"] != "{}")
        .all()
    )
    registration_info_list = {
        u.username: u.additional_info["registration_info"] for u in registered_users
    }
    return registration_info_list
