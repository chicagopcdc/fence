# Override the default_digest_method for Signer before flask and flask_wtf are loaded. 
import hashlib
from itsdangerous import Signer
# Explicitly set to sha256 as the default (sha1) will break in FIPS environments when flask_wtf attempts to process a user registration form. 
# This is a known issue with itsdangerous defaults (see: https://github.com/pgadmin-org/pgadmin4/issues/7979 for a similar issue with pgadmin)
# According to: https://itsdangerous.palletsprojects.com/en/latest/concepts/#digest-method-security and https://stackoverflow.com/a/27669587, we can override the default here:
Signer.default_digest_method = hashlib.sha256 

from collections import OrderedDict
import os
from urllib.parse import urljoin

from authutils.oauth2.client import OAuthClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
from cdislogging import get_logger
import flask
from flask_cors import CORS
from flask_wtf.csrf import validate_csrf
from gen3authz.client.arborist.client import ArboristClient
from sqlalchemy.orm import scoped_session


# Can't read config yet. Just set to debug for now, else no handlers.
# Later, in app_config(), will actually set level based on config
logger = get_logger(__name__, log_level="debug")

# Load the configuration *before* importing modules that rely on it
from fence.config import config
from fence.settings import CONFIG_SEARCH_FOLDERS

config.load(
    config_path=os.environ.get("FENCE_CONFIG_PATH"),
    search_folders=CONFIG_SEARCH_FOLDERS,
)

from fence.auth import logout, build_redirect_url
from fence.metrics import metrics
from fence.blueprints.data.indexd import S3IndexedFileLocation
from fence.blueprints.login.utils import allowed_login_redirects, domain
from fence.errors import UserError
from fence.jwt import keys
from fence.oidc.client import query_client
from fence.oidc.server import server
from fence.resources.audit.client import AuditServiceClient
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase
from fence.resources.openid.cilogon_oauth2 import CilogonOauth2Client
from fence.resources.openid.cognito_oauth2 import CognitoOauth2Client
from fence.resources.openid.google_oauth2 import GoogleOauth2Client
from fence.resources.openid.microsoft_oauth2 import MicrosoftOauth2Client
from fence.resources.openid.okta_oauth2 import OktaOauth2Client
from fence.resources.openid.orcid_oauth2 import OrcidOauth2Client
from fence.resources.openid.synapse_oauth2 import SynapseOauth2Client
from fence.resources.openid.ras_oauth2 import RASOauth2Client
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.error_handler import get_error_response
from fence.utils import get_SQLAlchemyDriver
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.misc
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.blueprints.link
import fence.blueprints.google
import fence.blueprints.privacy
import fence.blueprints.register
import fence.blueprints.ga4gh
from pcdcutils.signature import SignatureManager
from pcdcutils.errors import KeyPathInvalidError, NoKeyError


app = flask.Flask(__name__)
CORS(app=app, headers=["content-type", "accept"], expose_headers="*")


def warn_about_logger():
    raise Exception(
        "Flask 0.12 will remove and replace all of our log handlers if you call "
        "app.logger anywhere. Use get_logger from cdislogging instead."
    )


def app_init(
    app,
    settings="fence.settings",
    root_dir=None,
    config_path=None,
    config_file_name=None,
):
    app.__dict__["logger"] = warn_about_logger

    app_config(
        app,
        settings=settings,
        root_dir=root_dir,
        config_path=config_path,
        file_name=config_file_name,
    )
    app_sessions(app)
    app_register_blueprints(app)
    server.init_app(app, query_client=query_client)
    logger.info(
        f"Prometheus metrics are{'' if config['ENABLE_PROMETHEUS_METRICS'] else ' NOT'} enabled."
    )


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = get_SQLAlchemyDriver(config["DB"])

    # app.db.Session is from SQLAlchemyDriver and uses
    # SQLAlchemy's sessionmaker. Using scoped_session here ensures
    # a thread-local db session is created. Effectively the below is expanded to:
    #   app.scoped_session = scoped_session(
    #       sessionmaker(
    #            bind=sqlalchemy.create_engine(config["DB"]),
    #            expire_on_commit=False,
    #       )
    #   )
    #
    # From the sqlalchemy docs: "The scoped_session object by default uses
    # [Python's threading.local() construct] as
    # storage, so that a single Session is maintained for all who call upon the
    # scoped_session registry, but only within the scope of a single thread.
    # Callers who call upon the registry in a different thread get a Session
    # instance that is local to that other thread."
    app.scoped_session = scoped_session(app.db.Session)

    app.session_interface = UserSessionInterface()


def app_register_blueprints(app):
    app.register_blueprint(fence.blueprints.oauth2.blueprint, url_prefix="/oauth2")
    app.register_blueprint(fence.blueprints.user.blueprint, url_prefix="/user")

    creds_blueprint = fence.blueprints.storage_creds.make_creds_blueprint()
    app.register_blueprint(creds_blueprint, url_prefix="/credentials")

    app.register_blueprint(fence.blueprints.admin.blueprint, url_prefix="/admin")
    app.register_blueprint(
        fence.blueprints.well_known.blueprint, url_prefix="/.well-known"
    )

    login_blueprint = fence.blueprints.login.make_login_blueprint()
    app.register_blueprint(login_blueprint, url_prefix="/login")

    link_blueprint = fence.blueprints.link.make_link_blueprint()
    app.register_blueprint(link_blueprint, url_prefix="/link")

    google_blueprint = fence.blueprints.google.make_google_blueprint()
    app.register_blueprint(google_blueprint, url_prefix="/google")

    app.register_blueprint(
        fence.blueprints.privacy.blueprint, url_prefix="/privacy-policy"
    )

    app.register_blueprint(fence.blueprints.register.blueprint, url_prefix="/register")
    app.register_blueprint(fence.blueprints.ga4gh.blueprint, url_prefix="/ga4gh")

    fence.blueprints.misc.register_misc(app)

    @app.route("/")
    def root():
        """
        Register the root URL.
        """
        endpoints = {
            "oauth2 endpoint": "/oauth2",
            "user endpoint": "/user",
            "keypair endpoint": "/credentials",
        }
        return flask.jsonify(endpoints)

    @app.route("/logout")
    def logout_endpoint():
        root = config.get("BASE_URL", "")
        request_next = flask.request.args.get("next", root)
        force_era_global_logout = (
            flask.request.args.get("force_era_global_logout") == "true"
        )
        if request_next.startswith("https") or request_next.startswith("http"):
            next_url = request_next
        else:
            next_url = build_redirect_url(config.get("ROOT_URL", ""), request_next)
        if domain(next_url) not in allowed_login_redirects():
            raise UserError("invalid logout redirect URL: {}".format(next_url))
        return logout(
            next_url=next_url, force_era_global_logout=force_era_global_logout
        )

    @app.route("/jwt/keys")
    def public_keys():
        """
        Return the public keys which can be used to verify JWTs signed by fence.

        The return value should look like this:
            {
                "keys": [
                    {
                        "key-01": " ... [public key here] ... "
                    }
                ]
            }
        """
        return flask.jsonify(
            {"keys": [(keypair.kid, keypair.public_key) for keypair in app.keypairs]}
        )

    @app.route("/metrics")
    def metrics_endpoint():
        """
        /!\ There is no authz control on this endpoint!
        In cloud-automation setups, access to this endpoint is blocked at the revproxy level.
        """
        data, content_type = metrics.get_latest_metrics()
        return flask.Response(data, content_type=content_type)


def _check_azure_storage(app):
    """
    Confirm access to Azure Storage Account and Containers
    """
    azure_creds = config.get("AZ_BLOB_CREDENTIALS", None)

    # if this is a public bucket, Fence will not try to sign the URL
    if azure_creds == "*":
        return

    if not azure_creds or azure_creds.strip() == "":
        # Azure Blob credentials are not configured.
        # If you're using Azure Blob Storage set AZ_BLOB_CREDENTIALS to your Azure Blob Storage Connection String.
        logger.debug(
            "Azure Blob credentials are not configured.  If you're using Azure Blob Storage, please set AZ_BLOB_CREDENTIALS to your Azure Blob Storage Connection String."
        )
        return

    blob_service_client = BlobServiceClient.from_connection_string(azure_creds)

    for c in blob_service_client.list_containers():
        container_client = blob_service_client.get_container_client(c.name)

        # check if container exists.  If it doesn't exist, log a warning.
        if container_client.exists() is False:
            logger.debug(
                f"Unable to access Azure Blob Storage Container {c.name}. You may run into issues resolving orphaned indexed files pointing to this container."
            )
            continue

        # verify that you can check the container properties
        try:
            container_properties = container_client.get_container_properties()
            public_access = container_properties["public_access"]
            # check container properties
            logger.debug(
                f"Azure Blob Storage Container {c.name} has public access {public_access}"
            )
        except ResourceNotFoundError as err:
            logger.debug(
                f"Unable to access Azure Blob Storage Container {c.name}. You may run into issues resolving orphaned indexed files pointing to this container."
            )
            logger.debug(err)


def _check_buckets_aws_creds_and_region(app):
    """
    Function to ensure that all s3_buckets have a valid credential.
    Additionally, if there is no region it will produce a warning
    then try to fetch and cache the region.
    """
    buckets = config.get("S3_BUCKETS") or {}
    aws_creds = config.get("AWS_CREDENTIALS") or {}

    # check that AWS creds and regions are configured
    for bucket_name, bucket_details in buckets.items():
        cred = bucket_details.get("cred")
        region = bucket_details.get("region")
        if not cred:
            raise ValueError(
                "No cred for S3_BUCKET: {}. cred is required.".format(bucket_name)
            )

        # if this is a public bucket, Fence will not try to sign the URL
        # so it won't need to know the region.
        if cred == "*":
            continue

        if cred not in aws_creds:
            raise ValueError(
                "Credential {} for S3_BUCKET {} is not defined in AWS_CREDENTIALS".format(
                    cred, bucket_name
                )
            )

        # only require region when we're not specifying an
        # s3-compatible endpoint URL (ex: no need for region when using cleversafe)
        if not region and not bucket_details.get("endpoint_url"):
            logger.warning(
                "WARNING: no region for S3_BUCKET: {}. Providing the region will reduce"
                " response time and avoid a call to GetBucketLocation which you make lack the AWS ACLs for.".format(
                    bucket_name
                )
            )
            credential = S3IndexedFileLocation.get_credential_to_access_bucket(
                bucket_name,
                aws_creds,
                config.get("MAX_PRESIGNED_URL_TTL", 3600),
                app.boto,
            )
            if not getattr(app, "boto"):
                logger.warning(
                    "WARNING: boto not setup for app, probably b/c "
                    "nothing in AWS_CREDENTIALS. Cannot attempt to get bucket "
                    "bucket regions."
                )
                return

            region = app.boto.get_bucket_region(bucket_name, credential)
            config["S3_BUCKETS"][bucket_name]["region"] = region

    cred = config["PUSH_AUDIT_LOGS_CONFIG"].get("aws_sqs_config", {}).get("aws_cred")
    if cred and cred not in aws_creds:
        raise ValueError(
            "Credential {} for PUSH_AUDIT_LOGS_CONFIG.aws_sqs_config.aws_cred is not defined in AWS_CREDENTIALS".format(
                cred
            )
        )

    # check that all the configured buckets are in `S3_BUCKETS`
    bucket_names = config["ALLOWED_DATA_UPLOAD_BUCKETS"] or []
    if config["DATA_UPLOAD_BUCKET"]:
        bucket_names.append(config["DATA_UPLOAD_BUCKET"])
    for bucket_name in bucket_names:
        if bucket_name not in buckets:
            logger.warning(
                f"Data upload bucket '{bucket_name}' is not configured in 'S3_BUCKETS'"
            )


def app_config(
    app,
    settings="fence.settings",
    root_dir=None,
    config_path=None,
    file_name=None,
):
    """
    Set up the config for the Flask app.
    """
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    logger.info("Loading settings...")
    # not using app.config.from_object because we don't want all the extra flask cfg
    # vars inside our singleton when we pass these through in the next step
    settings_cfg = flask.Config(app.config.root_path)
    settings_cfg.from_object(settings)

    # dump the settings into the config singleton before loading a configuration file
    config.update(dict(settings_cfg))

    # load the configuration file, this overwrites anything from settings/local_settings
    config.load(
        config_path=config_path,
        search_folders=CONFIG_SEARCH_FOLDERS,
        file_name=file_name,
    )

    # load all config back into flask app config for now, we should PREFER getting config
    # directly from the fence config singleton in the code though.
    app.config.update(**config._configs)

    _setup_hubspot_key(app)
    _setup_arborist_client(app)
    _setup_audit_service_client(app)
    _setup_data_endpoint_and_boto(app)
    _load_keys(app, root_dir)

    app.storage_manager = StorageManager(config["STORAGE_CREDENTIALS"], logger=logger)

    app.debug = config["DEBUG"]
    # Following will update logger level, propagate, and handlers
    get_logger(__name__, log_level="debug" if config["DEBUG"] is True else "info")

    _setup_oidc_clients(app)

    with app.app_context():
        _check_buckets_aws_creds_and_region(app)
        _check_azure_storage(app)

    # load amanuensis public key for cross-service access
    key_path = config.get("AMANUENSIS_PUBLIC_KEY_PATH", None)
    try:
        config["AMANUENSIS_PUBLIC_KEY"] = SignatureManager(key_path=key_path).get_key()
    except NoKeyError:
        logger.warn('AMANUENSIS_PUBLIC_KEY not found.')
        pass
    except KeyPathInvalidError:
        logger.warn('AMANUENSIS_PUBLIC_KEY_PATH invalid.')
        pass


def _setup_data_endpoint_and_boto(app):
    if "AWS_CREDENTIALS" in config and len(config["AWS_CREDENTIALS"]) > 0:
        creds = config["AWS_CREDENTIALS"]
        buckets = config.get("S3_BUCKETS", {})
        app.boto = BotoManager(creds, buckets, logger=logger)
        app.register_blueprint(fence.blueprints.data.blueprint, url_prefix="/data")


def _load_keys(app, root_dir):
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    app.keypairs = keys.load_keypairs(os.path.join(root_dir, "keys"))

    app.jwt_public_keys = {
        config["BASE_URL"]: OrderedDict(
            [(str(keypair.kid), str(keypair.public_key)) for keypair in app.keypairs]
        )
    }


def _setup_oidc_clients(app):
    configured_idps = config.get("OPENID_CONNECT", {})

    clean_idps = [idp.lower().replace(" ", "") for idp in configured_idps]
    if len(clean_idps) != len(set(clean_idps)):
        raise ValueError(
            f"Some IDPs configured in OPENID_CONNECT are not unique once they are lowercased and spaces are removed: {clean_idps}"
        )

    for idp in set(configured_idps.keys()):
        logger.info(f"Setting up OIDC client for {idp}")
        settings = configured_idps[idp]
        if idp == "google":
            app.google_client = GoogleOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "orcid":
            app.orcid_client = OrcidOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "ras":
            app.ras_client = RASOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "synapse":
            app.synapse_client = SynapseOauth2Client(
                settings, HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
            )
        elif idp == "microsoft":
            app.microsoft_client = MicrosoftOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "okta":
            app.okta_client = OktaOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "cognito":
            app.cognito_client = CognitoOauth2Client(
                settings, HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
            )
        elif idp == "cilogon":
            app.cilogon_client = CilogonOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "fence":
            # https://docs.authlib.org/en/latest/client/flask.html#flask-client
            app.fence_client = OAuthClient(app)
            # https://docs.authlib.org/en/latest/client/frameworks.html
            app.fence_client.register(**settings)
        else:  # generic OIDC implementation
            if hasattr(app, "arborist"):
                app_arborist = app.arborist
            else:
                app_arborist = None
            client = Oauth2ClientBase(
                settings=settings,
                logger=logger,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                idp=settings.get("name") or idp.title(),
                arborist=app_arborist,
            )
            clean_idp = idp.lower().replace(" ", "")
            setattr(app, f"{clean_idp}_client", client)


def _setup_arborist_client(app):
    if app.config.get("ARBORIST"):
        app.arborist = ArboristClient(arborist_base_url=config["ARBORIST"])

def _setup_hubspot_key(app):
    if app.config.get("HUBSPOT"):
        if "API_KEY" in config["HUBSPOT"]:
            app.hubspot_api_key = config["HUBSPOT"]["API_KEY"]
        # else:
            #TODO throw error

def _setup_audit_service_client(app):
    # Initialize the client regardless of whether audit logs are enabled. This
    # allows us to call `app.audit_service_client.create_x_log()` from
    # anywhere without checking if audit logs are enabled. The client
    # checks that for us.
    service_url = app.config.get("AUDIT_SERVICE") or urljoin(
        app.config["BASE_URL"], "/audit"
    )
    app.audit_service_client = AuditServiceClient(
        service_url=service_url, logger=logger
    )


@app.errorhandler(Exception)
def handle_error(error):
    """
    Register an error handler for general exceptions.
    """
    return get_error_response(error)


@app.before_request
def check_csrf():
    has_auth = "Authorization" in flask.request.headers
    no_username = not flask.session.get("username")
    if has_auth or no_username:
        return
    if not config.get("ENABLE_CSRF_PROTECTION", True):
        return
    if flask.request.method != "GET":
        try:
            csrf_header = flask.request.headers.get("x-csrf-token")
            csrf_formfield = flask.request.form.get("csrf_token")
            # validate_csrf checks the input (a signed token) against the raw
            # token stored in session["csrf_token"].
            # (session["csrf_token"] is managed by flask-wtf.)
            # To pass CSRF check, there must exist EITHER an x-csrf-token header
            # OR a csrf_token form field that matches the token in the session.
            assert (
                csrf_header
                and validate_csrf(csrf_header) is None
                or csrf_formfield
                and validate_csrf(csrf_formfield) is None
            )

            referer = flask.request.headers.get("referer")
            assert referer, "Referer header missing"
            logger.debug("HTTP REFERER " + str(referer))
        except Exception as e:
            raise UserError("CSRF verification failed: {}. Request aborted".format(e))


@app.teardown_appcontext
def remove_scoped_session(*args, **kwargs):
    if hasattr(app, "scoped_session"):
        try:
            app.scoped_session.remove()
        except Exception as exc:
            logger.warning(f"could not remove app.scoped_session. Error: {exc}")
