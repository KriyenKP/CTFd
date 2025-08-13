import base64
import traceback

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import db, ma, Challenges, Teams, Users, Solves, Fails, Flags, Files, Hints, Tags, ChallengeFiles
from CTFd.utils.decorators import admins_only, authed_only, during_ctf_time_only, require_verified_emails
from CTFd.utils.decorators.visibility import check_challenge_visibility, check_score_visibility
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
# from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    TextAreaField,
    SelectMultipleField,
    BooleanField,
)
# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
import requests
import tempfile
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random
from CTFd.plugins import register_admin_plugin_menu_bar

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.utils.config import get_themes

from pathlib import Path


class DockerConfig(db.Model):
    """
	Docker Config Model. This model stores the config for docker API connections.
	"""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column("hostname", db.String(64), index=True)
    hostedDomain = db.Column("hostedDomain", db.String(64), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    repositories = db.Column("repositories", db.String(1024), index=True)
    registry_url = db.Column("registry_url", db.String(256), index=True)
    registry_username = db.Column("registry_username", db.String(128), index=True)
    registry_password = db.Column("registry_password", db.String(256), index=True)
    use_registry = db.Column("use_registry", db.Boolean, default=False, index=True)


class DockerChallengeTracker(db.Model):
    """
	Docker Container Tracker. This model stores the users/teams active docker containers.
	"""
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column('ports', db.String(128), index=True)
    host = db.Column('host', db.String(128), index=True)
    challenge = db.Column('challenge', db.String(256), index=True)

class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname", description="The Hostname/IP and Port of your Docker Server"
    )
    hostedDomain = StringField(
        "Hosted Domain", description="The Hostname/IP of your hosted domain"
    )
    tls_enabled = RadioField('TLS Enabled?')
    ca_cert = FileField('CA Cert')
    client_cert = FileField('Client Cert')
    client_key = FileField('Client Key')
    repositories = SelectMultipleField('Repositories')
    use_registry = BooleanField('Use Registry?')
    registry_url = StringField('Registry URL', description="Registry URL (e.g., https://registry-1.docker.io/v2/)")
    registry_username = StringField('Registry Username')
    registry_password = PasswordField('Registry Password')
    submit = SubmitField('Submit')


def define_docker_admin(app):
    admin_docker_config = Blueprint('admin_docker_config', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_config.route("/admin/docker_config", methods=["GET", "POST"])
    @admins_only
    def docker_config():
        docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerConfigForm()
        if request.method == "POST":
            if docker:
                b = docker
            else:
                b = DockerConfig()
            # Handle file uploads - only try to read if files are actually uploaded
            ca_cert = ''
            client_cert = ''
            client_key = ''
            
            if 'ca_cert' in request.files and request.files['ca_cert'].filename:
                try:
                    ca_cert = request.files['ca_cert'].stream.read()
                except Exception as e:
                    print(f"Error reading ca_cert: {e}")
                    ca_cert = ''
                    
            if 'client_cert' in request.files and request.files['client_cert'].filename:
                try:
                    client_cert = request.files['client_cert'].stream.read()
                except Exception as e:
                    print(f"Error reading client_cert: {e}")
                    client_cert = ''
                    
            if 'client_key' in request.files and request.files['client_key'].filename:
                try:
                    client_key = request.files['client_key'].stream.read()
                except Exception as e:
                    print(f"Error reading client_key: {e}")
                    client_key = ''
            if len(ca_cert) != 0: b.ca_cert = ca_cert
            if len(client_cert) != 0: b.client_cert = client_cert
            if len(client_key) != 0: b.client_key = client_key
            b.hostname = request.form['hostname']
            b.hostedDomain = request.form['hostedDomain']
            b.tls_enabled = request.form['tls_enabled']
            if b.tls_enabled == "True":
                b.tls_enabled = True
            else:
                b.tls_enabled = False
            if not b.tls_enabled:
                b.ca_cert = None
                b.client_cert = None
                b.client_key = None
            
            # Handle registry configuration
            b.use_registry = 'use_registry' in request.form
            b.registry_url = request.form.get('registry_url', '')
            b.registry_username = request.form.get('registry_username', '')
            b.registry_password = request.form.get('registry_password', '')
            
            # Handle repositories - only needed when not using registry
            if b.use_registry:
                try:
                    # Fetch repositories from the registry
                    headers = {
                        "Authorization": f"Basic {base64.b64encode(f'{b.registry_username}:{b.registry_password}'.encode()).decode()}"
                    }
                    registry_url = b.registry_url.rstrip('/') + '/v2/_catalog'
                    response = requests.get(registry_url, headers=headers, timeout=10)

                    if response.status_code == 200:
                        catalog = response.json().get('repositories', [])
                        b.repositories = ','.join(catalog) if catalog else None
                    else:
                        print(f"Failed to fetch repositories: {response.status_code} {response.text}")
                        b.repositories = None
                except Exception as e:
                    print(f"Error fetching repositories: {e}")
                    b.repositories = None
            else:
                try:
                    # Check both 'repositories' and 'registry-repositories' fields
                    repositories = request.form.to_dict(flat=False).get('repositories', []) or \
                                request.form.to_dict(flat=False).get('registry-repositories', [])
                    if repositories and repositories != ['']:
                        b.repositories = ','.join(repositories)
                    else:
                        b.repositories = None
                except Exception as e:
                    print(f"Error handling repositories: {e}")
                    b.repositories = None
            db.session.add(b)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()
        try:
            repos = get_repositories(docker)
        except Exception as e:
            print(f"Error getting repositories: {e}")
            repos = list()
        if len(repos) == 0:
            if docker.use_registry:
                form.repositories.choices = [("ERROR", "Failed to Connect to Registry")]
            else:
                form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
        else:
            form.repositories.choices = [(d, d) for d in repos]
        dconfig = DockerConfig.query.first()
        try:
            if dconfig and dconfig.repositories:
                selected_repos = dconfig.repositories.split(',') if dconfig.repositories else []
            else:
                selected_repos = []
        except Exception as e:
            print(f"Error handling selected repositories: {e}")
            selected_repos = []
        return render_template("docker_config.html", config=dconfig, form=form, repos=selected_repos)

    app.register_blueprint(admin_docker_config)


def define_docker_status(app):
    admin_docker_status = Blueprint('admin_docker_status', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_status.route("/admin/docker_status", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        for i in docker_tracker:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.team_id).first()
                i.team_id = name.name
            else:
                name = Users.query.filter_by(id=i.user_id).first()
                i.user_id = name.name
        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


kill_container = Namespace("nuke", description='Endpoint to nuke containers')


@kill_container.route("", methods=['POST', 'GET'])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get('container')
        full = request.args.get('all')
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                delete_container(docker_config, c.instance_id)
                DockerChallengeTracker.query.filter_by(instance_id=c.instance_id).delete()
                db.session.commit()

        elif container != 'null' and container in [c.instance_id for c in docker_tracker]:
            delete_container(docker_config, container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True


def do_request(docker, url, headers=None, method='GET'):
    if not docker or not docker.hostname:
        print("Docker configuration is missing or invalid")
        return None
        
    tls = docker.tls_enabled
    prefix = 'https' if tls else 'http'
    host = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, host)
    
    try:
        if tls:
            cert, verify = get_client_cert(docker)
            if (method == 'GET'):
                r = requests.get(url=f"%s{url}" % URL_TEMPLATE, cert=cert, verify=verify, headers=headers, timeout=10)
            elif (method == 'DELETE'):
                r = requests.delete(url=f"%s{url}" % URL_TEMPLATE, cert=cert, verify=verify, headers=headers, timeout=10)
            # Clean up the cert files:
            for file_path in [*cert, verify]:
                if file_path:
                    Path(file_path).unlink(missing_ok=True)
        else:
            if (method == 'GET'):
                r = requests.get(url=f"%s{url}" % URL_TEMPLATE, headers=headers, timeout=10)
            elif (method == 'DELETE'):
                r = requests.delete(url=f"%s{url}" % URL_TEMPLATE, headers=headers, timeout=10)
    except Exception as e:
        print(f"Error in do_request: {e}")
        return None
    return r


def get_client_cert(docker):
    # this can be done more efficiently, but works for now.
    try:
        ca = docker.ca_cert
        client = docker.client_cert
        ckey = docker.client_key
        
        if not ca or not client or not ckey:
            print("Missing certificate files for TLS connection")
            return None, None
            
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        ca_file.write(ca.encode())
        ca_file.seek(0)
        client_file = tempfile.NamedTemporaryFile(delete=False)
        client_file.write(client.encode())
        client_file.seek(0)
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(ckey.encode())
        key_file.seek(0)
        CERT = (client_file.name, key_file.name)
    except Exception as e:
        print(f"Error in get_client_cert: {e}")
        CERT = None
        ca_file = None
    return CERT, ca_file.name if ca_file else None


def get_registry_auth(docker):
    """Get authentication headers for registry API calls"""
    if docker.use_registry and docker.registry_username and docker.registry_password:
        import base64
        auth_string = f"{docker.registry_username}:{docker.registry_password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        return {'Authorization': f'Basic {auth_b64}'}
    return {}

def get_registry_repositories(docker, tags=False, repos=False):
    """Get repositories from Docker Registry API"""
    if not docker or not docker.use_registry or not docker.registry_url:
        return []
    
    try:
        # Get catalog of repositories
        headers = get_registry_auth(docker)
        
        # Ensure registry URL has proper scheme
        registry_url = docker.registry_url.strip()
        if not registry_url.startswith(('http://', 'https://')):
            registry_url = f"https://{registry_url}"
        
        catalog_url = f"{registry_url.rstrip('/')}/"

        print(f"Registry catalog request {catalog_url}")

        r = requests.get(catalog_url, headers=headers, timeout=10)
        
        if r.status_code != 200:
            print(f"Registry catalog request failed with status {r.status_code}")
            return []
        
        result = []
        catalog = r.json().get('repositories', [])
        
        for repo in catalog:
            if repos and repo not in repos:
                continue
                
            # Get tags for this repository
            tags_url = f"{registry_url.rstrip('/')}/{repo}/tags/list"
            tags_r = requests.get(tags_url, headers=headers, timeout=10)
            
            if tags_r.status_code == 200:
                tag_list = tags_r.json().get('tags', [])
                for tag in tag_list:
                    if tags:
                        result.append(f"{repo}:{tag}")
                    else:
                        result.append(repo)
                        break  # Only add repository name once
            else:
                # If we can't get tags, just add the repo name
                if not tags:
                    result.append(repo)
        
        return list(set(result))
    except Exception as e:
        print(f"Error getting registry repositories: {e}")
        return []

import requests
from requests.auth import HTTPBasicAuth

def get_ghcr_repositories(github_username, github_pat, include_tags=False, filter_repos=None):
    """
    Get GHCR repositories for a user via GitHub REST API.
    
    Args:
        github_username: GitHub username (owner of the GHCR images)
        github_pat: GitHub Personal Access Token with `read:packages`
        include_tags: If True, includes image:tag in the result
        filter_repos: Optional list of repo names to include (e.g., ["ctf", "ctf_decoder"])

    Returns:
        List of images or image:tag strings.
    """
    base_url = "https://api.github.com"
    headers = {"Accept": "application/vnd.github+json"}
    auth = HTTPBasicAuth(github_username, github_pat)

    result = []

    try:
        # Get all container packages under the user
        pkg_url = f"{base_url}/users/{github_username}/packages?package_type=container"
        response = requests.get(pkg_url, headers=headers, auth=auth, timeout=10)

        if response.status_code != 200:
            print(f"[!] Failed to fetch packages: {response.status_code} - {response.text}")
            return []

        packages = response.json()

        for pkg in packages:
            name = pkg["name"]

            if filter_repos and name not in filter_repos:
                continue

            # Always use full registry path for GHCR images (lowercase for Docker compatibility)
            full_image_name = f"ghcr.io/{github_username.lower()}/{name}"
            print(f"[+] Found package: {full_image_name}")
            
            # If include_tags is False, just add the full image name
            if not include_tags:
                result.append(full_image_name)

            if include_tags:
                # Fetch versions (i.e., tags) of this package
                versions_url = f"{base_url}/users/{github_username}/packages/container/{name}/versions"
                tags_resp = requests.get(versions_url, headers=headers, auth=auth, timeout=10)

                if tags_resp.status_code == 200:
                    versions = tags_resp.json()
                    for version in versions:
                        # Some versions may not have metadata.tags
                        tags = version.get("metadata", {}).get("container", {}).get("tags", [])
                        for tag in tags:
                            result.append(f"{full_image_name}:{tag}")
                else:
                    print(f"[-] Could not fetch tags for {name}: {tags_resp.status_code}")
                    # If we can't get tags, add the image with latest tag
                    result.append(f"{full_image_name}:latest")

        return list(set(result))

    except Exception as e:
        print(f"[!] Error fetching GHCR repos: {e}")
        return []



# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, tags=False, repos=False):
    if not docker:
        return []
        
    if docker.use_registry:

        if 'ghcr.io' in docker.registry_url:
            # If using GitHub Container Registry, use the specific function
            return get_ghcr_repositories(docker.registry_username, docker.registry_password, tags, repos)
        else:
            return get_registry_repositories(docker, tags, repos)

    try:
        r = do_request(docker, '/images/json?all=1')
        if not r or not hasattr(r, 'json'):
            return []
            
        result = list()
        for i in r.json():
            if not i['RepoTags'] == []:
                if not i['RepoTags'][0].split(':')[0] == '<none>':
                    if repos:
                        if not i['RepoTags'][0].split(':')[0] in repos:
                            continue
                    if not tags:
                        result.append(i['RepoTags'][0].split(':')[0])
                    else:
                        result.append(i['RepoTags'][0])
        return list(set(result))
    except Exception as e:
        print(f"Error in get_repositories: {e}")
        return []


def get_unavailable_ports(docker):
    r = do_request(docker, '/containers/json?all=1')
    result = []
    for i in r.json():
        for p in i.get('Ports', []):
            public_port = p.get('PublicPort')
            if public_port is not None:
                result.append(public_port)
    return result



def get_required_ports(docker, image):
    r = do_request(docker, f'/images/{image}/json?all=1')
    result = r.json()['Config']['ExposedPorts'].keys()
    return result


def pull_image_from_registry(docker, image):
    """Pull image from registry if it doesn't exist locally"""
    if not docker.use_registry:
        return True

    # Check if image exists locally first
    r = do_request(docker, f'/images/{image}/json')
    if r and r.status_code == 200:
        return True

    try:
        headers = {'Content-Type': "application/json"}

        # Docker Engine requires base64-encoded JSON for X-Registry-Auth
        auth_payload = {
            "username": docker.registry_username or "",
            "password": docker.registry_password or "",
            "serveraddress": docker.registry_url or "ghcr.io",  # fallback for GHCR
            "email": "none@example.com"
        }
        import base64, json
        encoded_auth = base64.b64encode(json.dumps(auth_payload).encode('utf-8')).decode('utf-8')
        headers['X-Registry-Auth'] = encoded_auth

        tls = docker.tls_enabled
        prefix = 'https' if tls else 'http'
        host = docker.hostname
        URL_TEMPLATE = f'{prefix}://{host}'

        # Separate image name and tag (if any)
        if ':' in image:
            from_image, tag = image.split(':', 1)
            pull_url = f"{URL_TEMPLATE}/images/create?fromImage={from_image}&tag={tag}"
        else:
            pull_url = f"{URL_TEMPLATE}/images/create?fromImage={image}"

        if tls:
            cert, verify = get_client_cert(docker)
            r = requests.post(url=pull_url, cert=cert, verify=verify, headers=headers, timeout=20)
            for file_path in [*cert, verify]:
                if file_path:
                    Path(file_path).unlink(missing_ok=True)
        else:
            r = requests.post(url=pull_url, headers=headers, timeout=20)

        if r.status_code in [200, 201]:
            return True
        print(f"Failed to pull image: {r.status_code} - {r.text}")
        return False

    except Exception as e:
        print(f"Error pulling image {image}: {e}")
        return False

def create_container(docker, image, team, portbl):
    # Pull image from registry if needed
    if not pull_image_from_registry(docker, image):
        raise Exception(f"Failed to pull image {image} from registry")
    
    tls = docker.tls_enabled
    CERT = None
    if not tls:
        prefix = 'http'
    else:
        prefix = 'https'
    host = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, host)
    needed_ports = get_required_ports(docker, image)
    team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    # Create container name from image name (replace special chars with underscores)
    image_name = image.split(':')[0].replace('/', '_').replace('-', '_')
    container_name = "%s_%s" % (image_name, team)
    assigned_ports = dict()
    for i in needed_ports:
        while True:
            assigned_port = random.choice(range(30000, 30300))
            if assigned_port not in portbl:
                # Store only the numeric host port; protocol belongs to the container port side (key `i`)
                assigned_ports[str(assigned_port)] = {}
                break
    ports = dict()
    bindings = dict()
    tmp_ports = list(assigned_ports.keys())
    for i in needed_ports:
        ports[i] = {}
        # Use only the numeric host port value
        bindings[i] = [{"HostPort": tmp_ports.pop()}]
    headers = {'Content-Type': "application/json"}
    data = json.dumps({"Image": image, "ExposedPorts": ports, "HostConfig": {"PortBindings": bindings}})

    def delete_by_name():
        try:
            if tls:
                cert2, verify2 = get_client_cert(docker)
                requests.delete(url=f"{URL_TEMPLATE}/containers/{container_name}?force=true", cert=cert2, verify=verify2, headers=headers, timeout=10)
                for file_path in [*cert2, verify2]:
                    if file_path:
                        Path(file_path).unlink(missing_ok=True)
            else:
                requests.delete(url=f"{URL_TEMPLATE}/containers/{container_name}?force=true", headers=headers, timeout=10)
        except Exception as _e:
            pass

    if tls:
        cert, verify = get_client_cert(docker)
        try:
            r = requests.post(url=f"{URL_TEMPLATE}/containers/create?name={container_name}", cert=cert, verify=verify, data=data, headers=headers)
            if r.status_code == 409:
                # Conflict: container name already exists. Delete and retry once.
                delete_by_name()
                r = requests.post(url=f"{URL_TEMPLATE}/containers/create?name={container_name}", cert=cert, verify=verify, data=data, headers=headers)
            result = r.json()
            requests.post(url=f"{URL_TEMPLATE}/containers/{result['Id']}/start", cert=cert, verify=verify, headers=headers)
        finally:
            for file_path in [*cert, verify]:
                if file_path:
                    Path(file_path).unlink(missing_ok=True)
    else:
        r = requests.post(url=f"{URL_TEMPLATE}/containers/create?name={container_name}", data=data, headers=headers)
        if r.status_code == 409:
            delete_by_name()
            r = requests.post(url=f"{URL_TEMPLATE}/containers/create?name={container_name}", data=data, headers=headers)
        result = r.json()
        requests.post(url=f"{URL_TEMPLATE}/containers/{result['Id']}/start", headers=headers)

    return result, data


def delete_container(docker, instance_id):
    headers = {'Content-Type': "application/json"}
    do_request(docker, f'/containers/{instance_id}?force=true', headers=headers, method='DELETE')
    return True


class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        'create': '/plugins/docker_challenges/assets/create.html',
        'update': '/plugins/docker_challenges/assets/update.html',
        'view': '/plugins/docker_challenges/assets/view.html',
    }
    scripts = {
        'create': '/plugins/docker_challenges/assets/create.js',
        'update': '/plugins/docker_challenges/assets/update.js',
        'view': '/plugins/docker_challenges/assets/view.js',
    }
    route = '/plugins/docker_challenges/assets'
    blueprint = Blueprint('docker_challenges', __name__, template_folder='templates', static_folder='assets')

    @staticmethod
    def update(challenge, request):
        """
		This method is used to update the information associated with a challenge. This should be kept strictly to the
		Challenges table and any child tables.

		:param challenge:
		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        for attr, value in data.items():
            setattr(challenge, attr, value)

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
		This method is used to delete the resources used by a challenge.
		NOTE: Will need to kill all containers here

		:param challenge:
		:return:
		"""
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
        ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
        Tags.query.filter_by(challenge_id=challenge.id).delete()
        Hints.query.filter_by(challenge_id=challenge.id).delete()
        DockerChallenge.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
		This method is in used to access the data of a challenge in a format processable by the front end.

		:param challenge:
		:return: Challenge object, data dictionary to be returned to the user
		"""
        challenge = DockerChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'docker_image': challenge.docker_image,
            'connection_type': challenge.connection_type or 'auto',
            'description': challenge.description,
            'category': challenge.category,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': DockerChallengeType.id,
                'name': DockerChallengeType.name,
                'templates': DockerChallengeType.templates,
                'scripts': DockerChallengeType.scripts,
            }
        }
        return data

    @staticmethod
    def create(request):
        """
		This method is used to process the challenge creation request.

		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        challenge = DockerChallenge(**data)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        """
		This method is used to check whether a given input is right or wrong. It does not make any changes and should
		return a boolean for correctness and a string to be shown to the user. It is also in charge of parsing the
		user's input from the request itself.

		:param challenge: The Challenge object from the database
		:param request: The request the user submitted
		:return: (boolean, string)
		"""

        data = request.form or request.get_json()
        print(request.get_json())
        print(data)
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
                return True, "Correct"
        return False, "Incorrect"

    @staticmethod
    def solve(user, team, challenge, request):
        """
		This method is used to insert Solves into the database in order to mark a challenge as solved.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        docker = DockerConfig.query.filter_by(id=1).first()
        try:
            if is_teams_mode():
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(team_id=team.id).first()
            else:
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(user_id=user.id).first()
            delete_container(docker, docker_containers.instance_id)
            DockerChallengeTracker.query.filter_by(instance_id=docker_containers.instance_id).delete()
        except:
            pass
        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission,
        )
        db.session.add(solve)
        db.session.commit()
        # trying if this solces the detached instance error...
        #db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        """
		This method is used to insert Fails into the database in order to mark an answer incorrect.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission,
        )
        db.session.add(wrong)
        db.session.commit()
        #db.session.close()


class DockerChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'docker'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)
    connection_type = db.Column(db.String(20), default='auto', index=True)


# API
container_namespace = Namespace("container", description='Endpoint to interact with containers')


@container_namespace.route("", methods=['POST', 'GET'])
class ContainerAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        container = request.args.get('name')
        if not container:
            return abort(403, "No container specified")

        challenge = request.args.get('challenge')

        if not challenge:
            return abort(403, "No challenge name specified")

        docker = DockerConfig.query.filter_by(id=1).first()
        containers = DockerChallengeTracker.query.all()
        available_repos = get_repositories(docker, tags=False)

        # Resolve container name against available repositories (support short name matching)
        container_found = False
        if container in available_repos:
            container_found = True
        else:
            for repo in available_repos:
                if repo.endswith('/' + container) or repo.split('/')[-1] == container.split('/')[-1]:
                    container_found = True
                    container = repo
                    break

        if not container_found:
            if docker.use_registry:
                return abort(403, f"Container {container} not present in the registry.")
            else:
                return abort(403, f"Container {container} not present in the repository.")

        # Determine current session (team or user)
        if is_teams_mode():
            current_session = get_current_team()
        else:
            current_session = get_current_user()

        # Delete old containers for this session (> 2 hours)
        for i in containers:
            is_owner = (int(current_session.id) == int(i.team_id)) if is_teams_mode() else (int(current_session.id) == int(i.user_id))
            if is_owner and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                delete_container(docker, i.instance_id)
                DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                db.session.commit()

        # Find an existing container for this session and image
        if is_teams_mode():
            check = DockerChallengeTracker.query.filter_by(team_id=current_session.id, docker_image=container).first()
        else:
            check = DockerChallengeTracker.query.filter_by(user_id=current_session.id, docker_image=container).first()

        # Enforce 5 minute cooldown / stopping logic
        if check is not None and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 300:
            return abort(403, "To prevent abuse, dockers can be reverted and stopped after 5 minutes of creation.")
        elif check is not None and request.args.get('stopcontainer'):
            delete_container(docker, check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=current_session.id, docker_image=container).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=current_session.id, docker_image=container).delete()
            db.session.commit()
            return {"result": "Container stopped"}
        elif check is not None:
            delete_container(docker, check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=current_session.id, docker_image=container).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=current_session.id, docker_image=container).delete()
            db.session.commit()

        # Ensure only one container is running for this session
        containers = DockerChallengeTracker.query.all()
        for i in containers:
            is_owner = (int(current_session.id) == int(i.team_id)) if is_teams_mode() else (int(current_session.id) == int(i.user_id))
            if is_owner:
                return abort(403, f"Another container is already running for challenge:<br><i><b>{i.challenge}</b></i>.<br>Please stop this first.<br>You can only run one container.")

        # Create container
        portsbl = get_unavailable_ports(docker)
        create = create_container(docker, container, current_session.name, portsbl)
        ports = json.loads(create[1])['HostConfig']['PortBindings'].values()
        port_list = [p[0]['HostPort'] for p in ports]
        entry = DockerChallengeTracker(
            team_id=current_session.id if is_teams_mode() else None,
            user_id=current_session.id if not is_teams_mode() else None,
            docker_image=container,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=create[0]['Id'],
            ports=','.join(port_list),
            host=str(docker.hostedDomain),
            #host=str(docker.hostname).split(':')[0],
            #host=f"{port_list[0]}.kriyenkp.duckdns.org",
            challenge=challenge
        )
        db.session.add(entry)
        db.session.commit()
        return


active_docker_namespace = Namespace("docker", description='Endpoint to retrieve User Docker Image Status')


@active_docker_namespace.route("", methods=['POST', 'GET'])
class DockerStatus(Resource):
    """
	The Purpose of this API is to retrieve a public JSON string of all docker containers
	in use by the current team/user.
	"""

    @authed_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()

        if is_teams_mode():
            session = get_current_team()
            tracker = DockerChallengeTracker.query.filter_by(team_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(user_id=session.id)
        data = list()
        for i in tracker:
            data.append({
                'id': i.id,
                'team_id': i.team_id,
                'user_id': i.user_id,
                'docker_image': i.docker_image,
                'timestamp': i.timestamp,
                'revert_time': i.revert_time,
                'instance_id': i.instance_id,
                'ports': i.ports.split(','),
                'host': i.host
            })

        return {
            'success': True,
            'data': data
        }


docker_namespace = Namespace("docker", description='Endpoint to retrieve dockerstuff')


@docker_namespace.route("", methods=['POST', 'GET'])
class DockerAPI(Resource):
    """
	This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
	object in the Challenge Creation Screen.
	"""

    @admins_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        
        if docker.use_registry:
            # When using registry, get all available images without filtering by repositories
            images = get_repositories(docker, tags=False, repos=None)
        else:
            # When using Docker API directly, filter by selected repositories
            images = get_repositories(docker, tags=True, repos=docker.repositories)
    
        if images:
            print(f"Available images: {images}")
            data = list()
            for i in images:
                data.append({'name': i})
            return {
                'success': True,
                'data': data
            }
        else:
            error_msg = 'Error in Registry Config!' if docker.use_registry else 'Error in Docker Config!'
            return {
                       'success': False,
                       'data': [
                           {
                               'name': error_msg
                           }
                       ]
                   }, 400



def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES['docker'] = DockerChallengeType
    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
        return datetime.fromtimestamp(value).strftime(format)
    register_plugin_assets_directory(app, base_path='/plugins/docker_challenges/assets')
    define_docker_admin(app)
    define_docker_status(app)
    CTFd_API_v1.add_namespace(docker_namespace, '/docker')
    CTFd_API_v1.add_namespace(container_namespace, '/container')
    CTFd_API_v1.add_namespace(active_docker_namespace, '/docker_status')
    CTFd_API_v1.add_namespace(kill_container, '/nuke')
