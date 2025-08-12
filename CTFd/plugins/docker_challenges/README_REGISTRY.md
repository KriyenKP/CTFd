# Docker Challenges Plugin - Registry Support

This plugin has been enhanced to support Docker registries, allowing you to use images from remote registries instead of requiring them to be pre-pulled on your Docker host.

## Features

- **Registry Integration**: Connect to Docker Hub, private registries, or any Docker Registry v2 compatible registry
- **Authentication Support**: Username/password authentication for private registries
- **Automatic Image Pulling**: Images are automatically pulled from the registry when needed
- **Backward Compatibility**: Existing local Docker functionality remains unchanged

## Configuration

### 1. Enable Registry Mode

In the Docker Config page (`/admin/docker_config`):

1. Check the "Use Registry?" checkbox
2. Enter your registry URL (e.g., `https://registry-1.docker.io/v2/` for Docker Hub)
3. Optionally provide username and password for private registries
4. Save the configuration

### 2. Registry URLs

Common registry URLs:
- **Docker Hub**: `https://registry-1.docker.io/v2/`
- **GitHub Container Registry**: `https://ghcr.io/v2/`
- **Google Container Registry**: `https://gcr.io/v2/`
- **Amazon ECR**: `https://[account-id].dkr.ecr.[region].amazonaws.com/v2/`

### 3. Authentication

For private registries, provide:
- **Username**: Your registry username
- **Password**: Your registry password or access token

## Usage

### Creating Challenges

1. Go to the challenge creation page
2. Select "Docker" as the challenge type
3. Choose an image from the dropdown (populated from your registry)
4. Configure other challenge settings
5. Save the challenge

### Container Management

- Containers are automatically created when users start challenges
- Images are pulled from the registry if not available locally
- Containers are automatically cleaned up after use

## Migration

If you have an existing CTFd installation with the docker challenges plugin:

1. Run the migration script:
   ```bash
   python CTFd/plugins/docker_challenges/migration_add_registry_support.py
   ```

2. Restart your CTFd application

3. Configure registry settings in the admin panel

## Troubleshooting

### Common Issues

1. **"Failed to Connect to Registry"**
   - Check your registry URL
   - Verify network connectivity
   - Ensure registry is accessible

2. **Authentication Errors**
   - Verify username/password
   - Check if registry requires authentication
   - For Docker Hub, use access tokens instead of passwords

3. **Image Pull Failures**
   - Verify image exists in registry
   - Check registry permissions
   - Ensure Docker daemon has network access

### Debug Mode

Enable debug logging to see detailed registry API calls:

```python
import logging
logging.getLogger('requests').setLevel(logging.DEBUG)
```

## API Endpoints

The plugin provides several API endpoints:

- `GET /api/v1/docker` - List available images
- `GET /api/v1/container` - Manage containers
- `GET /api/v1/docker_status` - Get container status
- `POST /api/v1/nuke` - Kill containers (admin only)

## Security Considerations

1. **Registry Credentials**: Store registry passwords securely
2. **Network Security**: Ensure registry communication is encrypted
3. **Image Validation**: Consider implementing image scanning
4. **Access Control**: Limit registry access to necessary images only

## Examples

### Docker Hub Configuration
```
Registry URL: https://registry-1.docker.io/v2/
Username: your_username
Password: your_access_token
```

### Private Registry Configuration
```
Registry URL: https://your-registry.company.com/v2/
Username: registry_user
Password: registry_password
```

### GitHub Container Registry
```
Registry URL: https://ghcr.io/v2/
Username: your_github_username
Password: your_github_personal_access_token
``` 