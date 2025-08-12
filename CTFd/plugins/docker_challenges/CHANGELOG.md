# Docker Challenges Plugin - Registry Support Changelog

## Version 2.0.0 - Registry Support

### New Features

- **Docker Registry Integration**: Added support for Docker Registry v2 API
- **Registry Authentication**: Username/password authentication for private registries
- **Automatic Image Pulling**: Images are automatically pulled from registry when needed
- **Backward Compatibility**: Existing local Docker functionality remains unchanged

### Database Changes

- Added `registry_url` column to `docker_config` table
- Added `registry_username` column to `docker_config` table  
- Added `registry_password` column to `docker_config` table
- Added `use_registry` column to `docker_config` table

### New Functions

- `get_registry_auth()`: Generate authentication headers for registry API
- `get_registry_repositories()`: Fetch repositories from Docker Registry API
- `pull_image_from_registry()`: Pull images from registry if not available locally

### Modified Functions

- `get_repositories()`: Now supports both local Docker and registry sources
- `create_container()`: Now pulls images from registry if needed
- `docker_config()`: Added registry configuration handling

### UI Changes

- Added registry configuration section to Docker Config page
- Added "Use Registry?" checkbox
- Added registry URL, username, and password fields
- Added JavaScript to toggle registry fields visibility

### Configuration

New configuration options in Docker Config:
- **Use Registry**: Enable/disable registry mode
- **Registry URL**: URL of the Docker registry (e.g., https://registry-1.docker.io/v2/)
- **Registry Username**: Username for registry authentication
- **Registry Password**: Password for registry authentication

### Migration

Run the migration script to add new database columns:
```bash
python CTFd/plugins/docker_challenges/migration_add_registry_support.py
```

### Supported Registries

- Docker Hub (https://registry-1.docker.io/v2/)
- GitHub Container Registry (https://ghcr.io/v2/)
- Google Container Registry (https://gcr.io/v2/)
- Amazon ECR
- Any Docker Registry v2 compatible registry

### Breaking Changes

None - this is a backward-compatible enhancement.

### Files Added

- `migration_add_registry_support.py`: Database migration script
- `README_REGISTRY.md`: Documentation for registry functionality
- `test_registry.py`: Test script for registry connectivity

### Files Modified

- `__init__.py`: Main plugin file with registry support
- `templates/docker_config.html`: Updated UI for registry configuration 