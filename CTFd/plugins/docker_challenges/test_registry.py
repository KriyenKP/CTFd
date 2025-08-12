#!/usr/bin/env python3
"""
Test script for Docker Registry functionality
"""

import requests
import json
import base64

def test_registry_connection(registry_url, username=None, password=None):
    """Test connection to a Docker registry"""
    print(f"Testing connection to: {registry_url}")
    
    headers = {}
    if username and password:
        auth_string = f"{username}:{password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        headers['Authorization'] = f'Basic {auth_b64}'
    
    try:
        # Test catalog endpoint
        catalog_url = f"{registry_url.rstrip('/')}/_catalog"
        print(f"Testing catalog endpoint: {catalog_url}")
        
        response = requests.get(catalog_url, headers=headers, timeout=10)
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            catalog = response.json()
            repositories = catalog.get('repositories', [])
            print(f"Found {len(repositories)} repositories")
            
            # Test first few repositories
            for repo in repositories[:3]:
                tags_url = f"{registry_url.rstrip('/')}/{repo}/tags/list"
                tags_response = requests.get(tags_url, headers=headers, timeout=10)
                
                if tags_response.status_code == 200:
                    tags = tags_response.json().get('tags', [])
                    print(f"  {repo}: {len(tags)} tags")
                    if tags:
                        print(f"    Sample tags: {tags[:3]}")
                else:
                    print(f"  {repo}: Failed to get tags (status: {tags_response.status_code})")
            
            return True
        else:
            print(f"Failed to connect: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Test various registry configurations"""
    print("Docker Registry Connection Test")
    print("=" * 40)
    
    # Test Docker Hub (public)
    print("\n1. Testing Docker Hub (public)")
    success = test_registry_connection("https://registry-1.docker.io/v2/")
    print(f"Result: {'SUCCESS' if success else 'FAILED'}")
    
    # Test with authentication (you would need real credentials)
    print("\n2. Testing with authentication (requires real credentials)")
    print("Skipping - requires real username/password")
    
    # Test invalid registry
    print("\n3. Testing invalid registry")
    success = test_registry_connection("https://invalid-registry.example.com/v2/")
    print(f"Result: {'SUCCESS' if success else 'FAILED'}")
    
    print("\nTest completed!")

if __name__ == "__main__":
    main() 