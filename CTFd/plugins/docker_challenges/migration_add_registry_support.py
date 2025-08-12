"""
Migration script to add registry support to DockerConfig table
"""
from CTFd.plugins.docker_challenges import DockerConfig
from CTFd import db

def upgrade():
    """Add registry fields to DockerConfig table"""
    # Add new columns to DockerConfig table
    with db.engine.begin() as conn:
        # Add registry_url column
        conn.execute("""
            ALTER TABLE docker_config 
            ADD COLUMN registry_url VARCHAR(256)
        """)
        
        # Add registry_username column
        conn.execute("""
            ALTER TABLE docker_config 
            ADD COLUMN registry_username VARCHAR(128)
        """)
        
        # Add registry_password column
        conn.execute("""
            ALTER TABLE docker_config 
            ADD COLUMN registry_password VARCHAR(256)
        """)
        
        # Add use_registry column
        conn.execute("""
            ALTER TABLE docker_config 
            ADD COLUMN use_registry BOOLEAN DEFAULT FALSE
        """)

def downgrade():
    """Remove registry fields from DockerConfig table"""
    with db.engine.begin() as conn:
        # Remove registry columns
        conn.execute("""
            ALTER TABLE docker_config 
            DROP COLUMN IF EXISTS registry_url
        """)
        
        conn.execute("""
            ALTER TABLE docker_config 
            DROP COLUMN IF EXISTS registry_username
        """)
        
        conn.execute("""
            ALTER TABLE docker_config 
            DROP COLUMN IF EXISTS registry_password
        """)
        
        conn.execute("""
            ALTER TABLE docker_config 
            DROP COLUMN IF EXISTS use_registry
        """)

if __name__ == "__main__":
    print("Adding registry support to DockerConfig table...")
    upgrade()
    print("Migration completed successfully!") 