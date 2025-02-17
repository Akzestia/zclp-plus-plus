-- Root Cql Script
-- Defines key spaces and replication strategies
-- References https://docs.scylladb.com/stable/


CREATE KEYSPACE IF NOT EXISTS user_data
    WITH replication = {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        }
     AND durable_writes = true;

CREATE KEYSPACE IF NOT EXISTS temp_storage_data
    WITH replication = {
        'class': 'SimpleStrategy',
        'replication_factor': 1
        }
     AND durable_writes = true;

