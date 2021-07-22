import os
import psycopg2
import boto3
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import random
from string import digits, ascii_uppercase
import logging
import json

RDS_HOST = os.environ.get('RDS_HOST')
RDS_PORT = os.environ.get('RDS_PORT')
RDS_USER = os.environ.get('RDS_USER')
RDS_TOKEN = os.environ.get('RDS_TOKEN')
RDS_DATABASE = os.environ.get('RDS_DATABASE')
REGION = os.environ.get('REGION')
DBNAME = "postgres"

legals = digits + ascii_uppercase
ssm = boto3.client('ssm', region_name=REGION)

masterpass = '/rds/' + RDS_DATABASE + '/RDS_MASTERPASS'
response = ssm.get_parameter(Name=masterpass, WithDecryption=True)
db_password = response['Parameter']['Value']

rds = boto3.client('rds', region_name=REGION)
token = rds.generate_db_auth_token(DBHostname=RDS_HOST, Port=RDS_PORT, DBUsername=RDS_USER, Region=REGION)

tags = ssm.list_tags_for_resource(ResourceType='Parameter', ResourceId=masterpass)
for tag in tags['TagList']:
    if tag['Key'] == 'UPDATED' and tag['Value'] == 'True':
        try:
            conn = psycopg2.connect(host=RDS_HOST, port=RDS_PORT, database=DBNAME, user=RDS_USER, password=db_password,
                                    sslmode='require')
            cur = conn.cursor()
            cur.execute("""SELECT now()""")
            # -----------------------RDS_IAM to MASTER USER---------------------
            cur.execute(f"GRANT rds_iam TO {RDS_USER}");

            query_results = cur.fetchall()
            print(query_results)
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        except Exception as e:
            print("Database connection failed due to {}".format(e))

    else:
        print("LOGIN WITH TOKEN")


try:
    conn = psycopg2.connect(host=RDS_HOST, port=RDS_PORT, database=DBNAME, user=RDS_USER, password=token,
                            sslmode='require')
    cur = conn.cursor()
    cur.execute("""SELECT now()""")

    query_results = cur.fetchall()
    print(query_results)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
except Exception as e:
    print("Database connection failed due to {}".format(e))


def lambda_handler(event, context):
    data = json.dumps(event)
    config = json.loads(data)
    for t in config:
        customer_db = t['Database']
        rw_role = "rw_role_" + customer_db
        ro_role = "ro_role_" + customer_db
        migrator_role = "migrator_role_" + customer_db
        cur.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = \'{customer_db}\'")
        row = cur.fetchone()
        print(row)

        if row == None:
            sqlCreateDatabase = f"Create database {customer_db} ";
            cur.execute(sqlCreateDatabase)
            print(f"DATABASE {customer_db} CREATED")
        else:
            print(f"DATABASE {customer_db} EXIST")

        # SCHEMA STUFF
        print("CREATING SCHEMA IF NOT EXISTS")
        sqlCreateSchema = f"CREATE SCHEMA IF NOT EXISTS {customer_db}";
        cur.execute(sqlCreateSchema);

        cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
        cur.execute(f"REVOKE ALL ON DATABASE {customer_db} FROM PUBLIC");
        cur.execute(f"REVOKE ALL ON DATABASE {customer_db} FROM PUBLIC");

        # -----------------------RDS_IAM to MASTER USER---------------------
        cur.execute(f"GRANT rds_iam TO {RDS_USER}");

        # -----------------------RW ROLE------------------------------------

        cur.execute(f"SELECT rolname FROM pg_roles where rolname =\'{rw_role}\'");
        exist = cur.fetchone()

        if exist == None:
            cur.execute(f"CREATE ROLE {rw_role}");
            cur.execute(f"GRANT CONNECT ON DATABASE {customer_db} TO {rw_role}");
            cur.execute(
                f"ALTER DEFAULT PRIVILEGES IN SCHEMA {customer_db} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {rw_role}");
            cur.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA {customer_db} TO {rw_role}");
            cur.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {customer_db} GRANT USAGE ON SEQUENCES TO {rw_role}");
            cur.execute(f"GRANT USAGE, CREATE ON SCHEMA {customer_db} TO {rw_role}");
            cur.execute(f"GRANT SELECT, INSERT , UPDATE, DELETE ON ALL TABLES IN SCHEMA {customer_db} TO {rw_role}");
            print(f"ROLE {rw_role} CREATED [OK]")

        # -----------------------MIGRATOR ROLE------------------------------------
        cur.execute(f"SELECT rolname FROM pg_roles where rolname =\'{migrator_role}\'");
        exist = cur.fetchone()

        if exist == None:
            cur.execute(f"create role {migrator_role}");
            print(f"ROLE {migrator_role} CREATED [OK]")
            cur.execute(f"GRANT ALL ON DATABASE {customer_db} TO {migrator_role}");
            cur.execute(f"GRANT CONNECT ON DATABASE {customer_db} TO {migrator_role}");
            cur.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE, USAGE ON ALL TABLES IN SCHEMA public TO {migrator_role}");
        else:
            print(f"ROLE {migrator_role} EXIST [OK]")

        # -----------------------READONLY ROLE------------------------------------
        cur.execute(f"SELECT rolname FROM pg_roles where rolname =\'{ro_role}\'");
        exist = cur.fetchone()

        if exist == None:
            cur.execute(f"create role {ro_role}");
            cur.execute(f"GRANT CONNECT ON DATABASE {customer_db} TO {ro_role}");
            cur.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {customer_db} GRANT SELECT ON TABLES TO {ro_role}");
            cur.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA {customer_db} TO {ro_role}");
            cur.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {customer_db} GRANT USAGE ON SEQUENCES TO {ro_role}");
            cur.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA {customer_db} TO {ro_role}");
            print(f"ROLE {ro_role} CREATED [OK]")
        else:
            print(f"ROLE {ro_role} EXIST [OK]")

        print("CREATE EXTENSION UUID-OSSP")
        cur.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"");

        # ----------------CREATE USER-----------------------------

        for user in t['Users']:
            username = user['Name']
            role = user['Role']
            print(f"CREATE USER {username} with role {role}")
            create_user(username, role, customer_db)

        print("CHECKING MASTER PASSWORD FOR RDS")
        rds_pass = rand_string(16)
        update_master(rds_pass)


def create_user(username, role, customer_db):
    role = role + '_' + customer_db
    cur.execute(f"SELECT 1 FROM pg_roles WHERE rolname=\'{username}\'");
    exist = cur.fetchone()

    print(f"CHECKING IF USER {username} EXIST")
    if exist == None:
        cur.execute(f"Create user {username}");
        cur.execute(f"GRANT {role} TO {username}");
        cur.execute(f"GRANT rds_iam TO {username}");
        print(f"USER {username} CREATED [OK]")
        rds_pass = rand_string(16)
        update_user_pass(rds_pass, username, customer_db)
    else:
        print(f"USER {username} EXIST [OK]")


def update_user_pass(rds_pass, username, customer_db):
    path = '/rds/' + RDS_DATABASE + '/' + customer_db + '/' + username
    try:
        ssm.get_parameter(Name=path, WithDecryption=True)
        tags = ssm.list_tags_for_resource(ResourceType='Parameter', ResourceId=path)
        for tag in tags['TagList']:
            if tag['Key'] == 'UPDATED' and tag['Value'] == 'True':
                print("PASSWORD ALREADY HAVE BEEN UPDATED")
            else:
                cur.execute(f"ALTER USER {username} WITH PASSWORD \'{rds_pass}\';")
                ssm.delete_parameter(Name=path)
                ssm.put_parameter(Name=path, Value=rds_pass, Type='SecureString', Tags=[
                    {
                        'Key': 'UPDATED',
                        'Value': 'True'
                    },
                ])
                print(f"USER {username} PASSWORD NEW VALUE ADDED")
    except ssm.exceptions.ParameterNotFound:
        logging.error(f"PASSWORD NOT FOUND IN SSM FOR {username}")
        cur.execute(f"ALTER USER {username} WITH PASSWORD \'{rds_pass}\';")
        ssm.put_parameter(Name=path, Value=rds_pass, Type='SecureString', Tags=[
            {
                'Key': 'UPDATED',
                'Value': 'True'
            },
        ])
        print(f"{username} PASSWORD CREATED")


def update_master(rds_pass):
    path = '/rds/' + RDS_DATABASE + '/RDS_MASTERPASS'
    tags = ssm.list_tags_for_resource(ResourceType='Parameter', ResourceId=path)
    for tag in tags['TagList']:
        if tag['Key'] == 'UPDATED' and tag['Value'] == 'True':
            print("PASSWORD ALREADY HAVE BEEN UPDATED")
        else:
            cur.execute(f"ALTER USER postgres WITH PASSWORD \'{rds_pass}\';")

            ssm.delete_parameter(Name=path)
            print("MASTER PASS OLD VALUE DELETED")
            ssm.put_parameter(Name=path, Value=rds_pass, Type='SecureString', Tags=[
                {
                    'Key': 'UPDATED',
                    'Value': 'True'
                },
            ])
            print("MASTER PASS NEW VALUE ADDED")


def rand_string(length, char_set=legals):
    return ''.join(random.choice(char_set) for _ in range(length))
