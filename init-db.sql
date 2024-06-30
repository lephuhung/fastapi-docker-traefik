CREATE TABLE agents(
    id SERIAL PRIMARY KEY,
    name text,
    token text,
    zalo_name text,
    zalo_number_target text,
    webhook_id integer,
    created_at TIMESTAMP,
    ended_at TIMESTAMP NULL
);

CREATE TABLE webhooks(
    id SERIAL PRIMARY KEY,
    url_webhook text,
    webhook_name text,
    created_at TIMESTAMP,
    ended_at TIMESTAMP NULL
);

CREATE TABLE logger (
    id SERIAL PRIMARY KEY,
    IP text NULL,
    user_agents TEXT NULL,
    device TEXT NULL,
    IP_Info text NULL,
    filename text NULL,
    token text NULL,
    time_stamp TIMESTAMP NULL,
    created_at TIMESTAMP
);

CREATE TABLE logger_error(
    id SERIAL PRIMARY KEY,
    IP text,
    user_agents TEXT NULL,
    device TEXT,
    IP_Info text NULL,
    filename text NULL,
    token text NULL,
    time_stamp TIMESTAMP NULL,
    created_at TIMESTAMP
);

CREATE TABLE Users(
    id SERIAL PRIMARY KEY,
    username text,
    password text,
    is_active boolean,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE ip(
    id SERIAL PRIMARY KEY,
    ip text,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE zns_message (
    id SERIAL PRIMARY KEY,
    phone_id integer,
    message_id text,
    zns_id integer,
    message text,
    time_stamp text NULL,
    time_send  text,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
CREATE TABLE zns(
    id SERIAL PRIMARY KEY,
    zns_name text,
    zns_value text,
    zns_id text,
    discord_url text,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)

CREATE TABLE phone (
    id SERIAL PRIMARY KEY,
    phone text,
    phone_user text,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
CREATE TABLE token (
    id SERIAL PRIMARY KEY,
    token_type text,
    token text,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)