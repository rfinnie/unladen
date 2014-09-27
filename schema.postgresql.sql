CREATE TABLE cluster_peers (
    peer text PRIMARY KEY,
    peer_updated double precision NOT NULL,
    storage_url text,
    token text,
    token_expires double precision,
    total_size bigint,
    used_size bigint
);

CREATE TABLE files (
    uuid uuid PRIMARY KEY,
    bytes_disk bigint NOT NULL,
    store text NOT NULL,
    uploader text NOT NULL,
    created double precision DEFAULT date_part('epoch'::text, now()) NOT NULL,
    meta text DEFAULT '{}'::text NOT NULL
);

CREATE TABLE objects (
    uuid uuid PRIMARY KEY,
    account text NOT NULL,
    container text NOT NULL,
    name text NOT NULL,
    bytes bigint NOT NULL,
    last_modified double precision DEFAULT date_part('epoch'::text, now()) NOT NULL,
    expires double precision,
    deleted boolean DEFAULT false NOT NULL,
    meta text DEFAULT '{}'::text NOT NULL,
    user_meta text DEFAULT '{}'::text NOT NULL
);

CREATE TABLE tempauth_users (
    account text PRIMARY KEY,
    username text NOT NULL,
    password text NOT NULL
);

CREATE TABLE tokens_cache (
    id text NOT NULL,
    account text NOT NULL,
    expires double precision DEFAULT date_part('epoch'::text, (now() + '24:00:00'::interval)) NOT NULL,
    source text NOT NULL,
    PRIMARY KEY (id, source)
);
