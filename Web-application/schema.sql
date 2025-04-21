DROP TABLE IF EXISTS "user";

CREATE TABLE "user" (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    publickey TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL
);