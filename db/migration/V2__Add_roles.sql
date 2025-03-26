CREATE TYPE role_enum AS ENUM (
    'ROLE_CUSTOMER',
    'ROLE_ADMIN',
    'ROLE_INVENTORY_MANAGER'
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role role_enum NOT NULL,
    PRIMARY KEY (user_id, role),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id)
);