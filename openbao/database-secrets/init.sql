-- Runs once at PostgreSQL container start (as lab_admin). LAB ONLY, synthetic values.
-- Creates sample data and a DEDICATED management role for OpenBao.
-- The mgmt role can create/drop roles and grant on the lab tables; it is not a superuser.

CREATE ROLE bao_mgmt WITH LOGIN CREATEROLE PASSWORD 'lab-mgmt-password-not-a-secret';

CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    customer    TEXT NOT NULL,
    amount      NUMERIC(10,2) NOT NULL
);
INSERT INTO orders (customer, amount) VALUES
    ('synthetic-customer-1', 10.00),
    ('synthetic-customer-2', 25.50),
    ('synthetic-customer-3', 99.99);

-- Table owner can GRANT to the short-lived roles OpenBao creates
ALTER TABLE orders OWNER TO bao_mgmt;
ALTER SEQUENCE orders_id_seq OWNER TO bao_mgmt;
GRANT CONNECT ON DATABASE labdb TO bao_mgmt;
GRANT USAGE ON SCHEMA public TO bao_mgmt;
