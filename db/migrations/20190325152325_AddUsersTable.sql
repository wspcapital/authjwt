-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE users (
  ID SERIAL PRIMARY KEY,
  Chat_ID int DEFAULT NULL,
  Alias VARCHAR(32) NOT NULL,
  Email VARCHAR(64) NOT NULL,
  Phone int DEFAULT NULL,
  Passw VARCHAR(512) NOT NULL,
  First_name VARCHAR(64) NOT NULL,
  Last_name VARCHAR(64) NOT NULL,
  Middle_name VARCHAR(64),
  Active boolean DEFAULT FALSE,
  Role int DEFAULT 20,
  Salt VARCHAR(32),
  Created_at TIMESTAMP,
  Updated_at TIMESTAMP,
  Two_factor_email boolean DEFAULT TRUE ,
  Two_factor_telegram boolean DEFAULT FALSE,
  Session_key text
);


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE users;

