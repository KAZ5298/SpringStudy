INSERT INTO employee (id, name, age)
VALUES('1', 'Tom', 30);

/* ユーザーマスタ */
INSERT INTO m_user (
	user_id,
	password,
	user_name,
	birthday,
	age,
	gender,
	department_id,
	role
) VALUES 
('system@co.jp', '$2a$10$be4P5ibSvri7f4AUW.twpOcb4oXmKhpZYBp34yrM0bAoahQTDJmya', 'システム管理者', '2000-01-01', 21, 1, 1, 'ROLE_ADMIN'),
('user@co.jp', '$2a$10$be4P5ibSvri7f4AUW.twpOcb4oXmKhpZYBp34yrM0bAoahQTDJmya', 'ユーザー１', '2000-01-01', 21, 2, 2, 'ROLE_GENERAL')
;

/* 部署マスタ */
INSERT INTO m_department (
	department_id,
	department_name
) VALUES 
(1, 'システム管理部'),
(2, '営業部')
;

/* 給料テーブル */
CREATE TABLE IF NOT EXISTS t_salary (
	user_id VARCHAR(50),
	year_month VARCHAR(50),
	salary INT,
	PRIMARY KEY(user_id, year_month)
);

INSERT INTO t_salary (
	user_id,
	year_month,
	salary
) VALUES 
('user@co.jp', '2020/11', 280000),
('user@co.jp', '2020/12', 290000),
('user@co.jp', '2021/01', 300000)
;