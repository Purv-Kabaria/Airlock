-- 01_clean_aggregate
-- before:
SELECT status, COUNT(*) AS n, ROUND(SUM(total), 2) AS revenue FROM orders GROUP BY status ORDER BY revenue DESC;
-- after:
SELECT "orders"."status" AS "status", COUNT(*) AS "n", ROUND(SUM("orders"."total"), 2) AS "revenue" FROM "orders" AS "orders" GROUP BY "orders"."status" ORDER BY "revenue" DESC LIMIT 10000;

-- 02_pii_masked
-- before:
SELECT name, email, phone FROM dim_users LIMIT 5;
-- after:
SELECT "dim_users"."name" AS "name", CASE WHEN STRPOS(CAST("dim_users"."email" AS TEXT), '@') > 0 THEN SUBSTRING(CAST("dim_users"."email" AS TEXT), 1, 1) || '***@' || SUBSTRING(CAST("dim_users"."email" AS TEXT), STRPOS(CAST("dim_users"."email" AS TEXT), '@') + 1) ELSE '***' END AS "email", CASE WHEN LENGTH(CAST("dim_users"."phone" AS TEXT)) >= 7 THEN '***-' || RIGHT(CAST("dim_users"."phone" AS TEXT), 4) ELSE '***' END AS "phone" FROM "dim_users" AS "dim_users" LIMIT 5;

-- 03_deprecated_substituted
-- before:
SELECT u.name, u.email, u.ssn, o.total FROM users_raw u JOIN orders o ON o.user_id = u.id ORDER BY o.total DESC LIMIT 10;
-- after:
SELECT "u"."name" AS "name", CASE WHEN STRPOS(CAST("u"."email" AS TEXT), '@') > 0 THEN SUBSTRING(CAST("u"."email" AS TEXT), 1, 1) || '***@' || SUBSTRING(CAST("u"."email" AS TEXT), STRPOS(CAST("u"."email" AS TEXT), '@') + 1) ELSE '***' END AS "email", NULL AS "ssn", "o"."total" AS "total" FROM dim_users AS "u" JOIN "orders" AS "o" ON "o"."user_id" = "u"."id" ORDER BY "o"."total" DESC LIMIT 10;

-- 04_predicate_denied
-- before:
SELECT name FROM dim_users WHERE email = 'ada@corp.com';
-- after:
-- <denied - not executed>

-- 05_cross_domain_denied
-- before:
SELECT name, salary FROM payroll;
-- after:
-- <denied - not executed>

-- 06_natural_language_rejected
-- before:
show me the biggest spenders this quarter;
-- after:
-- <denied - not executed>

-- 07_complex_cte_window
-- before:
WITH ranked AS (SELECT name, email, ROW_NUMBER() OVER (ORDER BY signup_date DESC) AS rn FROM dim_users) SELECT name, email FROM ranked WHERE rn <= 3;
-- after:
WITH "ranked" AS (SELECT "dim_users"."name" AS "name", CASE WHEN STRPOS(CAST("dim_users"."email" AS TEXT), '@') > 0 THEN SUBSTRING(CAST("dim_users"."email" AS TEXT), 1, 1) || '***@' || SUBSTRING(CAST("dim_users"."email" AS TEXT), STRPOS(CAST("dim_users"."email" AS TEXT), '@') + 1) ELSE '***' END AS "email", ROW_NUMBER() OVER (ORDER BY "dim_users"."signup_date" DESC) AS "rn" FROM "dim_users" AS "dim_users") SELECT "ranked"."name" AS "name", "ranked"."email" AS "email" FROM "ranked" AS "ranked" WHERE "ranked"."rn" <= 3 LIMIT 10000;

-- 08_lineage_inherited_mask
-- before:
SELECT user_id, contact, signup_month FROM user_report;
-- after:
SELECT "user_report"."user_id" AS "user_id", MD5('demo-not-secret-salt' || CAST("user_report"."contact" AS TEXT)) AS "contact", "user_report"."signup_month" AS "signup_month" FROM "user_report" AS "user_report" LIMIT 10000;
