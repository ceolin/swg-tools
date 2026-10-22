# Sourced by the mysql image entrypoint on first start (empty data volume).
# Creates the account the ghsa tool uses, limited to what it needs.
ghsa_pw=$(cat /run/secrets/ghsa_pw)
docker_process_sql --database=mysql <<SQL
CREATE USER 'ghsa'@'%' IDENTIFIED BY '${ghsa_pw}' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, CREATE, ALTER ON \`ghsa\`.* TO 'ghsa'@'%';
SQL
unset ghsa_pw
