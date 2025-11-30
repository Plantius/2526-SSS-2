php_query=$(<find_PHP_injection_vuln.sql)

PGPASSWORD='a42a18537d74c3b7e584c769152c3d' psql -h localhost -p 5432 -U postgrescvedumper -d postgrescvedumper \
    -c "\copy (
$php_query
) TO 'PHP_output.txt';"

rm -rf output/
mkdir output

while IFS= read -r line; do
    file_name="output/output_file_$((++count)).php"
    printf "%b\n" "$line" >"$file_name"
done <"PHP_output.txt"
echo "Created $count files"

rm PHP_output.txt
