while IFS= read -r line; do
    file_name="output_file_$((++count)).php"
    printf "%b\n" "$line" > "$file_name"
    echo "Created file: $file_name"
done < "$1"