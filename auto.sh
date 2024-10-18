#!/bin/bash
debug="false"
debug="true"

archive_filename=$1
directory="/tmp"
output_filename="$directory/output_results-$(date +%s).json"
input_dir="$directory/input-$(date +%s)/"
output_dir="$directory/output-$(date +%s)/"

if [[ $(echo $archive_filename | grep tar) == '' ]]; then
	echo "Specify .tar file"
	exit 1
fi
mkdir $input_dir
mkdir $output_dir
tar -xf "$archive_filename" -C $input_dir 
input_dir="${input_dir}ubuntu_report/success/"

readarray -t file_names < <(ls "$input_dir")

echo "Analyzing:"
for file_name in ${file_names[@]}; do
    if [[ $(echo $file_name | grep -P '\.txt$') == '' ]]; then
        continue
    fi

    input_file="${input_dir}${file_name}"
    output_file=$(echo "${output_dir}${file_name}" | sed 's/\.txt$/.json/g')

    results=$(python3 ubuntu-oval.py --release focal --report $input_file)
    if [[ $results == '' ]]; then
        results=$(python3 ubuntu-oval.py --release xenial --report $input_file)
    fi
    echo "$results" > "${output_file}"
    tail -c 80 "${output_file}"
done

echo "Creating result file ($output_filename):"
readarray -t file_names < <(ls "$output_dir")

for file_name in "${file_names[@]}"; do
   if [[ $(echo $file_name | grep -P '\.json$') == '' ]]; then
       continue
   fi 
   output_file="${output_dir}${file_name}"

   # If file is not empty (can be due to python script error)
   if [[ ! -z "$(cat $output_file)" ]]; then
   	cat "$output_file" | tr '\n' ' ' >> $output_filename 
   	echo -n ',' >> $output_filename
   fi

   #if [[ $engagement_id == '' ]]; then
   #    engagement_id=$(dojo-upload.sh -f $output_file -t "Wpscan API Scan" \
   #        -p "Casino Website" | grep 'Engagement: ' | cut -d ' ' -f2)
   #else
   #    dojo-upload.sh -f $output_file -t "Wpscan API Scan" -p "Casino Website" -e $engagement_id \
   #        | tail -n 1 | head -c 50
   #    echo
   #fi
done

output_file_content=$(cat "$output_filename")
echo "$output_file_content" | sed 's/^/[/g' | sed 's/,$/]/g' > $output_filename

echo "Uploading results: "
dojo-upload.sh -f $output_filename -t "Ubuntu OVAL" -p "Test"

if [[ $debug == "false" ]]; then
    rm -r $input_dir
    rm -r $output_dir
    rm $output_filename
fi
