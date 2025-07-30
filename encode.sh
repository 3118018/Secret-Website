# Usage: ./encode.sh <input_file> <output_file>
# Description: This script encodes a file using base64 encoding and saves the output to a specified file.

#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input_file> <output_file>"
    exit 1
fi
INPUT_FILE="$1"
OUTPUT_FILE="$2"
if [ ! -f "$INPUT_FILE" ]; then
    echo "Input file does not exist."
    exit 1
fi
base64 -i "$INPUT_FILE" -o "$OUTPUT_FILE"
# Add to file to make it executable
PRE="#!/bin/bash"$'\n'"base64 -d \""
SUF="\""
if [ $? -eq 0 ]; then
    echo "File encoded successfully to $OUTPUT_FILE"
else
    echo "Failed to encode file."
    exit 1
fi
