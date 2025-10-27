#!/bin/bash

# --- CSV SPLITTING SCRIPT ---
# Splits a CSV file into three new files, ensuring the original header is present in all of them.

# --- Configuration ---
INPUT_FILE="$1"
NUM_SPLITS=3
DATA_SPLIT_PREFIX="temp_data_chunk_"
HEADER_FILE="temp_header.csv"
FINAL_OUTPUT_PREFIX="split_part_"

# --- Functions ---

# Function to display usage information
usage() {
    echo "Usage: $0 <input_csv_file>"
    echo "Example: $0 data.csv"
    echo ""
    echo "The script will generate three files named:"
    echo "final_split_part_01.csv, final_split_part_02.csv, etc."
    exit 1
}

# Ensure the input file is provided
if [ -z "$INPUT_FILE" ]; then
    usage
fi

# Ensure the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: File '$INPUT_FILE' not found."
    exit 1
fi

# --- Main Logic ---

echo "Starting CSV split for file: $INPUT_FILE"

# 1. Count total lines in the input file
TOTAL_LINES=$(wc -l < "$INPUT_FILE")

# Check if there are enough lines to split (must be more than 3)
if [ "$TOTAL_LINES" -le "$NUM_SPLITS" ]; then
    echo "Error: The file must have at least ${NUM_SPLITS} data lines (4 total lines including header) to perform a split."
    exit 1
fi

# 2. Calculate the number of data lines per split
DATA_LINES=$((TOTAL_LINES - 1))
LINES_PER_SPLIT=$((DATA_LINES / NUM_SPLITS))
REMAINDER=$((DATA_LINES % NUM_SPLITS))

echo "Total Data Lines: $DATA_LINES"
echo "Lines per Split (approx.): $LINES_PER_SPLIT"
echo "Remainder for last file: $REMAINDER"

# 3. Extract the Header
echo "Extracting header..."
head -n 1 "$INPUT_FILE" > "$HEADER_FILE"

# 4. Split the Data (Excluding Header)
# We use the calculated LINES_PER_SPLIT to divide the content starting from line 2.
echo "Splitting data lines..."
tail -n +2 "$INPUT_FILE" | split -l "$LINES_PER_SPLIT" --numeric-suffixes=1 --additional-suffix=.csv "$DATA_SPLIT_PREFIX"

# 5. Combine Header and Split Data
echo "Prepending header to split files..."
OUTPUT_FILES=()

# Loop through the temporary data files created by 'split'
for temp_file in "${DATA_SPLIT_PREFIX}"*.csv; do
    
    # Construct the final output filename
    # Example: split_part_01.csv, split_part_02.csv, etc.
    FINAL_FILENAME="${FINAL_OUTPUT_PREFIX}$(echo "$temp_file" | sed "s/$DATA_SPLIT_PREFIX//")"
    
    # Combine the header and the data chunk into the final file
    cat "$HEADER_FILE" "$temp_file" > "$FINAL_FILENAME"
    OUTPUT_FILES+=("$FINAL_FILENAME")
done

# 6. Clean Up Temporary Files
echo "Cleaning up temporary files..."
rm "$HEADER_FILE" "${DATA_SPLIT_PREFIX}"*.csv

# 7. Final Output Confirmation
echo "---"
echo "SUCCESS! The original file was successfully split into ${#OUTPUT_FILES[@]} files:"
for final_file in "${OUTPUT_FILES[@]}"; do
    echo "- $final_file ($(wc -l < "$final_file" | tr -d '[:space:]') lines)"
done
echo "---"

# Example usage instructions:
# 1. Save this script as split_csv.sh
# 2. Make it executable: chmod +x split_csv.sh
# 3. Run it: ./split_csv.sh my_data.csv
