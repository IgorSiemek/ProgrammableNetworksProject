import os

def filter_log(input_file, output_file, keywords):
    """
    Filters the input log file, keeping only lines that contain any of the specified keywords.

    :param input_file: Path to the input log file.
    :param output_file: Path to the output filtered log file.
    :param keywords: List of keywords to filter lines.
    """
    if not os.path.isfile(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        return

    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                if any(keyword in line for keyword in keywords):
                    outfile.write(line)
        print(f"Filtering complete. Filtered log saved to '{output_file}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    # Define the input and output file paths
    input_file = 'logs/s1.log'
    output_file = 'logs/s1_filtered.log'

    # Define the keywords to filter by
    keywords = ['exceed_threshold', 'tbl_check_dos', 'count_']

    # Call the filter function
    filter_log(input_file, output_file, keywords)

if __name__ == '__main__':
    main()
