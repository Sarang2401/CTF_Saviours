import os

def read_file(filepath):
    """Reads content from a file."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            print(f"--- Content of {filepath} ---")
            print(content)
            return content
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def write_file(filepath, content, mode='w'):
    """Writes content to a file. 'w' for overwrite, 'a' for append."""
    try:
        with open(filepath, mode) as f:
            f.write(content)
            print(f"Successfully wrote to {filepath}")
            return True
    except Exception as e:
        print(f"Error writing to {filepath}: {e}")
        return False

def search_in_file(filepath, keyword):
    """Searches for a keyword in a file line by line."""
    found_lines = []
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if keyword in line:
                    found_lines.append(f"Line {line_num}: {line.strip()}")
        if found_lines:
            print(f"\n--- Found '{keyword}' in {filepath} ---")
            for found_line in found_lines:
                print(found_line)
        else:
            print(f"\n--- '{keyword}' not found in {filepath} ---")
        return found_lines
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return []
    except Exception as e:
        print(f"Error searching in {filepath}: {e}")
        return []

if __name__ == "__main__":
    # Example Usage:
    test_file = "test_ctf_data.txt"
    write_file(test_file, "This is line 1.\nThis is line 2 with a FLAG{example_flag}.\nAnother line.")
    read_file(test_file)
    search_in_file(test_file, "FLAG{")
    os.remove(test_file) 